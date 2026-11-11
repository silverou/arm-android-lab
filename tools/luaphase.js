'use strict';
/*
 * Phase runner: created BEFORE app resume (suspended -> creation always
 * succeeds). Waits for a host-created gate file, then executes its embedded
 * Lua chunk once and writes the result to a file.
 *
 * __TAG__, __CHUNK__ (JSON string) and __OTP__ substitution are injected
 * by the host before loading.
 */
var TAG = '__TAG__';
var GATE = '/data/local/tmp/' + TAG + '.gate';
var OUT = '/data/user/0/com.ihuman.pinyin/files/out_' + TAG + '.txt';
var OTP_PATH = '/data/local/tmp/otp.txt';
var CHUNK = __CHUNK__;
var luaStatePtr = null;
var luaFns = {};
var started = false;

function findAny(name) {
  var mods = [];
  try { mods = Process.enumerateModules(); } catch (e) { return null; }
  try { var g = Module.getGlobalExportByName(name); if (g && !g.isNull()) return g; } catch (e) {}
  for (var i = 0; i < mods.length; i++) {
    try { var q = mods[i].findExportByName(name); if (q && !q.isNull()) return q; } catch (e) {}
  }
  return null;
}

function writeOut(txt) {
  for (var i = 0; i < 3; i++) {
    try {
      var f = new File(OUT, 'w');
      f.write(txt);
      f.flush();
      f.close();
      return;
    } catch (e) {}
  }
}

function gateOpen() {
  try { File.readAllText(GATE); return true; } catch (e) { return false; }
}

function grabState() {
  if (luaStatePtr) return true;
  ['luaL_loadbuffer', 'lua_pcall', 'lua_tolstring'].forEach(function (n) {
    if (luaFns[n]) return;
    var q = findAny(n);
    if (q) luaFns[n] = q;
  });
  if (!luaFns['luaL_loadbuffer'] || !luaFns['lua_pcall'] || !luaFns['lua_tolstring']) return false;
  try {
    var mods = Process.enumerateModules();
    for (var i = 0; i < mods.length; i++) {
      try {
        var ps = mods[i].findExportByName('_ZN13LuaJavaBridge10s_luaStateE');
        if (!ps || ps.isNull()) {
          if (/libcocos2dlua/.test(mods[i].name || '')) ps = mods[i].base.add(0x25f9cd8);
        }
        if (ps && !ps.isNull()) {
          var p = ps.readPointer();
          if (!p.isNull()) { luaStatePtr = p; return true; }
        }
      } catch (e) {}
    }
  } catch (e) {}
  return false;
}

function execute() {
  var code = CHUNK;
  if (code.indexOf('__OTP__') >= 0) {
    var otp = '';
    try { otp = File.readAllText(OTP_PATH).trim(); } catch (e) {}
    if (!otp) { writeOut('ERR:no OTP file'); started = 'done'; return; }
    code = code.split('__OTP__').join(otp);
  }
  var codeStr = Memory.allocUtf8String(code);
  var fnLoad = new NativeFunction(luaFns['luaL_loadbuffer'], 'int', ['pointer', 'pointer', 'size_t', 'pointer']);
  var fnPcall = new NativeFunction(luaFns['lua_pcall'], 'int', ['pointer', 'int', 'int', 'int']);
  var nm = Memory.allocUtf8String('=luaphase');
  var r = fnLoad(luaStatePtr, codeStr, code.length, nm);
  if (r !== 0) { writeOut('ERR:load ' + r); return true; }
  var rc = fnPcall(luaStatePtr, 0, 1, 0);
  try {
    var fnToStr = new NativeFunction(luaFns['lua_tolstring'], 'pointer', ['pointer', 'int', 'pointer']);
    var szp = Memory.alloc(8);
    var ps = fnToStr(luaStatePtr, -1, szp);
    if (ps.isNull()) { writeOut('ERR:nostr rc=' + rc); return true; }
    var len = szp.readU64().toNumber();
    var txt = ps.readUtf8String(Math.min(len, 60000)) || '';
    writeOut('OK:' + rc + ':' + txt);
    return true;
  } catch (e2) {
    writeOut('ERR:read ' + String(e2));
    return true;
  }
}

setInterval(function () {
  if (started === 'done') return;
  if (!started) {
    if (!gateOpen()) return;
    started = true;
  }
  if (!grabState()) return;
  try {
    if (execute()) started = 'done';
  } catch (e) {
    writeOut('ERR:exc ' + String(e));
    started = 'done';
  }
}, 700);
