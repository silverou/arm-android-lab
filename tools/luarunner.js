'use strict';
/*
 * Single runner: created BEFORE resume. Embeds all phase chunks as JSON.
 * Host writes /data/local/tmp/lua_queue.txt with "RUN:<tag>" to trigger a
 * phase; results go to /data/user/0/<pkg>/files/out_<tag>.txt; a heartbeat
 * goes to out_HB.txt every 5s so the host can see liveness.
 *
 * __QUEUE__ (JSON array of {tag, chunk}) is injected by the host.
 */
var PHASES = __QUEUE__;
var QUEUE_FILE = '/data/local/tmp/lua_queue.txt';
var OUT_DIR = '/data/user/0/com.ihuman.pinyin/files/';
var OTP_PATH = '/data/local/tmp/otp.txt';
var luaStatePtr = null;
var luaFns = {};
var current = null;      // tag currently requested
var executed = {};       // tag -> true
var beats = 0;

function findAny(name) {
  var mods = [];
  try { mods = Process.enumerateModules(); } catch (e) { return null; }
  try { var g = Module.getGlobalExportByName(name); if (g && !g.isNull()) return g; } catch (e) {}
  for (var i = 0; i < mods.length; i++) {
    try { var q = mods[i].findExportByName(name); if (q && !q.isNull()) return q; } catch (e) {}
  }
  return null;
}

function writeFile(path, txt) {
  for (var i = 0; i < 3; i++) {
    try {
      var f = new File(path, 'w');
      f.write(txt);
      f.flush();
      f.close();
      return true;
    } catch (e) {}
  }
  return false;
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

function execute(tag, chunk) {
  var code = chunk;
  if (code.indexOf('__OTP__') >= 0) {
    var otp = '';
    try { otp = File.readAllText(OTP_PATH).trim(); } catch (e) {}
    if (!otp) { writeFile(OUT_DIR + 'out_' + tag + '.txt', 'ERR:no OTP file'); return; }
    code = code.split('__OTP__').join(otp);
  }
  var codeStr = Memory.allocUtf8String(code);
  var fnLoad = new NativeFunction(luaFns['luaL_loadbuffer'], 'int', ['pointer', 'pointer', 'size_t', 'pointer']);
  var fnPcall = new NativeFunction(luaFns['lua_pcall'], 'int', ['pointer', 'int', 'int', 'int']);
  var nm = Memory.allocUtf8String('=luarunner');
  var r = fnLoad(luaStatePtr, codeStr, code.length, nm);
  if (r !== 0) { writeFile(OUT_DIR + 'out_' + tag + '.txt', 'ERR:load ' + r); return; }
  var rc = fnPcall(luaStatePtr, 0, 1, 0);
  try {
    var fnToStr = new NativeFunction(luaFns['lua_tolstring'], 'pointer', ['pointer', 'int', 'pointer']);
    var szp = Memory.alloc(8);
    var ps = fnToStr(luaStatePtr, -1, szp);
    if (ps.isNull()) { writeFile(OUT_DIR + 'out_' + tag + '.txt', 'ERR:nostr rc=' + rc); return; }
    var len = szp.readU64().toNumber();
    var txt = ps.readUtf8String(Math.min(len, 60000)) || '';
    writeFile(OUT_DIR + 'out_' + tag + '.txt', 'OK:' + rc + ':' + txt);
  } catch (e2) {
    writeFile(OUT_DIR + 'out_' + tag + '.txt', 'ERR:read ' + String(e2));
  }
}

setInterval(function () {
  beats++;
  var q = '';
  try { q = File.readAllText(QUEUE_FILE).trim(); } catch (e) { q = '?'; }
  if (beats % 8 === 0) {
    var st = grabState() ? 1 : 0;
    writeFile(OUT_DIR + 'out_HB.txt', 'HB beats=' + beats + ' lua=' + st + ' queue=' + q + ' done=' + Object.keys(executed).join(','));
  }
  // queue processing
  if (q.indexOf('RUN:') !== 0) return;
  var tag = q.substring(4).trim();
  if (!tag || executed[tag] || current === tag) return;
  var chunk = null;
  for (var i = 0; i < PHASES.length; i++) {
    if (PHASES[i].tag === tag) { chunk = PHASES[i].chunk; break; }
  }
  if (chunk == null) { writeFile(OUT_DIR + 'out_' + tag + '.txt', 'ERR:unknown tag'); executed[tag] = true; return; }
  if (!grabState()) return;
  current = tag;
  try {
    execute(tag, chunk);
  } catch (e) {
    writeFile(OUT_DIR + 'out_' + tag + '.txt', 'ERR:exc ' + String(e));
  }
  executed[tag] = true;
}, 700);
