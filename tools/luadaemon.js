'use strict';
/*
 * Lua daemon: loaded ONCE while the app is still suspended, then serves
 * command files written by the host (/data/local/tmp/lua_cmd.lua). Results
 * go to /data/user/0/<pkg>/files/frida_out.txt. No post-resume script
 * creation, so frida RPC timeouts under load cannot break phases.
 *
 * Command format: first line "TAG:<id>", rest is Lua chunk source.
 * Result format:  "OK:<rc>:<tag>:<text>"  or "ERR:<tag>:<msg>"
 */
var CMD_PATH = '/data/local/tmp/lua_cmd.lua';
var OUT_PATH = '/data/user/0/com.ihuman.pinyin/files/frida_out.txt';
var luaStatePtr = null;
var luaFns = {};
var currentTag = null;
var busy = false;

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
      var f = new File(OUT_PATH, 'w');
      f.write(txt);
      f.flush();
      f.close();
      return true;
    } catch (e) {}
  }
  return false;
}

function resolveLua() {
  if (luaFns['luaL_loadbuffer']) return true;
  ['luaL_loadbuffer', 'lua_pcall', 'lua_tolstring'].forEach(function (n) {
    if (luaFns[n]) return;
    var q = findAny(n);
    if (q) luaFns[n] = q;
  });
  return !!(luaFns['luaL_loadbuffer'] && luaFns['lua_pcall'] && luaFns['lua_tolstring']);
}

function grabState() {
  if (luaStatePtr) return true;
  if (!resolveLua()) return false;
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
          return false;
        }
      } catch (e) {}
    }
  } catch (e) {}
  return false;
}

function execute(code, tag) {
  var codeStr = Memory.allocUtf8String(code);
  var fnLoad = new NativeFunction(luaFns['luaL_loadbuffer'], 'int', ['pointer', 'pointer', 'size_t', 'pointer']);
  var fnPcall = new NativeFunction(luaFns['lua_pcall'], 'int', ['pointer', 'int', 'int', 'int']);
  var nm = Memory.allocUtf8String('=luacall');
  var r = fnLoad(luaStatePtr, codeStr, code.length, nm);
  if (r !== 0) { writeOut('ERR:' + tag + ':load ' + r); return; }
  var rc = fnPcall(luaStatePtr, 0, 1, 0);
  var fnToStr = new NativeFunction(luaFns['lua_tolstring'], 'pointer', ['pointer', 'int', 'pointer']);
  var szp = Memory.alloc(8);
  var ps = fnToStr(luaStatePtr, -1, szp);
  if (ps.isNull()) { writeOut('ERR:' + tag + ':nostr rc=' + rc); return; }
  var len = szp.readU64().toNumber();
  var txt = ps.readUtf8String(Math.min(len, 20000)) || '';
  writeOut('OK:' + rc + ':' + tag + ':' + txt);
}

function poll() {
  if (busy) return;
  var raw = null;
  try { raw = File.readAllText(CMD_PATH); } catch (e) { return; }
  if (!raw) return;
  var nl = raw.indexOf('\n');
  if (nl < 0) return;
  var head = raw.substring(0, nl);
  if (head.indexOf('TAG:') !== 0) return;
  var tag = head.substring(4).trim();
  if (!tag || tag === currentTag) return;
  if (!grabState()) return;
  busy = true;
  currentTag = tag;
  try { execute(raw.substring(nl + 1), tag); } catch (e) {
    writeOut('ERR:' + tag + ':exc ' + String(e));
  }
  busy = false;
}

setInterval(poll, 1000);
send({ ev: 'daemon_up' });
