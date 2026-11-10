'use strict';
/*
 * Generic Lua RPC v2: reads /data/local/tmp/lua_cmd.lua, arms on s_luaState,
 * executes the chunk, writes result to a process-writable file so the host
 * can read it with docker exec (immune to frida message-channel timeouts).
 */
var CMD_PATH = '/data/local/tmp/lua_cmd.lua';
var OUT_PATH = '/data/user/0/com.ihuman.pinyin/files/frida_out.txt';
var LUA_CODE = '';
var luaStatePtr = null;
var luaFns = {};
var luaInj = 0;
var injFails = 0;
var done = false;

try {
  LUA_CODE = File.readAllText(CMD_PATH);
} catch (e) {}

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
  try {
    var f = new File(OUT_PATH, 'w');
    f.write(txt);
    f.flush();
    f.close();
    send({ ev: 'wrote', len: txt.length });
  } catch (e) {
    send({ ev: 'write_err', e: String(e) });
  }
}

function luaRunInject() {
  if (done || luaInj !== 0 || !luaStatePtr || !LUA_CODE) return;
  if (injFails >= 4) { writeOut('ERR:giveup ' + injFails); done = true; return; }
  luaInj = 1;
  try {
    var codeStr = Memory.allocUtf8String(LUA_CODE);
    var fnLoad = new NativeFunction(luaFns['luaL_loadbuffer'], 'int', ['pointer', 'pointer', 'size_t', 'pointer']);
    var fnPcall = new NativeFunction(luaFns['lua_pcall'], 'int', ['pointer', 'int', 'int', 'int']);
    var nm = Memory.allocUtf8String('=luacall');
    var r = fnLoad(luaStatePtr, codeStr, LUA_CODE.length, nm);
    if (r !== 0) { injFails++; luaInj = 0; return; }
    var rc = fnPcall(luaStatePtr, 0, 1, 0);
    try {
      var fnToStr = new NativeFunction(luaFns['lua_tolstring'], 'pointer', ['pointer', 'int', 'pointer']);
      var szp = Memory.alloc(8);
      var ps = fnToStr(luaStatePtr, -1, szp);
      if (!ps.isNull()) {
        var len = szp.readU64().toNumber();
        var txt = ps.readUtf8String(Math.min(len, 60000)) || '';
        writeOut('OK:' + rc + ':' + txt);
        done = true;
      } else {
        writeOut('ERR:nostr rc=' + rc);
        if (rc === 0) done = true; else { injFails++; luaInj = 0; }
      }
    } catch (e2) {
      injFails++; luaInj = 0;
      writeOut('ERR:read ' + String(e2));
    }
  } catch (e) {
    injFails++;
    luaInj = 0;
    writeOut('ERR:exc ' + String(e));
  }
}

function armLua() {
  if (!findAny('luaL_loadfile')) return;
  if (armLua.done) return;
  armLua.done = true;
  ['luaL_loadbuffer', 'lua_pcall', 'lua_tolstring'].forEach(function (n) {
    if (luaFns[n]) return;
    var q = findAny(n);
    if (q) luaFns[n] = q;
  });
  if (!luaFns['luaL_loadbuffer'] || !luaFns['lua_pcall'] || !luaFns['lua_tolstring']) return;
  var slot = null;
  try {
    var mods = Process.enumerateModules();
    for (var i = 0; i < mods.length; i++) {
      try {
        var ps = mods[i].findExportByName('_ZN13LuaJavaBridge10s_luaStateE');
        if (!ps || ps.isNull()) {
          if (/libcocos2dlua/.test(mods[i].name || '')) ps = mods[i].base.add(0x25f9cd8);
        }
        if (ps && !ps.isNull()) { slot = ps; break; }
      } catch (e) {}
    }
  } catch (e) {}
  if (slot) {
    setInterval(function () {
      if (luaStatePtr) return;
      try {
        var p = slot.readPointer();
        if (!p.isNull()) luaStatePtr = p;
      } catch (e) {}
    }, 500);
  }
  send({ ev: 'armed', slot: !!slot, hasCode: !!LUA_CODE });
}

setInterval(armLua, 500);
setInterval(function () {
  if (luaStatePtr && luaInj === 0 && !done) {
    try { luaRunInject(); } catch (e) {}
  }
}, 500);
