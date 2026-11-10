'use strict';
/*
 * Generic Lua RPC over frida: reads /data/local/tmp/lua_cmd.lua, arms on
 * s_luaState, executes the chunk with retry on crash, sends back the string.
 */
var CMD_PATH = '/data/local/tmp/lua_cmd.lua';
var LUA_CODE = '';
var luaStatePtr = null;
var luaFns = {};
var luaCalls = 0;
var luaInj = 0;
var injFails = 0;
var jsRetryStarted = false;
var done = false;

try {
  LUA_CODE = File.readAllText(CMD_PATH);
} catch (e) {
  send({ ev: 'cmd_read_err', e: String(e) });
}

function findAny(name) {
  var mods = [];
  try { mods = Process.enumerateModules(); } catch (e) { return null; }
  try { var g = Module.getGlobalExportByName(name); if (g && !g.isNull()) return g; } catch (e) {}
  for (var i = 0; i < mods.length; i++) {
    try { var q = mods[i].findExportByName(name); if (q && !q.isNull()) return q; } catch (e) {}
  }
  return null;
}

function luaResolve() {
  ['luaL_loadbuffer', 'lua_pcall', 'lua_tolstring'].forEach(function (n) {
    if (luaFns[n]) return;
    var q = findAny(n);
    if (q) luaFns[n] = q;
  });
  return !!(luaFns['luaL_loadbuffer'] && luaFns['lua_pcall'] && luaFns['lua_tolstring']);
}

function luaRunInject() {
  if (done || luaInj !== 0 || !luaStatePtr || !LUA_CODE) return;
  if (injFails >= 4) { send({ ev: 'giveup', fails: injFails }); done = true; return; }
  luaInj = 1;
  try {
    var codeStr = Memory.allocUtf8String(LUA_CODE);
    var fnLoad = new NativeFunction(luaFns['luaL_loadbuffer'], 'int', ['pointer', 'pointer', 'size_t', 'pointer']);
    var fnPcall = new NativeFunction(luaFns['lua_pcall'], 'int', ['pointer', 'int', 'int', 'int']);
    var nm = Memory.allocUtf8String('=luacall');
    var r = fnLoad(luaStatePtr, codeStr, LUA_CODE.length, nm);
    send({ ev: 'load', r: r });
    if (r !== 0) { injFails++; luaInj = 0; return; }
    var rc = fnPcall(luaStatePtr, 0, 1, 0);
    send({ ev: 'pcall', rc: rc });
    try {
      var fnToStr = new NativeFunction(luaFns['lua_tolstring'], 'pointer', ['pointer', 'int', 'pointer']);
      var szp = Memory.alloc(8);
      var ps = fnToStr(luaStatePtr, -1, szp);
      if (!ps.isNull()) {
        var len = szp.readU64().toNumber();
        send({ ev: 'result', txt: ps.readUtf8String(Math.min(len, 60000)) || '' });
        done = true;
      } else {
        send({ ev: 'nostr', rc: rc });
        if (rc === 0) done = true;
        else { injFails++; luaInj = 0; }
      }
    } catch (e2) { send({ ev: 'read_err', e: String(e2) }); injFails++; luaInj = 0; send({ ev: 'nostr' }); }
  } catch (e) {
    injFails++;
    luaInj = 0;
    send({ ev: 'exc', e: String(e), fails: injFails });
  }
}

function armLua() {
  if (!luaResolve()) return;
  if (armLua.done) return;
  armLua.done = true;
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
    var iv = setInterval(function () {
      if (luaStatePtr) return;
      try {
        var p = slot.readPointer();
        if (!p.isNull()) { luaStatePtr = p; send({ ev: 'state', p: p.toString() }); }
      } catch (e) {}
    }, 500);
  }
  send({ ev: 'armed', slot: !!slot, hasCode: !!LUA_CODE });
}

var ivA = setInterval(armLua, 500);
var ticks = 0;
var ivB = setInterval(function () {
  ticks++;
  if (ticks > 2400) { clearInterval(ivA); clearInterval(ivB); return; }
  if (luaStatePtr && luaInj === 0 && !done) {
    if (!jsRetryStarted) { jsRetryStarted = true; }
    try { luaRunInject(); } catch (e) {}
  }
}, 500);
setTimeout(function () { send({ ev: 'final', done: done, fails: injFails }); }, 90000);
