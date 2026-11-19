'use strict';
/*
 * Override planter v1: two-variant entry-swap test (engine-side).
 *
 * Timeline (paired with the override_test workflow step):
 *   t0        workflow wrote PLAIN-LUA main.ihi into files/asset/src/launcher/
 *   att1 t0   engine reads plain variant at startup  -> tests text passthrough
 *   att1 t+15 this probe compiles an entry payload with the engine's own
 *             loadstring + string.dump (= valid SZAQ bytecode) and OVERWRITES
 *             main.ihi with those bytes + writes plant_marker.txt
 *   att2      engine restart reads the SZAQ variant  -> tests bytecode-as-ihi
 *
 * Proof: /data/.../files/override_proof.txt appended by whichever variant ran:
 *   "plain-ok"  = plain Lua source executed
 *   "szaq-ok"   = string.dump'd bytecode executed
 *
 * Injection pattern proven in lua_bytecode_dump.js (lua_State takeover via
 * luaL_loadbuffer / callJavaStaticMethod heartbeat, pcall roundtrip).
 */
var L = null;
var fns = {};
var mod = null;
var injState = 0;
var attempts = 0;
var planted = false;
var firstStateAt = 0;
var armed = false;

var PLANT_DELAY_MS = 15000;   // let att1 finish reading the plain variant first

function findFns() {
  if (!mod) {
    Process.enumerateModules().forEach(function (m) {
      if (!mod && /libcocos2dlua/.test(m.name)) mod = m;
    });
  }
  if (!mod) return false;
  ['luaL_loadbuffer', 'lua_pcall', 'lua_tolstring', 'lua_settop'].forEach(function (n) {
    if (fns[n]) return;
    try {
      var p = mod.findExportByName(n);
      if (p) fns[n] = p;
    } catch (e) {}
  });
  return !!(fns['luaL_loadbuffer'] && fns['lua_pcall'] && fns['lua_tolstring']);
}

var SRC = [
  'local f = io.open("/data/user/0/com.ihuman.pinyin/files/override_proof.txt", "a")',
  'if f then f:write("szaq-ok\\n"); f:close() end',
  'print("SZAQ_OVERRIDE_OK")',
  'return true',
].join('\n');

var CODE = [
  'local SRC = ' + JSON.stringify(SRC),
  'local ok, fn = pcall(loadstring, SRC)',
  'if not ok or not fn then return "COMPILE_ERR:" .. tostring(fn) end',
  'local ok2, bc = pcall(string.dump, fn)',
  'if not ok2 or type(bc) ~= "string" then return "DUMP_ERR:" .. tostring(bc) end',
  'local path = "/data/user/0/com.ihuman.pinyin/files/asset/src/launcher/main.ihi"',
  'local wf, werr = io.open(path, "wb")',
  'if not wf then return "OPEN_ERR:" .. tostring(werr) end',
  'wf:write(bc)',
  'wf:close()',
  'local mf = io.open("/data/user/0/com.ihuman.pinyin/files/plant_marker.txt", "w")',
  'if mf then mf:write("planted bytes=" .. tostring(#bc)); mf:close() end',
  'return "PLANTED bytes=" .. tostring(#bc)',
].join('\n');

var lastAttempt = 0;
function runPlant() {
  if (injState === 2 || planted || !L) return;
  var now = Date.now();
  if (!firstStateAt) return;
  if (now - firstStateAt < PLANT_DELAY_MS) return;   // plain-variant window
  if (now - lastAttempt < 1500) return;
  lastAttempt = now;
  if (attempts >= 30) { injState = 2; send({ ev: 'plant_giveup' }); return; }
  attempts++;
  try {
    var codeStr = Memory.allocUtf8String(CODE);
    var fnLoad = new NativeFunction(fns['luaL_loadbuffer'], 'int',
                                    ['pointer', 'pointer', 'size_t', 'pointer']);
    var fnPcall = new NativeFunction(fns['lua_pcall'], 'int',
                                     ['pointer', 'int', 'int', 'int']);
    var fnToStr = new NativeFunction(fns['lua_tolstring'], 'pointer',
                                     ['pointer', 'int', 'pointer']);
    var nameStr = Memory.allocUtf8String('=frida_plant');
    var r = fnLoad(L, codeStr, CODE.length, nameStr);
    if (r !== 0) { send({ ev: 'plant_load_err', r: r }); return; }
    var rc = fnPcall(L, 0, 1, 0);
    if (rc === 0) {
      var szp = Memory.alloc(4);
      var ps = fnToStr(L, -1, szp);
      var data = ps.isNull() ? '' : ps.readUtf8String();
      send({ ev: 'plant_out', attempt: attempts, data: data });
      if (data.indexOf('PLANTED') === 0) { planted = true; injState = 2; }
      try {
        var fnPop = mod.findExportByName('lua_settop');
        if (fnPop) new NativeFunction(fnPop, 'void', ['pointer', 'int'])(L, -2);
      } catch (e2) {}
    } else {
      var szp2 = Memory.alloc(4);
      var es = fnToStr(L, -1, szp2);
      send({ ev: 'plant_err', attempt: attempts, msg: es.isNull() ? '' : es.readUtf8String() });
    }
  } catch (e) {
    send({ ev: 'plant_exc', e: String(e) });
  }
}

function onLuaCall(a, via) {
  if (!L) {
    L = a[0];
    firstStateAt = Date.now();
    send({ ev: 'plant_state', via: via, p: L.toString() });
  }
  if (injState !== 2) runPlant();
}

function armBridgeHook() {
  if (!mod) return;
  var syms = [];
  try { syms = mod.enumerateSymbols(); } catch (e) { return; }
  for (var i = 0; i < syms.length; i++) {
    var s = syms[i];
    if (s.type !== 'function') continue;
    if (s.name.indexOf('callJavaStaticMethod') < 0) continue;
    try {
      Interceptor.attach(s.address, {
        onEnter: function (a) {
          try {
            if (!L && a[0] && !a[0].isNull()) {
              L = a[0];
              firstStateAt = Date.now();
              send({ ev: 'plant_state', via: 'callJavaStaticMethod', p: L.toString() });
            }
            if (injState !== 2) runPlant();
          } catch (e) {}
        }
      });
      send({ ev: 'plant_hooked', sym: s.name.slice(0, 60) });
    } catch (e) {}
  }
}

function armNow() {
  if (armed || !findFns()) return;
  armed = true;
  ['luaL_loadbuffer', 'lua_load', 'luaL_loadfile', 'luaL_loadstring', 'lua_pcall'].forEach(function (n) {
    var p = fns[n] || (mod && mod.findExportByName(n));
    if (!p) return;
    try {
      Interceptor.attach(p, { onEnter: function (a) { onLuaCall(a, n); } });
    } catch (e) {}
  });
  armBridgeHook();
  send({ ev: 'plant_armed' });
}

var tries = 0;
var poll = setInterval(function () {
  tries++;
  armNow();
  if (armed && tries > 40) clearInterval(poll);
}, 250);
