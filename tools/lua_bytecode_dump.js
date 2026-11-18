'use strict';
/*
 * Lua bytecode extractor v1: string.dump every loaded function.
 *
 * The engine's custom loader bypasses all exported luaL_load* symbols, but
 * the compiled Protos live in package.loaded / module tables. Lua 5.1's
 * string.dump produces the engine's own bytecode format (its undump reads
 * it back), so dumping every reachable function from package.loaded gives
 * us the full reconstructable script set without touching the loader.
 *
 * Runs inside the engine via luaL_loadbuffer+lua_pcall (proven pattern).
 * Writes /data/user/0/com.ihuman.pinyin/files/luabyte_dump.bin:
 *   repeated: [u32 nameLen][name][u32 codeLen][code]
 */
var L = null;
var fns = {};
var mod = null;
var injState = 0;
var attempts = 0;
var calls = 0;
var armed = false;

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

var CODE = [
  'local out = {}',
  'local seen = {}',
  'local count = 0',
  'local function push(name, fn)',
  '  if seen[fn] then return end',
  '  seen[fn] = true',
  '  local ok, code = pcall(string.dump, fn)',
  '  if ok and type(code) == "string" and #code > 16 then',
  '    out[#out+1] = name',
  '    out[#out+1] = code',
  '    count = count + 1',
  '  end',
  'end',
  'local function walk(tbl, depth, tag)',
  '  if depth > 3 or type(tbl) ~= "table" then return end',
  '  for k, v in pairs(tbl) do',
  '    if type(v) == "function" then',
  '      push(tag .. "." .. tostring(k), v)',
  '    elseif type(v) == "table" and depth < 3 and v ~= tbl then',
  '      local n = 0',
  '      for _ in pairs(v) do n = n + 1 end',
  '      if n <= 200 then walk(v, depth + 1, tag .. "." .. tostring(k)) end',
  '    end',
  '  end',
  'end',
  'for name, v in pairs(package.loaded) do',
  '  if type(v) == "table" then walk(v, 1, tostring(name)) end',
  '  if type(v) == "function" then push(tostring(name), v) end',
  'end',
  'local f, err = io.open("/data/user/0/com.ihuman.pinyin/files/luabyte_dump.bin", "wb")',
  'if not f then return "NO_IO:" .. tostring(err) end',
  'local total = 0',
  'for i = 1, #out, 2 do',
  '  local nm, code = out[i], out[i+1]',
  '  f:write(string.format("%08x", #nm))',
  '  f:write(nm)',
  '  f:write(string.format("%08x", #code))',
  '  f:write(code)',
  '  total = total + #code',
  'end',
  'f:close()',
  'return "OK count=" .. tostring(count) .. " bytes=" .. tostring(total)'
].join('\n');

var lastAttempt = 0;
function runInject() {
  if (injState === 2 || !L) return;
  var now = Date.now();
  if (now - lastAttempt < 1000) return;
  lastAttempt = now;
  if (attempts >= 30) { injState = 2; send({ ev: 'bc_giveup' }); return; }
  attempts++;
  try {
    var codeStr = Memory.allocUtf8String(CODE);
    var fnLoad = new NativeFunction(fns['luaL_loadbuffer'], 'int',
                                    ['pointer', 'pointer', 'size_t', 'pointer']);
    var fnPcall = new NativeFunction(fns['lua_pcall'], 'int',
                                     ['pointer', 'int', 'int', 'int']);
    var fnToStr = new NativeFunction(fns['lua_tolstring'], 'pointer',
                                     ['pointer', 'int', 'pointer']);
    var nameStr = Memory.allocUtf8String('=frida_bc');
    var r = fnLoad(L, codeStr, CODE.length, nameStr);
    if (r !== 0) return;
    var rc = fnPcall(L, 0, 1, 0);
    if (rc === 0) {
      var szp = Memory.alloc(4);
      var ps = fnToStr(L, -1, szp);
      var data = ps.isNull() ? '' : ps.readUtf8String();
      send({ ev: 'bc_out', attempt: attempts, data: data });
      if (data.indexOf('OK count=') === 0) injState = 2;  // success
      try {
        var fnPop = mod.findExportByName('lua_settop');
        if (fnPop) new NativeFunction(fnPop, 'void', ['pointer', 'int'])(L, -2);
      } catch (e2) {}
    } else {
      var szp2 = Memory.alloc(4);
      var es = fnToStr(L, -1, szp2);
      send({ ev: 'bc_err', attempt: attempts, msg: es.isNull() ? '' : es.readUtf8String() });
    }
  } catch (e) {
    send({ ev: 'bc_exc', e: String(e) });
  }
}

function onLuaCall(a, via) {
  calls++;
  if (!L) {
    L = a[0];
    send({ ev: 'bc_state', via: via, p: L.toString() });
  }
  if (injState !== 2) runInject();
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
              send({ ev: 'bc_state', via: 'callJavaStaticMethod', p: L.toString() });
            }
            if (injState !== 2) runInject();
          } catch (e) {}
        }
      });
      send({ ev: 'bc_hooked', sym: s.name.slice(0, 70) });
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
  send({ ev: 'bc_armed' });
}

var tries = 0;
var poll = setInterval(function () {
  tries++;
  armNow();
  if (armed && tries > 20) clearInterval(poll);
}, 250);
