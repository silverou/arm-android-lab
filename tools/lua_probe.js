'use strict';
/*
 * Read-only asset-manager probe (v1, 2026-11-17).
 *
 * Answers three questions with zero state changes:
 *   1) where downloaded packs land        -> AssetMgr path getters +
 *                                            cc.FileUtils:getWritablePath
 *   2) what drives Asset.state (file-existence vs registry)
 *   3) what fields an Asset object carries (url/state/md5/version...)
 *
 * Pattern proven in v87/v88: take over lua_State on luaL_loadbuffer, run a
 * read-only chunk via luaL_loadbuffer+lua_pcall, read back the returned
 * string. Nothing is downloaded, nothing is modified.
 */
var L = null;
var fns = {};
var mod = null;
var injState = 0;      // 0=retry on next lua call, 2=done
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
  ['luaL_loadbuffer', 'luaL_loadbufferx', 'lua_load', 'luaL_loadfile', 'luaL_loadfilex',
   'luaL_loadstring', 'lua_pcall', 'lua_tolstring', 'lua_gettop', 'lua_settop'].forEach(function (n) {
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
  'local function P(s) out[#out+1] = tostring(s or "nil") end',
  'P("PROBE_VER:"..tostring(_VERSION))',
  'local AM = _G.AssetMgr',
  'P("AM:"..type(AM))',
  'if type(AM) ~= "table" then return "NO_ASSETMGR" end',
  // ---- cocos FileUtils search paths (the make-or-break for external seeding)
  'local cc = _G.cc',
  'if type(cc) == "table" and cc.FileUtils then',
  '  local fu = cc.FileUtils:getInstance()',
  '  local ok, sp = pcall(function() return fu:getSearchPaths() end)',
  '  if ok and type(sp) == "table" then',
  '    for i, p in ipairs(sp) do P("SP."..i.."="..tostring(p)) end',
  '  else',
  '    P("SP_ERR:"..tostring(sp))',
  '  end',
  'end',
  // ---- AssetMgr function list
  'local fns = {}',
  'for k, v in pairs(AM) do if type(v) == "function" then fns[#fns+1] = tostring(k) end end',
  'table.sort(fns)',
  'P("AM_FNS:"..table.concat(fns, ","))',
  // ---- asset path + metatable methods
  'local okA, a = pcall(function() return AM:getAsset("PY001") end)',
  'if okA and type(a) == "table" then',
  '  local mt = getmetatable(a)',
  '  if mt then',
  '    local ms = {}',
  '    for k, v in pairs(mt) do if type(v) == "function" then ms[#ms+1] = tostring(k) elseif type(v) == "table" then for k2, v2 in pairs(v) do if type(v2) == "function" then ms[#ms+1] = tostring(k2) end end end end',
  '    table.sort(ms)',
  '    P("ASSET_MT:"..table.concat(ms, ","))',
  '  end',
  '  local okP, p1 = pcall(function() return AM:getAssetPath("PY001") end)',
  '  P("PATHPY001:"..tostring(okP)..":"..tostring(p1))',
  // ---- try reading the asset dir listing via io.popen / os.execute
  '  local cmds = {"ls /data/user/0/com.ihuman.pinyin/files/asset 2>&1", "ls /data/user/0/com.ihuman.pinyin/files/asset/PY001 2>&1 | head -20"}',
  '  for _, cmd in ipairs(cmds) do',
  '    local okR, h = pcall(function() return io.popen(cmd) end)',
  '    if okR and h then',
  '      local txt = h:read("*a") or ""',
  '      h:close()',
  '      P("LS:"..cmd:sub(1, 60).." => "..txt:gsub("\\n", " | "):sub(1, 400))',
  '    else',
  '      P("LS_ERR:"..tostring(h))',
  '    end',
  '  end',
  'end',
  'return table.concat(out, "\\n")'
].join('\n');

var lastAttempt = 0;
function runInject() {
  if (injState === 2 || !L) return;
  var now = Date.now();
  if (now - lastAttempt < 800) return;   // throttle: ~1 attempt/sec
  lastAttempt = now;
  if (attempts >= 400) { injState = 2; send({ ev: 'probe_giveup' }); return; }
  attempts++;
  try {
    var codeStr = Memory.allocUtf8String(CODE);
    var fnLoad = new NativeFunction(fns['luaL_loadbuffer'], 'int',
                                    ['pointer', 'pointer', 'size_t', 'pointer']);
    var fnPcall = new NativeFunction(fns['lua_pcall'], 'int',
                                     ['pointer', 'int', 'int', 'int']);
    var fnToStr = new NativeFunction(fns['lua_tolstring'], 'pointer',
                                     ['pointer', 'int', 'pointer']);
    var nameStr = Memory.allocUtf8String('=frida_probe');
    var r = fnLoad(L, codeStr, CODE.length, nameStr);
    if (r !== 0) {
      send({ ev: 'probe_load', r: r, attempt: attempts });
      return;
    }
    var rc = fnPcall(L, 0, 1, 0);  // 1 result
    if (rc === 0) {
      var szp = Memory.alloc(4);
      var ps = fnToStr(L, -1, szp);
      var data = ps.isNull() ? '' : ps.readUtf8String();
      send({ ev: 'probe_out', attempt: attempts, data: data });
      // keep probing only while AssetMgr is not yet initialized
      if (data.indexOf('AM:table') >= 0) injState = 2;
      try {
        var fnPop = mod.findExportByName('lua_settop');
        if (fnPop) new NativeFunction(fnPop, 'void', ['pointer', 'int'])(L, -2);
      } catch (e2) {}
    } else {
      var szp2 = Memory.alloc(4);
      var es = fnToStr(L, -1, szp2);
      send({ ev: 'probe_err', attempt: attempts, msg: es.isNull() ? '' : es.readUtf8String() });
      injState = 2;  // chunk errors are unlikely to heal; stop
    }
  } catch (e) {
    send({ ev: 'probe_exc', e: String(e) });
    injState = 2;
  }
}

function onLuaCall(a, via) {
  calls++;
  if (!L) {
    L = a[0];
    send({ ev: 'lua_state', via: via, p: L.toString() });
  }
  if (injState !== 2) runInject();
}

// Heartbeat path: LuaJavaBridge::callJavaStaticMethod runs every ~3s once
// the game loop is up (getServerTime). That is the reliable retry window:
// AssetMgr may not exist during the early script-loading calls.
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
              send({ ev: 'lua_state', via: 'callJavaStaticMethod', p: L.toString() });
            }
            if (injState !== 2) runInject();
          } catch (e) {}
        }
      });
      send({ ev: 'probe_hooked', sym: s.name.slice(0, 80) });
    } catch (e) {}
  }
}

function armNow() {
  if (armed || !findFns()) return;
  armed = true;
  ['luaL_loadbuffer', 'luaL_loadbufferx', 'lua_load', 'luaL_loadfile', 'luaL_loadfilex', 'luaL_loadstring', 'lua_pcall'].forEach(function (n) {
    var p = fns[n];
    if (!p) return;
    try {
      Interceptor.attach(p, { onEnter: function (a) { onLuaCall(a, n); } });
      send({ ev: 'probe_hooked', sym: n });
    } catch (e) {}
  });
  armBridgeHook();
  send({ ev: 'probe_armed' });
}

['android_dlopen_ext', 'dlopen', '__loader_dlopen', '__loader_android_dlopen_ext'].forEach(function (sym) {
  try {
    var p = Module.getGlobalExportByName(sym);
    Interceptor.attach(p, {
      onEnter: function (a) {
        try { this.pth = a[0].readCString(); } catch (e) { this.pth = ''; }
      },
      onLeave: function () {
        if (this.pth && /cocos2dlua/.test(this.pth)) {
          send({ ev: 'dl_seen', p: this.pth });
          armNow();
        }
      }
    });
  } catch (e) {}
});

var tries = 0;
var poll = setInterval(function () {
  tries++;
  armNow();
  if (armed && tries > 20) clearInterval(poll);
}, 500);
