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
var injState = 0;
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
  'if type(AM) == "table" then',
  '  local ks = {}',
  '  for k in pairs(AM) do ks[#ks+1] = tostring(k) end',
  '  table.sort(ks)',
  '  P("AM_KEYS:"..table.concat(ks, ","))',
  '  for _, fn in ipairs({"getAssetPath","getResPath","getFilePath","getDownloadPath","getSavePath","getResDir","getCachePath","getAssetDir","getAsset"}) do',
  '    local f = AM[fn]',
  '    P("FN."..fn..":"..type(f))',
  '    if type(f) == "function" then',
  '      local ok, r = pcall(f, AM, "PY001")',
  '      P("CALL."..fn.."(PY001)="..tostring(ok)..":"..tostring(r))',
  '    end',
  '  end',
  '  for _, id in ipairs({"PY001","PY002","PY063","LT001","song_PY"}) do',
  '    local ok, a = pcall(function() return AM:getAsset(id) end)',
  '    if ok and type(a) == "table" then',
  '      local fields = {}',
  '      for k, v in pairs(a) do',
  '        local tv = type(v)',
  '        if tv ~= "table" and tv ~= "function" then fields[#fields+1] = tostring(k).."="..tostring(v) end',
  '      end',
  '      table.sort(fields)',
  '      P("ASSET."..id..":"..table.concat(fields, "|"))',
  '      local okst, st = pcall(function() return a:getState() end)',
  '      P("STATE."..id.."="..tostring(okst)..":"..tostring(st))',
  '      local okp, p1 = pcall(function() return a:getPath() end)',
  '      if okp then P("PATH."..id.."="..tostring(p1)) end',
  '    else',
  '      P("ASSET."..id..":GETFAIL:"..tostring(ok)..":"..tostring(a))',
  '    end',
  '  end',
  'end',
  'local cc = _G.cc',
  'if type(cc) == "table" and cc.FileUtils then',
  '  local fu = cc.FileUtils:getInstance()',
  '  for _, m in ipairs({"getWritablePath","getDefaultResourceRootPath"}) do',
  '    local ok, r = pcall(function() return fu[m](fu) end)',
  '    P("CC."..m.."="..tostring(ok)..":"..tostring(r))',
  '  end',
  'end',
  'return table.concat(out, "\\n")'
].join('\n');

function runInject() {
  if (injState !== 0 || !L) return;
  injState = 1;
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
    send({ ev: 'probe_load', r: r });
    if (r === 0) {
      var rc = fnPcall(L, 0, 1, 0);  // 1 result
      send({ ev: 'probe_pcall', rc: rc });
      if (rc === 0) {
        var szp = Memory.alloc(4);
        var ps = fnToStr(L, -1, szp);
        if (!ps.isNull()) send({ ev: 'probe_out', data: ps.readUtf8String() });
        // pop result (and error object on failure) to keep the stack sane
        try {
          var fnPop = mod.findExportByName('lua_settop');
          if (fnPop) new NativeFunction(fnPop, 'void', ['pointer', 'int'])(L, -2);
        } catch (e2) {}
      } else {
        var szp2 = Memory.alloc(4);
        var es = fnToStr(L, -1, szp2);
        if (!es.isNull()) send({ ev: 'probe_err', msg: es.readUtf8String() });
      }
    }
  } catch (e) {
    send({ ev: 'probe_exc', e: String(e) });
  }
}

function onLuaCall(a, via) {
  calls++;
  if (!L) {
    L = a[0];
    send({ ev: 'lua_state', via: via, p: L.toString() });
  }
  if (injState === 0 && calls > 5) runInject();
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
