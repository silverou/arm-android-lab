'use strict';
/*
 * Lua state takeover: capture lua_State from luaL_loadbuffer, then (on the
 * Lua thread, inside a guard) load and pcall our own chunk to enumerate the
 * global Lua surface (AssetMgr / PYAssetMgr / ZipAsset ...). Results are
 * printed with print() so they land in logcat.
 */
var L = null;
var fns = {};
var mod = null;
var injState = 0; // 0 = not run, 1 = done
var calls = 0;

function findFns() {
  if (!mod) {
    Process.enumerateModules().forEach(function (m) {
      if (!mod && /libcocos2dlua/.test(m.name)) mod = m;
    });
  }
  if (!mod) return false;
  ['luaL_loadbuffer', 'lua_pcall', 'lua_tolstring', 'lua_gettop', 'lua_settop', 'lua_pushstring'].forEach(function (n) {
    if (fns[n]) return;
    try {
      var p = mod.findExportByName(n);
      if (p) fns[n] = p;
    } catch (e) {}
  });
  return !!(fns['luaL_loadbuffer'] && fns['lua_pcall'] && fns['lua_tolstring']);
}

var CODE = [
  '-- injected by frida',
  'local out = {}',
  'local function P(s) out[#out+1] = s end',
  'P("INJ_VERSION:"..tostring(_VERSION))',
  'local names = {}',
  'for k in pairs(_G) do names[#names+1] = tostring(k) end',
  'table.sort(names)',
  'P("INJ_GCOUNT:"..#names)',
  'local want = {"AssetMgr","PYAssetMgr","ZipAsset","BookAssetMgr","MiscAssetMgr","AppData","GameData","AssetSummary","Asset","UserData","Config","Net","HttpApiMgr","DressMgr","PinyinDataMgr","GlobalData","DataMgr","StoreMgr","VipMgr","PurchaseMgr","LoginMgr","UserManager","Platform"}',
  'for _,w in ipairs(want) do',
  '  local v = _G[w]',
  '  if v ~= nil then',
  '    P("INJ_HIT:"..w..":"..type(v))',
  '    if type(v) == "table" then',
  '      local ks = {}',
  '      for k in pairs(v) do ks[#ks+1] = tostring(k) end',
  '      table.sort(ks)',
  '      P("INJ_KEYS:"..w..":"..table.concat(ks, ",", 1, math.min(#ks, 60)))',
  '    end',
  '  end',
  'end',
  'P("INJ_NAMES:"..table.concat(names, ",", 1, math.min(#names, 240)))',
  'for _,s in ipairs(out) do print(s) end'
].join('\n');

function runInject() {
  if (injState !== 0 || !L) return;
  injState = 1;
  try {
    var codeStr = Memory.allocUtf8String(CODE);
    var fnLoad = new NativeFunction(fns['luaL_loadbuffer'], 'int', ['pointer', 'pointer', 'size_t', 'pointer']);
    var fnPcall = new NativeFunction(fns['lua_pcall'], 'int', ['pointer', 'int', 'int', 'int']);
    var nameStr = Memory.allocUtf8String('=frida_inject');
    var r = fnLoad(L, codeStr, CODE.length, nameStr);
    send({ ev: 'inj_load', r: r });
    if (r === 0) {
      var rc = fnPcall(L, 0, 0, 0);
      send({ ev: 'inj_pcall', rc: rc });
      if (rc !== 0) {
        try {
          var fnToStr = new NativeFunction(fns['lua_tolstring'], 'pointer', ['pointer', 'int', 'pointer']);
          var szp = Memory.alloc(4);
          var ps = fnToStr(L, -1, szp);
          if (!ps.isNull()) send({ ev: 'inj_err', msg: ps.readUtf8String() });
        } catch (e) {}
      }
    }
  } catch (e) {
    send({ ev: 'inj_exc', e: String(e) });
  }
}

function arm() {
  if (!findFns()) return false;
  if (arm.done) return true;
  arm.done = true;
  ['luaL_loadbuffer', 'lua_load', 'luaL_loadfile', 'luaL_loadfilex', 'luaL_loadstring'].forEach(function (n) {
    var p = null;
    try { p = mod.findExportByName(n); } catch (e) {}
    if (!p) return;
    Interceptor.attach(p, {
      onEnter: function (a) {
        calls++;
        if (!L) {
          L = a[0];
          send({ ev: 'lua_state', via: n, p: L.toString() });
        }
        if (injState === 0 && calls > 5) {
          runInject();
        }
      }
    });
    send({ ev: 'luainject_hooked', sym: n });
  });
  send({ ev: 'luainject_armed' });
  return true;
}
arm.done = false;

var iv = setInterval(arm, 500);
var ticks = 0;
var iv2 = setInterval(function () {
  ticks++;
  if (ticks > 400) { clearInterval(iv2); clearInterval(iv); }
}, 500);
setTimeout(function () {
  send({ ev: 'luainject_timeout', calls: calls, hasL: !!L, state: injState });
}, 210000);
