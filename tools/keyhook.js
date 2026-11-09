'use strict';
/*
 * Hook LuaStack::setHongenKAndS in libcocos2dlua.so to capture the XXTEA
 * key/sign passed at runtime.
 *
 * Signature (C++ static member, symbol exported):
 *   _ZN7cocos2d8LuaStack14setHongenKAndSEPKciS2_i
 *   void LuaStack::setHongenKAndS(const char* key, int keyLen,
 *                                 const char* sign, int signLen)
 *   -> x0=key, w1=keyLen, x2=sign, w3=signLen
 */
function emit(o) { send(o); }

var SYM = '_ZN7cocos2d8LuaStack14setHongenKAndSEPKciS2_i';
var keyHooked = false;
function hookKey() {
  if (keyHooked) return true;
  var exp = null;
  try {
    exp = Module.getGlobalExportByName(SYM);
  } catch (e) {
    exp = null;
  }
  if (exp === null || exp.isNull()) {
    // v50: frida17 getGlobalExportByName misses exports of late-loaded
    // modules (proven with AAsset_close in libandroid) — walk modules too.
    try {
      var mods = Process.enumerateModules();
      for (var i = 0; i < mods.length; i++) {
        try {
          var e2 = mods[i].findExportByName(SYM);
          if (e2 && !e2.isNull()) { exp = e2; send({ ev: 'keyhook_walk', mod: mods[i].name }); break; }
        } catch (e3) {}
      }
    } catch (e4) {}
  }
  if (exp === null || exp.isNull() || exp.isNull()) {
    // module may not be loaded yet; retry later
    return false;
  }
  Interceptor.attach(exp, {
    onEnter: function (a) {
      try {
        var keyLen = a[1].toInt32();
        var signLen = a[3].toInt32();
        var key = '';
        var sign = '';
        if (keyLen > 0 && keyLen < 4096) {
          var kb = a[0].readByteArray(keyLen);
          var ku = new Uint8Array(kb);
          for (var i = 0; i < ku.length; i++) key += String.fromCharCode(ku[i]);
        }
        if (signLen > 0 && signLen < 4096) {
          var sb = a[2].readByteArray(signLen);
          var su = new Uint8Array(sb);
          for (var j = 0; j < su.length; j++) sign += String.fromCharCode(su[j]);
        }
        emit({ ev: 'XXTEA_KEY', key: key, keyLen: keyLen, sign: sign, signLen: signLen,
               keyHex: key ? Array.from(new Uint8Array(a[0].readByteArray(keyLen)))
                 .map(function (b) { return ('0' + b.toString(16)).slice(-2); }).join('') : '' });
      } catch (e) {
        emit({ ev: 'keyhook_err', e: String(e) });
      }
    }
  });
  keyHooked = true;
  emit({ ev: 'keyhook_installed' });
  return true;
}

// v68: report every xxtea/hongen/sign-ish export of cocos to find the REAL
// key setter (setHongenKAndS is exported but apparently never called).
var expScanned = false;
function scanExports() {
  if (expScanned) return;
  try {
    var mods = Process.enumerateModules();
    var sawCocos = false;
    var hits = [];
    var KW = /xxtea|hongen|manager|downloader|manifest|download|resurl|remoteurl/i;
    for (var i = 0; i < mods.length; i++) {
      var mname = mods[i].name || '';
      var appLib = mname.indexOf('cocos') >= 0 || mname.indexOf('ihuman') >= 0 || mname.indexOf('hpyr') >= 0 || mname.indexOf('ihcommon') >= 0 || mname.indexOf('msaoai') >= 0;
      if (mname.indexOf('cocos') >= 0) sawCocos = true;
      if (!appLib) continue;
      try {
        var sy = mods[i].enumerateSymbols();
        for (var j = 0; j < sy.length; j++) {
          var nm = sy[j].name || '';
          if (KW.test(nm) && hits.length < 180) hits.push(mname.split('.')[0] + '|' + nm);
        }
      } catch (e0) {}
    }
    if (!sawCocos) return;   // retry until cocos is loaded
    emit({ ev: 'cocos-syms', n: hits });
    expScanned = true;
  } catch (e) {}
}

// v71: hook the REAL xxtea surface (names discovered via export scan):
//   _Z13xxtea_decryptPhjS_jPj  (data,len,key,&keylen)
//   _ZN7cocos2d5extra6Crypto15encryptXXTEALuaEPKciS3_i (key,keyLen,sign,signLen)
//   _ZN7cocos2d8LuaStack22cleanupXXTEAKeyAndSignEv
var xtArmed = false;
function armXxtea() {
  if (xtArmed) return;
  var SYMS = [
    ['_Z13xxtea_decryptPhjS_jPj', 'dec'],
    ['_ZN7cocos2d5extra6Crypto15encryptXXTEALuaEPKciS3_i', 'enc'],
    ['_ZN7cocos2d8LuaStack22cleanupXXTEAKeyAndSignEv', 'clean']
  ];
  var found = [];
  var mods = [];
  try { mods = Process.enumerateModules(); } catch (e) {}
  function resolve(name) {
    try { var a0 = Module.getGlobalExportByName(name); if (a0 && !a0.isNull()) return a0; } catch (e) {}
    for (var i = 0; i < mods.length; i++) {
      var mn2 = mods[i].name || '';
      if (mn2.indexOf('cocos') < 0 && mn2.indexOf('ihuman') < 0 && mn2.indexOf('hpyr') < 0 && mn2.indexOf('ihcommon') < 0) continue;
      try { var e1 = mods[i].findExportByName(name); if (e1 && !e1.isNull()) return e1; } catch (e2) {}
    }
    return null;
  }
  SYMS.forEach(function (pair) {
    var addr = resolve(pair[0]);
    if (!addr) return;
    found.push(pair[1]);
    if (pair[1] === 'dec') {
      var dn = 0;
      Interceptor.attach(addr, {
        onEnter: function (a) {
          try {
            if (dn >= 30) return;
            dn++;
            var len = a[1].toInt32();
            var kp = a[2];
            var klp = a[3];
            var kl = 16;
            try { if (!klp.isNull()) kl = klp.readU64().toNumber(); } catch (e) {}
            if (kl <= 0 || kl > 64) kl = 16;
            var ku = new Uint8Array(kp.readByteArray(kl));
            var kh = Array.from(ku).map(function (b) { return ('0' + b.toString(16)).slice(-2); }).join('');
            emit({ ev: 'XT-DEC', keyHex: kh, keyLen: kl, dataLen: len });
          } catch (e3) { emit({ ev: 'XT-DEC-err', e: String(e3) }); }
        }
      });
    } else if (pair[1] === 'enc') {
      var en = 0;
      Interceptor.attach(addr, {
        onEnter: function (a) {
          try {
            if (en >= 30) return;
            en++;
            var keyLen = a[1].toInt32();
            var signLen = a[3].toInt32();
            var key = '', sign = '', keyHex = '';
            if (keyLen > 0 && keyLen < 4096) {
              var ku = new Uint8Array(a[0].readByteArray(keyLen));
              for (var i = 0; i < ku.length; i++) key += String.fromCharCode(ku[i]);
              keyHex = Array.from(ku).map(function (b) { return ('0' + b.toString(16)).slice(-2); }).join('');
            }
            if (signLen > 0 && signLen < 4096) {
              var su = new Uint8Array(a[2].readByteArray(signLen));
              for (var j = 0; j < su.length; j++) sign += String.fromCharCode(su[j]);
            }
            emit({ ev: 'XXTEA_KEY', via: 'encryptXXTEALua', key: key, keyLen: keyLen, sign: sign, signLen: signLen, keyHex: keyHex });
          } catch (e4) { emit({ ev: 'XT-ENC-err', e: String(e4) }); }
        }
      });
    } else {
      var cn2 = 0;
      Interceptor.attach(addr, {
        onEnter: function () { if (cn2 < 10) { cn2++; emit({ ev: 'XT-CLEAN' }); } }
      });
    }
  });
  if (found.length) { xtArmed = true; emit({ ev: 'xt-armed', w: found }); }
}

// v73: download-pipeline hooks — every URL these carry is a resource URL.
// std::string reader handles libc++ long/SSO layouts.
function readStdStr(p) {
  try {
    var b = p.readPointer();
    if (!b.isNull() && (b.toInt32() & 1) === 0) {
      var sz = p.add(8).readU64().toNumber();
      if (sz > 0 && sz < 4096) return b.readUtf8String(sz);
    } else {
      var ss = (p.readU8() >> 1) & 0x7f;
      if (ss > 0) return p.add(1).readUtf8String(ss);
    }
  } catch (e) {}
  try { return p.readCString(); } catch (e2) { return ''; }
}
var dlArmed = false;
function armDownloads() {
  if (dlArmed) return;
  var mods = [];
  try { mods = Process.enumerateModules(); } catch (e) {}
  function resolve(name) {
    try { var a0 = Module.getGlobalExportByName(name); if (a0 && !a0.isNull()) return a0; } catch (e) {}
    for (var i = 0; i < mods.length; i++) {
      if ((mods[i].name || '').indexOf('cocos') < 0) continue;
      try { var e1 = mods[i].findExportByName(name); if (e1 && !e1.isNull()) return e1; } catch (e2) {}
    }
    return null;
  }
  var dn = 0;
  function hookStr(tag, sym, order) {
    var addr = resolve(sym);
    if (!addr) return false;
    Interceptor.attach(addr, {
      onEnter: function (a) {
        try {
          if (dn >= 120) return;
          dn++;
          var o = { ev: 'DL-URL', w: tag };
          for (var k = 0; k < order.length; k++) {
            var idx = order[k][0];
            o[order[k][1]] = readStdStr(a[idx]);
          }
          emit(o);
        } catch (e3) {}
      }
    });
    return true;
  }
  var armed = [];
  if (hookStr('amEx.create', '_ZN7cocos2d9extension15AssetsManagerEx6createERKSsS3_', [[0,'manifestUrl'],[1,'storage']])) armed.push('create');
  if (hookStr('setVersionFileUrl', '_ZN7cocos2d9extension13AssetsManager17setVersionFileUrlEPKc', [[0,'url']])) armed.push('verUrl');
  if (hookStr('downloadSync', '_ZN7cocos2d9extension10Downloader12downloadSyncERKSsS3_S3_', [[0,'url'],[1,'dst'],[2,'cksum']])) armed.push('dlSync');
  if (hookStr('downloadToBufferSync', '_ZN7cocos2d9extension10Downloader20downloadToBufferSyncERKSsPhRKlS3_', [[0,'url']])) armed.push('dlBuf');
  var su = resolve('_ZN7cocos2d9extension15AssetsManagerEx11startUpdateEv');
  if (su) { Interceptor.attach(su, { onEnter: function () { try { emit({ ev: 'DL-START' }); } catch (e) {} } }); armed.push('startUpdate'); }
  var du = resolve('_ZN7cocos2d9extension13AssetsManager21downloadAndUncompressEv');
  if (du) { Interceptor.attach(du, { onEnter: function () { try { emit({ ev: 'DL-START-AM' }); } catch (e) {} } }); armed.push('dlUncmp'); }
  if (armed.length) { dlArmed = true; emit({ ev: 'dl-armed', w: armed }); }
}

// v67: after cocos is located, also attach the libcurl URL logger
var curlArmed = false;
function armCurl() {
  if (curlArmed) return;
  var addr = null;
  try { addr = Module.getGlobalExportByName('curl_easy_setopt'); } catch (e) { addr = null; }
  if (!addr || addr.isNull()) {
    try {
      var mods = Process.enumerateModules();
      for (var i = 0; i < mods.length; i++) {
        try {
          var e1 = mods[i].findExportByName('curl_easy_setopt');
          if (e1 && !e1.isNull()) { addr = e1; break; }
        } catch (e2) {}
      }
    } catch (e3) {}
  }
  if (!addr || addr.isNull()) return;
  curlArmed = true;
  var cn = 0;
  Interceptor.attach(addr, {
    onEnter: function (a) {
      try {
        if (a[1].toInt32() === 10002 && cn < 200) {
          cn++;
          emit({ ev: 'URL', u: a[2].readCString() });
        }
      } catch (e4) {}
    }
  });
  emit({ ev: 'curl-log-ready' });
}

// ---- v83: Lua takeover inside keyhook (proven polling path) ----
var luaL = null, luaFns = {}, luaCalls = 0, luaInj = 0, luaArmed = false;
var LUA_CODE = [
  'local out = {}',
  'local function P(s) out[#out+1] = s end',
  'local function keys(t)',
  '  if type(t) ~= "table" then return type(t) end',
  '  local ks = {}',
  '  for k in pairs(t) do ks[#ks+1] = tostring(k) end',
  '  table.sort(ks)',
  '  return table.concat(ks, ",", 1, math.min(#ks, 80))',
  'end',
  'local g = {}',
  'for k,v in pairs(_G) do g[k] = v end',
  'local UD = g.UserData',
  'local m = (type(UD)=="table") and UD.model or nil',
  'if m == nil then local UI = g.UserInfo; m = (type(UI)=="table") and UI.model or nil end',
  'if m == nil then P("nomodel") return "x" end',
  'P("m.keys="..keys(m))',
  'local inner = m.model',
  'P("inner.type="..type(inner))',
  'if type(inner)=="table" then',
  '  P("inner.keys="..keys(inner))',
  '  local mgr = inner.manager or inner.db',
  '  P("mgr.type="..type(mgr)..":"..keys(mgr))',
  '  if type(mgr)=="table" then',
  '    local db = mgr.dataBase',
  '    P("db.type="..type(db))',
  '    if type(db)=="userdata" then',
  '      local mt = getmetatable(db)',
  '      P("db.mt="..keys(mt))',
  '      if type(mt)=="table" then',
  '        local idx = mt.__index',
  '        P("db.idx="..keys(idx))',
  '        if type(idx)=="table" then',
  '          for _,fn in ipairs({"execute","exec","run","query","prepare","step"}) do',
  '            if type(idx[fn])=="function" then',
  '              P("dbfn."..fn.."=yes")',
  '            end',
  '          end',
  '        end',
  '      end',
  '    end',
  '  end',
  'end',
  'local function try(sql)',
  '  local inner2 = m.model',
  '  local mgr = inner2 and (inner2.manager or inner2.db)',
  '  local db = mgr and mgr.dataBase',
  '  if type(db) ~= "userdata" then P("TRY "..sql.." -> nodb") return end',
  '  local mt = getmetatable(db)',
  '  local idx = type(mt)=="table" and mt.__index or nil',
  '  if type(idx) ~= "table" then P("TRY -> noidx") return end',
  '  local fn = idx.execute or idx.exec or idx.run or idx.query',
  '  if type(fn) ~= "function" then P("TRY -> nofn") return end',
  '  local ok, r = pcall(function() return fn(db, sql) end)',
  '  P("TRY "..sql:sub(1,100).." -> "..tostring(ok)..":"..tostring(r))',
  'end',
  'try("UPDATE UserModel SET allpack_flag=1, tmp_allpack_flag=1, allpack_childlink_flag=1, vip_purchased_flag=1, vip_type=1, vip_continuous=1, vip_start_ts=1790000000, vip_end_ts=4102416000, vip_trial_flag=1")',
  'local ok1, r1 = pcall(function() return m:selectData("allpack_flag") end)',
  'P("READ.allpack_flag="..tostring(ok1)..":"..tostring(r1))',
  'local ok2, r2 = pcall(function() return m:hasAllPack() end)',
  'P("READ.hasAllPack="..tostring(ok2)..":"..tostring(r2))',
  'local VM = g.VipManager',
  'if type(VM)=="table" then',
  '  local c = VM.class or VM',
  '  if type(c.isValidVip)=="function" then',
  '    local ok, r = pcall(function() return c.isValidVip(VM) end)',
  '    P("READ.isValidVip="..tostring(ok)..":"..tostring(r))',
  '  end',
  '  if type(c.hasAllPack)=="function" then',
  '    local ok, r = pcall(function() return c.hasAllPack(VM) end)',
  '    P("READ.VMhasAllPack="..tostring(ok)..":"..tostring(r))',
  '  end',
  'end',
  'return table.concat(out, string.char(10))'
].join('\n');

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
  ['luaL_loadbuffer', 'luaL_loadbufferx', 'lua_load', 'luaL_loadfile', 'luaL_loadstring', 'lua_pcall', 'lua_tolstring'].forEach(function (n) {
    if (luaFns[n]) return;
    var q = findAny(n);
    if (q) luaFns[n] = q;
  });
  return !!(luaFns['luaL_loadbuffer'] && luaFns['lua_pcall'] && luaFns['lua_tolstring']);
}

function luaRunInject() {
  if (luaInj !== 0 || !luaStatePtr) return;
  luaInj = 1;
  try {
    var codeStr = Memory.allocUtf8String(LUA_CODE);
    var fnLoad = new NativeFunction(luaFns['luaL_loadbuffer'], 'int', ['pointer', 'pointer', 'size_t', 'pointer']);
    var fnPcall = new NativeFunction(luaFns['lua_pcall'], 'int', ['pointer', 'int', 'int', 'int']);
    var nm = Memory.allocUtf8String('=frida_inject');
    var r = fnLoad(luaStatePtr, codeStr, LUA_CODE.length, nm);
    emit({ ev: 'inj_load', r: r });
    if (r === 0) {
      var rc = fnPcall(luaStatePtr, 0, 1, 0);
      emit({ ev: 'inj_pcall', rc: rc });
      try {
        var fnToStr = new NativeFunction(luaFns['lua_tolstring'], 'pointer', ['pointer', 'int', 'pointer']);
        var szp = Memory.alloc(8);
        var ps = fnToStr(luaStatePtr, -1, szp);
        if (!ps.isNull()) {
          var len = szp.readU64().toNumber();
          var txt = ps.readUtf8String(Math.min(len, 60000)) || '';
          emit({ ev: 'inj_out', len: len, txt: txt });
        } else {
          emit({ ev: 'inj_nostr', rc: rc });
        }
      } catch (e2) { emit({ ev: 'inj_read_err', e: String(e2) }); }
    }
  } catch (e) {
    emit({ ev: 'inj_exc', e: String(e) });
  }
}

var luaStatePtr = null;
function armLua() {
  if (luaArmed) return;
  if (!luaResolve()) return;
  luaArmed = true;
  ['luaL_loadbuffer', 'luaL_loadbufferx', 'lua_load', 'luaL_loadfile', 'luaL_loadstring', 'lua_pcall'].forEach(function (n) {
    var p = luaFns[n];
    if (!p) return;
    try {
      Interceptor.attach(p, {
        onEnter: function (a) {
          luaCalls++;
          if (!luaStatePtr) {
            luaStatePtr = a[0];
            emit({ ev: 'lua_state', via: n, p: luaStatePtr.toString() });
          }
          if (luaInj === 0 && luaCalls > 3) luaRunInject();
        }
      });
      emit({ ev: 'lua_hooked', sym: n });
    } catch (e) { emit({ ev: 'lua_hook_err', sym: n, e: String(e) }); }
  });
  // v84: LuaJavaBridge proves Lua runs (callJavaStaticMethod logged at start).
  // s_luaState is the static global holding the state pointer.
  try {
    var mods = Process.enumerateModules();
    for (var i = 0; i < mods.length; i++) {
      try {
        var ps = mods[i].findExportByName('_ZN13LuaJavaBridge10s_luaStateE');
        if ((!ps || ps.isNull()) && /libcocos2dlua/.test(mods[i].name || '')) {
          // fallback: symtab value is image vaddr (ET_DYN, load base vaddr 0)
          ps = mods[i].base.add(0x25f9cd8);
        }
        if (ps && !ps.isNull()) { luaStateSlot = ps; emit({ ev: 'lua_state_slot', p: ps.toString(), mod: mods[i].name }); }
        var pj = mods[i].findExportByName('_ZN13LuaJavaBridge20callJavaStaticMethodEP9lua_State');
        if (pj && !pj.isNull() && !ljArmed) {
          ljArmed = true;
          Interceptor.attach(pj, {
            onEnter: function (a) {
              luaCalls++;
              if (!luaStatePtr) {
                luaStatePtr = a[0];
                emit({ ev: 'lua_state', via: 'callJavaStaticMethod', p: luaStatePtr.toString() });
              }
              if (luaInj === 0 && luaCalls > 3) luaRunInject();
            }
          });
          emit({ ev: 'lua_hooked', sym: 'callJavaStaticMethod' });
        }
      } catch (e2) {}
    }
  } catch (e3) {}
  try {
    var fx = findAny('_ZN7cocos2d8LuaStack17executeScriptFileEPKc');
    if (fx && !fx.isNull()) {
      Interceptor.attach(fx, {
        onEnter: function (a) {
          try { this.fp = a[1].readCString(); } catch (e) { this.fp = '?'; }
          if (luaInj === 0 && luaStatePtr) { emit({ ev: 'execfile', f: this.fp }); luaRunInject(); }
        }
      });
      emit({ ev: 'lua_hooked', sym: 'executeScriptFile' });
    }
  } catch (e4) { emit({ ev: 'lua_hook_err', sym: 'executeScriptFile', e: String(e4) }); }
  emit({ ev: 'lua_armed' });
}
var luaStateSlot = null;
var ljArmed = false;

// poll the static slot too (works even before any hook fires)
var slotSeenAt = 0;
setInterval(function () {
  if (!luaStateSlot || luaStatePtr) return;
  try {
    var p = luaStateSlot.readPointer();
    if (!p.isNull()) {
      luaStatePtr = p;
      slotSeenAt = Date.now();
      emit({ ev: 'lua_state', via: 's_luaState', p: p.toString() });
      // only inject from the Lua thread (hooks above); if no hook ever
      // fired, last-resort injection from JS after a 15s grace period
      if (luaInj === 0 && luaCalls === 0) {
        setTimeout(function () {
          if (luaInj === 0 && luaStatePtr && luaCalls === 0) luaRunInject();
        }, 8000);
      }
    }
  } catch (e) {}
}, 500);

// try now, then poll until libcocos2dlua.so is loaded (up to 180s)
var tries = 0;
var iv = setInterval(function () {
  tries++;
  var done = false;
  try { done = hookKey(); } catch (e) { emit({ ev: 'poll_err', e: String(e) }); }
  armCurl();
  scanExports();
  armXxtea();
  armDownloads();
  try { armLua(); } catch (e5) { emit({ ev: 'lua_arm_err', e: String(e5) }); }
  if (done && luaArmed) { clearInterval(iv); return; }
  if (tries % 25 === 0) {
    var found = false;
    try { var m2 = Module.getGlobalExportByName(SYM); found = !!(m2 && !m2.isNull()); } catch (e) {}
    emit({ ev: 'kh-hb', t: tries, found: found ? 1 : 0 });
  }
  if (tries > 600) { clearInterval(iv); emit({ ev: 'keyhook_giveup' }); }
}, 300);

// also watch every dlopen entry point so we catch the lib however it loads
['android_dlopen_ext', 'dlopen', '__loader_dlopen', '__loader_android_dlopen_ext'].forEach(function (sym) {
  try {
    var dl = Module.getGlobalExportByName(sym);
    Interceptor.attach(dl, {
      onEnter: function (a) { try { this.p = a[0].readCString(); } catch (e) { this.p = ''; } },
      onLeave: function () {
        if (this.p && this.p.indexOf('libcocos2dlua') >= 0) {
          emit({ ev: 'cocos_loaded', path: this.p });
          setTimeout(function () { hookKey(); try { armLua(); } catch (e6) {} }, 50);
        }
      }
    });
    emit({ ev: 'dlwatch_ok', sym: sym });
  } catch (e) { emit({ ev: 'dlwatch_err', sym: sym, e: String(e) }); }
});

emit({ ev: 'keyhook_ready' });
