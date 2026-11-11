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
  'local IHM = package.loaded and package.loaded["app.common.ihumansdk.IHumanManager"]',
  'local LM = package.loaded and package.loaded["app.manager.LoginManager"]',
  'local function pick(tbl, name)',
  '  if type(tbl) ~= "table" then return nil end',
  '  local f = tbl[name]',
  '  if f == nil and type(tbl.class) == "table" then f = tbl.class[name] end',
  '  if f == nil and type(tbl.class) == "table" and type(tbl.class.__index) == "table" then f = tbl.class.__index[name] end',
  '  return f',
  'end',
  'local DIR = "/data/user/0/com.ihuman.pinyin/files/"',
  'local function append(fn, s)',
  '  pcall(function() local f = io.open(DIR..fn, "a"); if f then f:write(tostring(s)); f:write("\\n"); f:close() end end)',
  'end',
  'local function readfile(p)',
  '  local t = nil',
  '  pcall(function() local f = io.open(p, "r"); if f then t = f:read("*a"); f:close() end end)',
  '  return t',
  'end',
  'local function exists(fn)',
  '  local e = false',
  '  pcall(function() local f = io.open(DIR..fn, "r"); if f then e = true; f:close() end end)',
  '  return e',
  'end',
  'pcall(function() local f = io.open(DIR.."otp.txt", "a"); if f then f:close() end end)',
  'append("v120_dump.txt", "V126_START")',
  'local PHONE = "13662416252"',
  'local tick = 0',
  'local smsDone = exists("sms_sent.flag")',
  'local loginStarted = false',
  'local logged = false',
  'local ptr = 1',
  'local OTP_PATHS = {DIR.."otp.txt", "/data/data/com.ihuman.pinyin/files/otp.txt"}',
  'local ids = {"PY002","PY003","PY004","PY005","PY006","PY007","PY008","PY009","PY010","PY011","PY012","PY013","PY014","PY015","PY016","PY017","PY018","PY019","PY020","PY021","PY022","PY023","PY024","PY025","PY026","PY027","PY028","PY029","PY030","PY031","PY032","PY033","PY034","PY035","PY036","PY037","PY038","PY039","PY040","PY041","PY042","PY043","PY044","PY045","PY046","PY047","PY048","PY049","PY050","practice_01","practice_02","practice_03","practice_05","exercise_02","exercise_03","book_S1E02","book_S1E03","book_S1E05","book_S1E10","battle_02","battle_03","difficult_game_2","song_PY002","song_PY003","say_template_2","spell_template_2","shizi_radical","linkagegames_common"}',
  'local function scanTbl(tag, t, depth)',
  '  if type(t) ~= "table" or depth <= 0 then return end',
  '  local n = 0',
  '  for k, v in pairs(t) do',
  '    if type(v) == "string" and #v > 3 and #v < 500 then',
  '      local lk = tostring(k):lower()',
  '      if lk:find("token") or lk:find("session") or lk:find("uid") or lk:find("ticket") or lk:find("account") or lk:find("userid") then append("v120_dump.txt", tag.." T."..tostring(k).."="..v); n = n + 1 end',
  '    elseif type(v) == "table" then',
  '      n = n + 1',
  '      if n < 12 then scanTbl(tag.."."..tostring(k), v, depth - 1) end',
  '    end',
  '    if n > 40 then break end',
  '  end',
  'end',
  'local function dumpState(tag)',
  '  if type(LM) == "table" then',
  '    local model = LM.model or LM.userInfo or LM.userData',
  '    if type(model) == "table" then',
  '      for k, v in pairs(model) do',
  '        if type(v) == "string" and #v > 0 and #v < 500 then append("v120_dump.txt", tag.." MODEL."..tostring(k).."="..v) end',
  '        if type(v) == "table" then scanTbl(tag.." MODEL."..tostring(k), v, 2) end',
  '      end',
  '    end',
  '  end',
  '  for _, n in ipairs({"getAccountID","getSession","getUToken","getCurrentUserId"}) do',
  '    local f = pick(LM, n) or pick(IHM, n)',
  '    if type(f) == "function" then',
  '      local ok, r = pcall(f, LM)',
  '      if ok and r ~= nil and type(r) ~= "table" then append("v120_dump.txt", tag.." FN."..n.."="..tostring(r)) end',
  '      local ok2, r2 = pcall(f, IHM)',
  '      if ok2 and r2 ~= nil and type(r2) ~= "table" then append("v120_dump.txt", tag.." FN2."..n.."="..tostring(r2)) end',
  '    end',
  '  end',
  'end',
  'local function harvestRound(batch)',
  '  local AM = _G.AssetMgr',
  '  if type(AM) ~= "table" then append("v120_dump.txt", "NO_AM") return end',
  '  for i = 1, batch do',
  '    local id = ids[ptr]',
  '    if id == nil then break end',
  '    ptr = ptr + 1',
  '    local ok, a = pcall(function() return AM:getAsset(id) end)',
  '    if ok and type(a) == "table" then',
  '      local ok3, st = pcall(function() return a:getState() end)',
  '      if ok3 and st == 3 then',
  '        append("v120_dump.txt", "SKIP."..id.." installed")',
  '      else',
  '        local ok2, r2 = pcall(function() return a:download() end)',
  '        append("v120_dump.txt", "DL."..id.."="..tostring(ok2))',
  '      end',
  '    else',
  '      append("v120_dump.txt", "GETFAIL."..id)',
  '    end',
  '  end',
  'end',
  'local function step()',
  '  tick = tick + 1',
  '  if not smsDone then',
  '    smsDone = true',
  '    local smsFn = pick(IHM, "sendSMSWithMobile")',
  '    append("v120_dump.txt", "V126_SEND_TRY fn="..type(smsFn))',
  '    if type(smsFn) == "function" then',
  '      local ok1, r1 = pcall(function() return smsFn(IHM, PHONE) end)',
  '      append("v120_dump.txt", "V126_SEND "..tostring(ok1)..":"..tostring(r1))',
  '      pcall(function() local f = io.open(DIR.."sms_sent.flag","w"); if f then f:write("1"); f:close() end end)',
  '    end',
  '    return',
  '  end',
  '  if not loginStarted then',
  '    local otp = nil',
  '    local where = ""',
  '    for _, p in ipairs(OTP_PATHS) do',
  '      otp = readfile(p)',
  '      if otp then where = p; break end',
  '    end',
  '    if otp == nil then',
  '      if tick % 10 == 0 then append("v120_dump.txt", "OTPCHK none tick="..tick) end',
  '      return',
  '    end',
  '    otp = otp:gsub("%s+", "")',
  '    if #otp >= 4 and #otp <= 8 and otp:match("^%d+$") then',
  '      loginStarted = true',
  '      append("v120_dump.txt", "LOGIN_START otp_len="..#otp.." from="..where)',
  '      local loginFn = pick(IHM, "loginWithMobile")',
  '      append("v120_dump.txt", "LOGIN_FN="..type(loginFn))',
  '      if type(loginFn) == "function" then',
  '        local okA, rA = pcall(function() return loginFn(IHM, PHONE, otp) end)',
  '        append("v120_dump.txt", "LOGIN_A="..tostring(okA)..":"..tostring(rA))',
  '        if not okA then',
  '          local okB, rB = pcall(function() return loginFn(PHONE, otp) end)',
  '          append("v120_dump.txt", "LOGIN_B="..tostring(okB)..":"..tostring(rB))',
  '        end',
  '      end',
  '    else',
  '      append("v120_dump.txt", "OTP_BAD from="..where.." len="..#otp)',
  '    end',
  '  else',
  '    local acc = nil',
  '    local f = pick(LM, "getAccountID")',
  '    if type(f) == "function" then local ok, r = pcall(f, LM); if ok and r ~= nil and tostring(r) ~= "" then acc = tostring(r) end end',
  '    if acc and not logged then',
  '      logged = true',
  '      append("v120_dump.txt", "V126_LOGGED acc="..acc)',
  '      dumpState("LOGGED")',
  '    end',
  '    if tick % 10 == 0 then dumpState("T"..tick) end',
  '    if logged and ptr <= #ids then harvestRound(3) end',
  '  end',
  'end',
  '_G.__PB = {step = step}',
  'local okSched = pcall(function()',
  '  local d = cc.Director:getInstance()',
  '  d:getScheduler():scheduleScriptFunc(step, 1.2, false)',
  '  return true',
  'end)',
  'append("v120_dump.txt", "V126_SCHED="..tostring(okSched))',
  'local okFirst = pcall(step)',
  'append("v120_dump.txt", "V126_FIRST="..tostring(okFirst))',
  'return table.concat(out, string.char(10))'
].join('\n');

var LUA_TICK = [
  'local s = _G.__PB',
  'if type(s) == "table" and type(s.step) == "function" then',
  '  local ok, err = pcall(s.step)',
  '  if not ok then return "T:ERR:"..tostring(err) end',
  '  return "T:OK"',
  'end',
  'return "T:NOSTATE"'
].join('\n');

var lastTickAt = 0, tickBusy = false, tickN = 0;
function maybeTick() {
  if (luaInj === 0 || !luaStatePtr || tickBusy) return;
  var now = Date.now();
  if (now - lastTickAt < 1200) return;
  lastTickAt = now;
  tickBusy = true;
  try {
    var codeStr = Memory.allocUtf8String(LUA_TICK);
    var fnLoad = new NativeFunction(luaFns['luaL_loadbuffer'], 'int', ['pointer', 'pointer', 'size_t', 'pointer']);
    var fnPcall = new NativeFunction(luaFns['lua_pcall'], 'int', ['pointer', 'int', 'int', 'int']);
    var nm = Memory.allocUtf8String('=frida_tick');
    var r = fnLoad(luaStatePtr, codeStr, LUA_TICK.length, nm);
    if (r === 0) {
      fnPcall(luaStatePtr, 0, 0, 0);
      tickN++;
      if (tickN % 25 === 0) emit({ ev: 'tick', n: tickN });
    }
  } catch (e) { emit({ ev: 'tick_exc', e: String(e) }); }
  tickBusy = false;
}

var LUA_CODE2 = [
  'local out = {}',
  'local function P(s) out[#out+1] = s end',
  'local g = {}',
  'for k,v in pairs(_G) do g[k] = v end',
  'local UD = g.UserData',
  'local m = (type(UD)=="table") and UD.model or nil',
  'if m == nil then local UI = g.UserInfo; m = (type(UI)=="table") and UI.model or nil end',
  'if type(m) == "table" and type(m.model) == "table" then m = m.model end',
  'if type(m) == "table" and type(m.manager) == "table" then',
  '  local db = m.manager.dataBase',
  '  if type(db) == "userdata" then',
  '    local ok, r = pcall(function() return db:execute("UPDATE UserModel SET allpack_flag=1, tmp_allpack_flag=1, allpack_childlink_flag=1, vip_purchased_flag=1, vip_type=1, vip_continuous=1, vip_start_ts=1790000000, vip_end_ts=4102416000, vip_trial_flag=1") end)',
  '    P("UPDATE="..tostring(ok)..":"..tostring(r))',
  '  end',
  'end',
  'local ids = {{"battle_02","bac84a649a584147a79912bcbbc5b531"},{"book_S1E02","68dc51f33b4fa92c5106b6f953d5c1b3"},{"childlink_v2_math_q_6288","d92e8636e245ca1cd137071525407ed1"},{"difficult_game_2","1c74eb9202b704cfed9615cb69397601"},{"exercise_02","441bf0c32fb273f61efe52dffe4fd695"},{"linkagegames_common","552bb4d21fb543b4d79be29676f273d4"},{"say_template_2","5a03f972aa580c1f02337a46c4d8cfae"},{"shizi_radical","37d795f079ea7ba7582000d058445fcc"},{"song_PY002","72e8472ccd764c6583f0c6a09fd5c969"},{"spell_template_2","7499a9467a76196ea281449b6f02a642"},{"template2","1c716582a60fde601490e2532b6d1140"},{"tone_roller_coaster_2","5cab24a6f8ff2bf652fdccbc74ef8ab7"},{"ui_v_ve_explain","c7e25890808adf45b13f208736409e39"},{"write_templet_03","bcacf1669a1f85577e53057b070964cc"}}',
  'local AM = g.AssetMgr',
  'local okloop, errloop = pcall(function()',
  'if type(AM) == "table" then',
  '  for _,pair in ipairs(ids) do',
  '    local id, md5 = pair[1], pair[2]',
  '    local ok, a = pcall(function() return AM:getAsset(id) end)',
  '    if ok and type(a) == "table" then',
  '      local ok3, st = pcall(function() return a:getState() end)',
  '      if ok3 and st == 3 then',
  '        P("SKIP."..id..".installed")',
  '      else',
  '        local ok2, r2 = pcall(function() return a:download() end)',
  '        P("TRIG."..id.."="..tostring(ok2)..":"..type(r2))',
  '      end',
  '    else',
  '      P("TRIG."..id.."=GETFAIL:"..tostring(a))',
  '    end',
  '  end',
  'end',
  'end)',
  'if not okloop then P("LOOPERR:"..tostring(errloop)) end',
  'return table.concat(out, string.char(10))'
].join('\n');

var LUA_CODE3 = [
  'local out = {}',
  'local function P(s) out[#out+1] = s end',
  'local g = {}',
  'for k,v in pairs(_G) do g[k] = v end',
  'local ids = {{"battle_02","bac84a649a584147a79912bcbbc5b531"},{"book_S1E02","68dc51f33b4fa92c5106b6f953d5c1b3"},{"childlink_v2_math_q_6288","d92e8636e245ca1cd137071525407ed1"},{"difficult_game_2","1c74eb9202b704cfed9615cb69397601"},{"exercise_02","441bf0c32fb273f61efe52dffe4fd695"},{"linkagegames_common","552bb4d21fb543b4d79be29676f273d4"},{"say_template_2","5a03f972aa580c1f02337a46c4d8cfae"},{"shizi_radical","37d795f079ea7ba7582000d058445fcc"},{"song_PY002","72e8472ccd764c6583f0c6a09fd5c969"},{"spell_template_2","7499a9467a76196ea281449b6f02a642"},{"template2","1c716582a60fde601490e2532b6d1140"},{"tone_roller_coaster_2","5cab24a6f8ff2bf652fdccbc74ef8ab7"},{"ui_v_ve_explain","c7e25890808adf45b13f208736409e39"},{"write_templet_03","bcacf1669a1f85577e53057b070964cc"}}',
  'local AM = g.AssetMgr',
  'if type(AM) == "table" then',
  '  for _,pair in ipairs(ids) do',
  '    local id = pair[1]',
  '    local ok, a = pcall(function() return AM:getAsset(id) end)',
  '    if ok and type(a) == "table" then',
  '      local st = nil',
  '      local ok2, r2 = pcall(function() return a:getState() end)',
  '      if ok2 then st = r2 end',
  '      local url = a.url',
  '      P("HARVEST."..id..".state="..tostring(st)..".url="..tostring(url))',
  '    else',
  '      P("HARVEST."..id..".=NOASSET:"..tostring(a))',
  '    end',
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

var injFails = 0;
var jsRetryStarted = false;
function luaRunInject() {
  if (luaInj !== 0 || !luaStatePtr) return;
  if (injFails >= 3) return;
  luaInj = 1;
  var useSafe = injFails > 0;
  try {
    var codeStr = Memory.allocUtf8String(LUA_CODE);
    var fnLoad = new NativeFunction(luaFns['luaL_loadbuffer'], 'int', ['pointer', 'pointer', 'size_t', 'pointer']);
    var fnPcall = new NativeFunction(luaFns['lua_pcall'], 'int', ['pointer', 'int', 'int', 'int']);
    var nm = Memory.allocUtf8String(useSafe ? '=frida_inject_safe' : '=frida_inject');
    var srcCode = LUA_CODE;
    var r = fnLoad(luaStatePtr, codeStr, srcCode.length, nm);
    emit({ ev: 'inj_load', r: r, safe: useSafe });
    if (r !== 0) {
      injFails++;
      luaInj = 0;
    }
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
          if (!harvestScheduled) {
            harvestScheduled = true;
            setTimeout(function () { try { luaRunInject2(); } catch (e) { emit({ ev: 'inj2_sch_err', e: String(e) }); } }, 70000);
          }
        } else {
          emit({ ev: 'inj_nostr', rc: rc });
        }
      } catch (e2) { emit({ ev: 'inj_read_err', e: String(e2) }); }
    }
  } catch (e) {
    injFails++;
    luaInj = 0;
    emit({ ev: 'inj_exc', e: String(e), fails: injFails });
  }
}

var harvestScheduled = false;
function luaRunInject2() {
  if (true) return; // disabled: JS-thread injection races (SIGILL)
  luaInj = 2;
  try {
    var codeStr = Memory.allocUtf8String(LUA_CODE2);
    var fnLoad = new NativeFunction(luaFns['luaL_loadbuffer'], 'int', ['pointer', 'pointer', 'size_t', 'pointer']);
    var fnPcall = new NativeFunction(luaFns['lua_pcall'], 'int', ['pointer', 'int', 'int', 'int']);
    var nm = Memory.allocUtf8String('=frida_harvest');
    var r = fnLoad(luaStatePtr, codeStr, LUA_CODE2.length, nm);
    emit({ ev: 'inj2_load', r: r });
    if (r === 0) {
      var rc = fnPcall(luaStatePtr, 0, 1, 0);
      emit({ ev: 'inj2_pcall', rc: rc });
      try {
        var fnToStr = new NativeFunction(luaFns['lua_tolstring'], 'pointer', ['pointer', 'int', 'pointer']);
        var szp = Memory.alloc(8);
        var ps = fnToStr(luaStatePtr, -1, szp);
        if (!ps.isNull()) {
          var len = szp.readU64().toNumber();
          var txt = ps.readUtf8String(Math.min(len, 60000)) || '';
          emit({ ev: 'inj2_out', len: len, txt: txt });
          if (!harvest2Scheduled) {
            harvest2Scheduled = true;
            setTimeout(function () { try { luaRunInject3(); } catch (e) { emit({ ev: 'inj3_sch_err', e: String(e) }); } }, 80000);
          }
        } else {
          emit({ ev: 'inj2_nostr', rc: rc });
        }
      } catch (e2) { emit({ ev: 'inj2_read_err', e: String(e2) }); }
    }
  } catch (e) {
    emit({ ev: 'inj2_exc', e: String(e) });
  }
}

var harvest2Scheduled = false;
function luaRunInject3() {
  if (true) return; // disabled: JS-thread injection races (SIGILL)
  luaInj = 3;
  try {
    var codeStr = Memory.allocUtf8String(LUA_CODE3);
    var fnLoad = new NativeFunction(luaFns['luaL_loadbuffer'], 'int', ['pointer', 'pointer', 'size_t', 'pointer']);
    var fnPcall = new NativeFunction(luaFns['lua_pcall'], 'int', ['pointer', 'int', 'int', 'int']);
    var nm = Memory.allocUtf8String('=frida_harvest2');
    var r = fnLoad(luaStatePtr, codeStr, LUA_CODE3.length, nm);
    emit({ ev: 'inj3_load', r: r });
    if (r === 0) {
      var rc = fnPcall(luaStatePtr, 0, 1, 0);
      emit({ ev: 'inj3_pcall', rc: rc });
      try {
        var fnToStr = new NativeFunction(luaFns['lua_tolstring'], 'pointer', ['pointer', 'int', 'pointer']);
        var szp = Memory.alloc(8);
        var ps = fnToStr(luaStatePtr, -1, szp);
        if (!ps.isNull()) {
          var len = szp.readU64().toNumber();
          var txt = ps.readUtf8String(Math.min(len, 60000)) || '';
          emit({ ev: 'inj3_out', len: len, txt: txt });
        } else {
          emit({ ev: 'inj3_nostr', rc: rc });
        }
      } catch (e2) { emit({ ev: 'inj3_read_err', e: String(e2) }); }
    }
  } catch (e) {
    emit({ ev: 'inj3_exc', e: String(e) });
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
          maybeTick();
          if (!luaStatePtr) {
            luaStatePtr = a[0];
            emit({ ev: 'lua_state', via: n, p: luaStatePtr.toString() });
          }
          if (luaInj === 0 && luaCalls >= 1) luaRunInject();
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
              maybeTick();
              if (!luaStatePtr) {
                luaStatePtr = a[0];
                emit({ ev: 'lua_state', via: 'callJavaStaticMethod', p: luaStatePtr.toString() });
              }
              if (luaInj === 0 && luaCalls >= 1) luaRunInject();
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
  try {
    var flb = findAny('_ZN7cocos2d8LuaStack13luaLoadBufferEP9lua_StatePKciS4_');
    if (flb && !flb.isNull()) {
      Interceptor.attach(flb, {
        onEnter: function (a) {
          try {
            if (!luaStatePtr && !a[0].isNull()) luaStatePtr = a[0];
          } catch (e) {}
          if (luaInj === 0 && luaStatePtr) { emit({ ev: 'lb_inject' }); luaRunInject(); }
          else if (luaInj !== 0) maybeTick();
        }
      });
      emit({ ev: 'lua_hooked', sym: 'luaLoadBuffer' });
    }
  } catch (e5) { emit({ ev: 'lua_hook_err', sym: 'luaLoadBuffer', e: String(e5) }); }
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
      if (luaInj === 0 && !jsRetryStarted) {
        jsRetryStarted = true;
        var tries = 0;
        var ivr = setInterval(function () {
          tries++;
          if (luaInj !== 0 || tries > 6) { clearInterval(ivr); return; }
          if (luaStatePtr) { emit({ ev: 'js_retry', n: tries, fails: injFails }); luaRunInject(); }
        }, 6000);
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
