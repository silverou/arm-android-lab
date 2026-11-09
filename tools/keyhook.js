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
  'local ids = {{"battle_01","95ab5da08290ae9e28db213f0d1c6a92"},{"battle_02","bac84a649a584147a79912bcbbc5b531"},{"battle_03","4a6af575f88b6ae96263fbcb9538fbd5"},{"battle_04","06ed17150f5fb0ac06f298dfbe5136e2"},{"book_S1E01","8dfb6dd51de0a58f6e0bb372fbd14ea7"},{"book_S1E06","a6f902e811a7cae9303cd6b62140d9ea"},{"book_S1E11","8fc320b88bed788a771c5ba2a8fbc166"},{"book_S1E17","07d31cd63b0b4dcde8a11c4546403ebb"},{"book_S1E22","77cb02e747a54adfc2c30231111bd214"},{"book_S1E28","7edec04985779bf2915c3709f011bb00"},{"childlink_v2","10ffa58d61da2294edbbcced1f51c68d"},{"childlink_v2_math_q_6666","3f3e93f2fc69396a5b06cff879c5ece5"},{"childlink_v2_pinyin_q_0178","58ed1c0bb1ce43d6fb6a6265afd5e444"},{"childlink_v2_pinyin_q_0549","5baa4f72eba02e05033ef479659d5ffa"},{"childlink_v2_shizi_q_5867","6e54567f44dc8e5b66979ce514f730ea"},{"childlink_v2_shizi_q_6287","aa01d68635ee0b2b88c6f9483f6b853e"},{"difficult_game_1","1638005fcdd9cc65231b5a7dbc733819"},{"difficult_game_6","0af063a72a2653d3fe0bccbeedceb1f6"},{"dinosaur_10","351e195a804e038347102088b967a673"},{"dinosaur_21","87f585e3409a6a624917ab3702873f5a"},{"dinosaur_28","579f019be3cebc30a0a6fc4d5fc087e2"},{"dinosaur_99","808c435fb2ec9f7342e799f3d155ba93"},{"exercise_01","378d0d67576d92a21409dd53af1f2ecf"},{"exercise_02","441bf0c32fb273f61efe52dffe4fd695"},{"exercise_03","1822352798bccbd651437a7eac5559c1"},{"exp_class_write","2805ec304509e6e4e619f17beb7cf71c"},{"linkagegames_balloon","454f5c7b3569a4beba86709b1eb6673a"},{"linkagegames_common","552bb4d21fb543b4d79be29676f273d4"},{"linkagegames_gift","da2075d664042fe1d17ca02bcf85a985"},{"linkagegames_snowfield","d14cf83fb04accd3237efc6a9b085037"},{"practice_01","b619b9bd835032601c6c3ca74b0449ce"},{"practice_02","925e6c196add37e07dda21aae9db8c4b"},{"practice_04","7218f566b726af8ff14bdea996e2ffba"},{"practice_06","e8028f96888a338f743f85a7b889cb61"},{"practice_08","523ae8db2721179e33aef21cc8391a50"},{"practice_10","6cdc4c5052bb011b36a2dc542e3d43fc"},{"say_template_1","45c7fcc914bc25fafc3f0d4649f49d06"},{"say_template_2","5a03f972aa580c1f02337a46c4d8cfae"},{"say_template_3","5e9072bb563d5b4df0c5aa60523c5dc7"},{"shizi_book","717348862d528b7bad31214d3858d931"},{"shizi_radical","37d795f079ea7ba7582000d058445fcc"},{"shizi_words","774fdae5e6973ebdfb739fa572e14b37"},{"song_PY001","efbcfd2192d0dccfb02d33626ec8d0db"},{"song_PY013","810a1327e506b1333b9b0aaf7fb848e5"},{"song_PY025","2d6423db4d176813a03f20eb006252be"},{"song_PY038","00fd27cc0f4e9adf127bff81e73630d3"},{"song_PY050","6c3906dbdc0bbefa35beaf2659b5110e"},{"song_PY063","4ffd53a8e1d285e2ecb42ff6546a4e6c"},{"spell_template_1","78a8ae84db84e20d82aa94dd863162b8"},{"spell_template_2","7499a9467a76196ea281449b6f02a642"},{"spell_template_3","0b1ed906d0f36ace280ac722d58cf235"},{"template1","2493b0c6f01e56add2d8526f18ca2606"},{"template2","1c716582a60fde601490e2532b6d1140"},{"tone_roller_coaster_1","fc18bee171f2e037bc8f2a5e09ace47c"},{"tone_roller_coaster_2","5cab24a6f8ff2bf652fdccbc74ef8ab7"},{"ui_o_explain","7e279b835a0c99e360c64f632047af21"},{"ui_v_ve_explain","c7e25890808adf45b13f208736409e39"},{"ui_video","9607519d152ff3e82624479a8651cd98"},{"ui_vn_van_explain","fbbd47e0c8fae65299e9ed0ca28dbbc5"},{"write_templet_02","9864117e3f0a09e3f5f7f77dfa9188a7"},{"write_templet_03","bcacf1669a1f85577e53057b070964cc"},{"write_templet_04","bb64b86f717ab8156420bbbfb6f7956f"}}',
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

var LUA_CODE2 = [
  'local out = {}',
  'local function P(s) out[#out+1] = s end',
  'local g = {}',
  'for k,v in pairs(_G) do g[k] = v end',
  'local ids = {{"PY002","a99fde54ff5f404d04e04be2f59b0d30"},{"PY003","6628438921bdfd178c4aec9700e143a5"},{"PY004","08bb33bbe72cee33c634d662d6aaa161"},{"PY005","57e738d3213c0d8e94954b1c2debe827"},{"PY006","37f7b4acf9d7f2ccf70c48cb03d6d545"},{"PY007","50b7ebecad1da18eab05f909453e7d8f"},{"PY008","04af473272843bde28ab6a0a20ada742"},{"PY009","c891625d6979b5f806fc3fa8fe0ae1af"},{"PY010","86ec8622798207af5819be2461882b3c"},{"PY011","f6e5e61acaed8f5af9730182b8983649"},{"PY012","bb52b9e50ab93578dbbe974f5fce586f"},{"LT001","dee41e662081bbb81ad56a524cb3cb43"},{"PY013","ac91ec10c447cfcf998ec108d7fcc428"},{"PY025","0590e61b837caff969886251269d7504"},{"PY038","19dcd89cda07e9462b23da2bb0728413"},{"PY050","f27457dd46e9dcfa2dcd83c3150c8a71"},{"PY063","984ac54d16a747b3ee6286ebeb67ad68"},{"battle_01","95ab5da08290ae9e28db213f0d1c6a92"},{"battle_02","bac84a649a584147a79912bcbbc5b531"},{"battle_03","4a6af575f88b6ae96263fbcb9538fbd5"},{"battle_04","06ed17150f5fb0ac06f298dfbe5136e2"},{"book_S1E01","8dfb6dd51de0a58f6e0bb372fbd14ea7"},{"book_S1E06","a6f902e811a7cae9303cd6b62140d9ea"},{"book_S1E11","8fc320b88bed788a771c5ba2a8fbc166"},{"book_S1E17","07d31cd63b0b4dcde8a11c4546403ebb"},{"book_S1E22","77cb02e747a54adfc2c30231111bd214"},{"book_S1E28","7edec04985779bf2915c3709f011bb00"},{"childlink_v2_math_q_6666","3f3e93f2fc69396a5b06cff879c5ece5"},{"childlink_v2_pinyin_q_0178","58ed1c0bb1ce43d6fb6a6265afd5e444"},{"childlink_v2_pinyin_q_0549","5baa4f72eba02e05033ef479659d5ffa"},{"childlink_v2_shizi_q_5867","6e54567f44dc8e5b66979ce514f730ea"},{"childlink_v2_shizi_q_6287","aa01d68635ee0b2b88c6f9483f6b853e"},{"difficult_game_1","1638005fcdd9cc65231b5a7dbc733819"},{"difficult_game_6","0af063a72a2653d3fe0bccbeedceb1f6"},{"dinosaur_10","351e195a804e038347102088b967a673"},{"dinosaur_21","87f585e3409a6a624917ab3702873f5a"},{"dinosaur_28","579f019be3cebc30a0a6fc4d5fc087e2"},{"dinosaur_99","808c435fb2ec9f7342e799f3d155ba93"},{"exercise_01","378d0d67576d92a21409dd53af1f2ecf"},{"exercise_02","441bf0c32fb273f61efe52dffe4fd695"},{"exercise_03","1822352798bccbd651437a7eac5559c1"},{"exp_class_write","2805ec304509e6e4e619f17beb7cf71c"},{"linkagegames_balloon","454f5c7b3569a4beba86709b1eb6673a"},{"linkagegames_common","552bb4d21fb543b4d79be29676f273d4"},{"linkagegames_gift","da2075d664042fe1d17ca02bcf85a985"},{"linkagegames_snowfield","d14cf83fb04accd3237efc6a9b085037"},{"practice_01","b619b9bd835032601c6c3ca74b0449ce"},{"practice_04","7218f566b726af8ff14bdea996e2ffba"},{"practice_06","e8028f96888a338f743f85a7b889cb61"},{"practice_08","523ae8db2721179e33aef21cc8391a50"},{"practice_10","6cdc4c5052bb011b36a2dc542e3d43fc"},{"say_template_1","45c7fcc914bc25fafc3f0d4649f49d06"},{"say_template_2","5a03f972aa580c1f02337a46c4d8cfae"},{"say_template_3","5e9072bb563d5b4df0c5aa60523c5dc7"},{"shizi_book","717348862d528b7bad31214d3858d931"},{"shizi_radical","37d795f079ea7ba7582000d058445fcc"},{"shizi_words","774fdae5e6973ebdfb739fa572e14b37"},{"song_PY013","810a1327e506b1333b9b0aaf7fb848e5"},{"song_PY025","2d6423db4d176813a03f20eb006252be"},{"song_PY038","00fd27cc0f4e9adf127bff81e73630d3"},{"song_PY050","6c3906dbdc0bbefa35beaf2659b5110e"},{"song_PY063","4ffd53a8e1d285e2ecb42ff6546a4e6c"},{"spell_template_1","78a8ae84db84e20d82aa94dd863162b8"},{"spell_template_2","7499a9467a76196ea281449b6f02a642"},{"spell_template_3","0b1ed906d0f36ace280ac722d58cf235"},{"template1","2493b0c6f01e56add2d8526f18ca2606"},{"template2","1c716582a60fde601490e2532b6d1140"},{"tone_roller_coaster_1","fc18bee171f2e037bc8f2a5e09ace47c"},{"tone_roller_coaster_2","5cab24a6f8ff2bf652fdccbc74ef8ab7"},{"ui_o_explain","7e279b835a0c99e360c64f632047af21"},{"ui_v_ve_explain","c7e25890808adf45b13f208736409e39"},{"ui_video","9607519d152ff3e82624479a8651cd98"},{"ui_vn_van_explain","fbbd47e0c8fae65299e9ed0ca28dbbc5"},{"write_templet_02","9864117e3f0a09e3f5f7f77dfa9188a7"},{"write_templet_03","bcacf1669a1f85577e53057b070964cc"},{"write_templet_04","bb64b86f717ab8156420bbbfb6f7956f"}}',
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
    emit({ ev: 'inj_exc', e: String(e) });
  }
}

var harvestScheduled = false;
function luaRunInject2() {
  if (luaInj >= 2 || !luaStatePtr) return;
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
        } else {
          emit({ ev: 'inj2_nostr', rc: rc });
        }
      } catch (e2) { emit({ ev: 'inj2_read_err', e: String(e2) }); }
    }
  } catch (e) {
    emit({ ev: 'inj2_exc', e: String(e) });
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
