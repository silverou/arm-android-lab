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
function hookKey() {
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
    for (var i = 0; i < mods.length; i++) {
      if (mods[i].name.indexOf('cocos') < 0) continue;
      sawCocos = true;
      try {
        var sy = mods[i].enumerateSymbols();
        for (var j = 0; j < sy.length; j++) {
          var nm = sy[j].name || '';
          if (/xxtea|hongen|sign|tea/i.test(nm) && hits.length < 80) hits.push(nm);
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
      if (mods[i].name.indexOf('cocos') < 0) continue;
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

// try now, then poll until libcocos2dlua.so is loaded (up to 180s)
var tries = 0;
var iv = setInterval(function () {
  tries++;
  var done = false;
  try { done = hookKey(); } catch (e) { emit({ ev: 'poll_err', e: String(e) }); }
  armCurl();
  scanExports();
  armXxtea();
  if (done) { clearInterval(iv); return; }
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
          setTimeout(function () { hookKey(); }, 50);
        }
      }
    });
    emit({ ev: 'dlwatch_ok', sym: sym });
  } catch (e) { emit({ ev: 'dlwatch_err', sym: sym, e: String(e) }); }
});

emit({ ev: 'keyhook_ready' });
