'use strict';
/*
 * Probe A: capture the XXTEA key (and sign) used for Lua decryption.
 *
 * Key is passed from the Java layer into libcocos2dlua at runtime:
 *   LuaStack::setHongenKAndS(key, sign)   (called in ELF constructors)
 *   Crypto::decryptXXTEALua(const char*, int, const char* key, int)
 *   xxtea_decrypt(data, len, key, keyLen)
 * Constructor-time calls can be missed; the decrypt calls happen at every
 * script load and carry the key directly. Hook both.
 *
 * Writes /data/user/0/com.ihuman.pinyin/files/xxtea_key.txt
 */
var DIR = '/data/user/0/com.ihuman.pinyin/files/';
var fns = {};
['fopen', 'fwrite', 'fclose'].forEach(function (n) {
  var p = null;
  try { p = Module.getGlobalExportByName(n); } catch (e) {}
  if (p) fns[n] = new NativeFunction(p, 'pointer',
    n === 'fwrite' ? ['pointer', 'size_t', 'size_t', 'pointer'] :
    n === 'fclose' ? ['pointer'] : ['pointer', 'pointer']);
});
var ok = !!(fns.fopen && fns.fwrite && fns.fclose);

function writeFile(path, text) {
  if (!ok) return;
  var fp = fns.fopen(Memory.allocUtf8String(path), Memory.allocUtf8String('ab'));
  if (fp.isNull()) return;
  var enc = [];
  for (var i = 0; i < text.length; i++) enc.push(text.charCodeAt(i) & 0xff);
  var buf = Memory.alloc(enc.length || 1);
  if (enc.length) buf.writeByteArray(enc);
  fns.fwrite(buf, 1, enc.length, fp);
  fns.fclose(fp);
}

function hex(ptrVal, n) {
  try {
    var b = new Uint8Array(ptrVal.readByteArray(n));
    var s = '';
    for (var i = 0; i < b.length; i++) s += ('0' + b[i].toString(16)).slice(-2);
    return s;
  } catch (e) { return 'ERR:' + e; }
}

function capture(tag, keyPtr, keyLen) {
  var n = keyLen > 0 && keyLen <= 64 ? keyLen : 16;
  var h = hex(keyPtr, n);
  var line = tag + ' key=' + h + ' len=' + n + '\n';
  send({ ev: 'xxtea_key', tag: tag, hex: h, len: n });
  writeFile(DIR + 'xxtea_key.txt', line);
}

function hookSymbol(sym, handler) {
  try {
    Interceptor.attach(sym.address, {
      onEnter: function (a) {
        try { handler.call(this, a, sym.name); } catch (e) {}
      }
    });
    send({ ev: 'xxtea_hooked', sym: String(sym.name).slice(0, 90) });
    return true;
  } catch (e) { return false; }
}

var done = false;
function armOnModule(m) {
  if (done) return;
  done = true;
  var syms;
  try { syms = m.enumerateSymbols(); } catch (e) {
    send({ ev: 'xxtea_err', e: 'enumerateSymbols: ' + e });
    return;
  }
  var hooked = 0;
  for (var i = 0; i < syms.length; i++) {
    var s = syms[i];
    if (s.type !== 'function') continue;
    var nm = s.name || '';
    if (nm.indexOf('decryptXXTEALua') >= 0) {
      // (const char* data, int size, const char* key, int keySize)
      if (hookSymbol(s, function (a) {
        var keyLen = a[3].toInt32();
        capture('decryptXXTEALua', a[2], keyLen);
      })) hooked++;
    } else if (nm.toLowerCase().indexOf('xxtea') >= 0 &&
               nm.toLowerCase().indexOf('decrypt') >= 0 &&
               nm.indexOf('decryptXXTEALua') < 0) {
      // catch mangled _Z13xxtea_decryptPhjS_jPj (classic C API):
      // (const void* data, size_t len, const void* key, size_t keyLen)
      // Mangled forms can permute arg order; capture key-ish args defensively.
      if (hookSymbol(s, function (a) {
        try {
          var keyLen = a[3].toInt32();
          if (keyLen > 0 && keyLen <= 64) capture('xxtea_decrypt', a[2], keyLen);
        } catch (e) {}
        try {
          var kl2 = a[2].toInt32();
          if (kl2 > 7 && kl2 <= 64) capture('xxtea_decrypt.alt', a[3], kl2);
        } catch (e) {}
      })) hooked++;
    } else if (nm.indexOf('setXXTEAKeyAndSign') >= 0) {
      // LuaStack::setXXTEAKeyAndSign(const char* key, int keyLen, const char* sign, int signLen)
      if (hookSymbol(s, function (a) {
        try {
          var kl = a[2].toInt32();
          capture('setXXTEAKeyAndSign', a[1], kl);
        } catch (e) {}
        try {
          var sl = a[4].toInt32();
          capture('setXXTEAKeyAndSign.sign', a[3], sl);
        } catch (e) {}
      })) hooked++;
    } else if (nm.indexOf('setHongenKAndS') >= 0) {
      // (const char* key, const char* sign) or (this, key, sign)
      if (hookSymbol(s, function (a) {
        for (var k = 0; k < 3; k++) {
          try {
            var p = a[k];
            if (p.isNull()) continue;
            var b = new Uint8Array(p.readByteArray(32));
            var printable = true;
            for (var j = 0; j < b.length && j < 16; j++) {
              if (b[j] === 0) break;
              if (b[j] < 0x20 || b[j] > 0x7e) { printable = false; break; }
            }
            if (printable && b[0] !== 0) {
              capture('setHongenKAndS.arg' + k, p, 32);
            }
          } catch (e) {}
        }
      })) hooked++;
    }
  }
  send({ ev: 'xxtea_armed', hooked: hooked, count: syms.length });
}

function tryArm() {
  var m = null;
  try {
    Process.enumerateModules().forEach(function (x) {
      if (!m && /libcocos2dlua/.test(x.name)) m = x;
    });
  } catch (e) {}
  if (m) armOnModule(m);
}

// dlopen observer: arm right when the module lands (before any script load)
['android_dlopen_ext', 'dlopen', '__loader_dlopen', '__loader_android_dlopen_ext'].forEach(function (sym) {
  try {
    var p = Module.getGlobalExportByName(sym);
    Interceptor.attach(p, {
      onEnter: function (a) {
        try { this.pth = a[0].readCString(); } catch (e) { this.pth = ''; }
      },
      onLeave: function () {
        if (this.pth && /cocos2dlua/.test(this.pth)) tryArm();
      }
    });
  } catch (e) {}
});
tryArm();
var tries = 0;
var poll = setInterval(function () {
  tries++; tryArm();
  if (done && tries > 20) clearInterval(poll);
}, 300);
