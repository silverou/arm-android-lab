'use strict';
/*
 * File-level Lua chunk extractor v3: hook the real decrypt gateway.
 *
 * Symbols found in libcocos2dlua (mangled):
 *   cocos2d::FileUtils::decryptDataIfNeed(cocos2d::Data&, std::string const&)
 *   cocos2d::extra::AESHelper::AES_ecb_auto_decrypt_lua / SHA256_decrypt_lua
 * xxtea_* are never called — the fork decrypts with AES. decryptDataIfNeed
 * sits on every encrypted-file read: onLeave its Data holds the PLAINTEXT.
 *
 * Data layout (cocos2d-x): [0]=unsigned char* bytes, [8]=ssize_t size.
 * libc++ std::string layout: short: [0]=size<<1, data@1; long: [8]=size, [16]=ptr.
 *
 * Output: /data/user/0/com.ihuman.pinyin/files/filelua_<n>.bin
 *         + filelua_map.txt  (n -> path)
 */
var DIR = '/data/user/0/com.ihuman.pinyin/files/';
var fns = {};
['fopen', 'fwrite', 'fclose'].forEach(function (n) {
  var p = null;
  try { p = Module.getGlobalExportByName(n); } catch (e) {}
  if (p) fns[n] = new NativeFunction(p,
    n === 'fwrite' ? 'size_t' : (n === 'fclose' ? 'int' : 'pointer'),
    n === 'fwrite' ? ['pointer', 'size_t', 'size_t', 'pointer'] :
    n === 'fclose' ? ['pointer'] : ['pointer', 'pointer']);
});
var ok = !!(fns.fopen && fns.fwrite && fns.fclose);
send({ ev: 'fl_ready', ok: ok });

function writeFile(path, bytes, len, append) {
  if (!ok) return false;
  var fp = fns.fopen(Memory.allocUtf8String(path), Memory.allocUtf8String(append ? 'ab' : 'wb'));
  if (fp.isNull()) return false;
  var buf = Memory.alloc(len);
  buf.writeByteArray(bytes);
  fns.fwrite(buf, 1, len, fp);
  fns.fclose(fp);
  return true;
}

function readStdString(p) {
  try {
    var flag = p.readU8();
    if (flag & 1) {
      // long: [0..8)=cap, [8]=size, [16]=ptr
      var size = p.add(8).readPointer().toInt32();
      var ptr = p.add(16).readPointer();
      if (size > 0 && size < 4096 && !ptr.isNull()) return ptr.readUtf8String(size);
    } else {
      var sl = flag >> 1;
      if (sl > 0 && sl < 24) return p.add(1).readUtf8String(sl);
    }
  } catch (e) {}
  return '';
}

var n = 0, dup = 0, skip = 0;
var seen = {};
var mapLines = [];
var hookAddr = null;

function flushMap() {
  if (!mapLines.length) return;
  writeFile(DIR + 'filelua_map.txt', mapLines.join('\n') + '\n', 0, true);
  mapLines = [];
}

function onDecrypt(a, name) {
  try {
    var dataRef = a[1];
    var path = readStdString(a[2]);
    if (name) send({ ev: 'fl_call', fn: name, p: path.slice(0, 140), t: Date.now() });
    this.dataRef = dataRef;
    this.path = path;
  } catch (e) {}
}

function afterDecrypt() {
  try {
    var d = this.dataRef;
    if (!d || d.isNull()) return;
    var bytes = d.readPointer();
    var size = d.add(8).readPointer().toInt32();
    if (bytes.isNull() || size < 32 || size > 32 * 1024 * 1024) { skip++; return; }
    // snapshot BEFORE returning to caller would be ideal, but onLeave runs
    // after decrypt — this is the plaintext.
    var win = new Uint8Array(bytes.readByteArray(size));
    var key = '';
    for (var i = 0; i < Math.min(size, 32); i++) key += ('0' + win[i].toString(16)).slice(-2);
    if (seen[key]) { dup++; return; }
    seen[key] = 1;
    n++;
    var fn = 'filelua_' + n + '.bin';
    if (writeFile(DIR + fn, win, size)) {
      mapLines.push(fn + '\t' + (this.path || ''));
      flushMap();
      if (n <= 8 || n % 50 === 0) {
        send({ ev: 'fl_hit', n: n, size: size, head: key.slice(0, 16), p: (this.path || '').slice(0, 120) });
      }
    }
  } catch (e) {
    send({ ev: 'fl_err', e: String(e) });
  }
}

var mod = null;
function arm() {
  if (mod) return;
  try {
    Process.enumerateModules().forEach(function (m) {
      if (!mod && /libcocos2dlua/.test(m.name)) mod = m;
    });
  } catch (e) {}
  if (!mod) return;
  var syms;
  try { syms = mod.enumerateSymbols(); } catch (e) { return; }
  var hooked = 0;
  syms.forEach(function (s) {
    if (s.type !== 'function') return;
    if (s.name.indexOf('decryptDataIfNeed') >= 0) {
      Interceptor.attach(s.address, {
        onEnter: function (a) { onDecrypt.call(this, a, s.name.slice(0, 70)); },
        onLeave: function () { afterDecrypt.call(this); }
      });
      hookAddr = s.address;
      hooked++;
      send({ ev: 'fl_hooked', sym: s.name, at: s.address.toString() });
    }
    // also watch the AES lua helpers to confirm algorithm
    if (s.name.indexOf('AES_ecb_auto_decrypt_lua') >= 0 ||
        s.name.indexOf('SHA256_decrypt_lua') >= 0) {
      Interceptor.attach(s.address, {
        onEnter: function (a) { send({ ev: 'fl_aes', fn: s.name.slice(0, 70), t: Date.now() }); }
      });
      send({ ev: 'fl_hooked', sym: s.name, at: s.address.toString() });
      hooked++;
    }
  });
  if (!hooked) send({ ev: 'fl_no_hook' });
}

var tries = 0;
var poll = setInterval(function () {
  tries++;
  arm();
  if (hookAddr || tries > 600) clearInterval(poll);
}, 20);

setInterval(function () {
  send({ ev: 'fl_stat', files: n, dup: dup, skip: skip, hooked: !!hookAddr });
}, 10000);
