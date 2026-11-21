'use strict';
/*
 * bss full dump v3: T+15s, write the ENTIRE hidden tail
 * (RVA 0xdf1000 .. 0x24fdeb0) to files/bss_code.bin chunk by chunk.
 * Feasibility proven: all pages readable, zero-page gaps, decrypt-once.
 * File IO runs in setTimeout (never inside Interceptor) per v14 lesson.
 */
var DIR = '/data/user/0/com.ihuman.pinyin/files/';
var START_RVA = 0xdf1000;
var END_RVA = 0x24fdeb0;
var CHUNK = 0x180000;   // 1.5MB per write
var DELAY_MS = 15000;

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

function writeChunk(path, bytes, len, append) {
  if (!ok) return false;
  var fp = fns.fopen(Memory.allocUtf8String(path), Memory.allocUtf8String(append ? 'ab' : 'wb'));
  if (fp.isNull()) return false;
  var buf = Memory.alloc(len);
  buf.writeByteArray(bytes);
  fns.fwrite(buf, 1, len, fp);
  fns.fclose(fp);
  return true;
}

function run() {
  var m = null;
  try {
    Process.enumerateModules().forEach(function (x) {
      if (!m && /libcocos2dlua/.test(x.name)) m = x;
    });
  } catch (e) {}
  if (!m) { send({ ev: 'bss3_no_module' }); return; }
  var start = m.base.add(START_RVA);
  var total = END_RVA - START_RVA;
  var path = DIR + 'bss_code.bin';
  var first = true;
  var off = 0;
  var errN = 0;
  while (off < total) {
    var len = Math.min(CHUNK, total - off);
    try {
      var bytes = new Uint8Array(start.add(off).readByteArray(len));
      if (!writeChunk(path, bytes, len, !first)) {
        send({ ev: 'bss3_write_err', off: off });
        return;
      }
      first = false;
      off += len;
    } catch (e) {
      errN++;
      // fill unreadable chunk with zeros to keep offsets consistent
      try {
        var zb = new Uint8Array(len);
        if (!writeChunk(path, zb, len, !first)) { send({ ev: 'bss3_write_err2', off: off }); return; }
        first = false;
        off += len;
      } catch (e2) {
        send({ ev: 'bss3_chunk_err', off: off, e: String(e2) });
        return;
      }
    }
  }
  send({ ev: 'bss3_done', bytes: off, errN: errN, base: m.base.toString() });
}

var tries = 0;
var poll = setInterval(function () {
  tries++;
  var m = null;
  try {
    Process.enumerateModules().forEach(function (x) {
      if (!m && /libcocos2dlua/.test(x.name)) m = x;
    });
  } catch (e) {}
  if (m && ok) {
    clearInterval(poll);
    setTimeout(function () {
      try { run(); } catch (e) { send({ ev: 'bss3_exc', e: String(e) }); }
    }, DELAY_MS);
  } else if (tries > 300) {
    clearInterval(poll);
    send({ ev: 'bss3_timeout', ok: ok });
  }
}, 100);

send({ ev: 'bss3_ready', delay_ms: DELAY_MS });
