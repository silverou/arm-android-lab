'use strict';
/*
 * Dump the hidden runtime-code region of libcocos2dlua.
 *
 * Disk ELF: LOAD1 filesz=0xdf0200 memsz=0x24fdeb0 (r-x). The tail
 * (0xdf1000..0x250e000, page-rounded) is BSS zero pages mapped r-x with
 * NO file path (why previous so_dump missed it) — the packer decrypts the
 * real .text (including the static Lua copy, ihi loader, and the
 * fopen caller at RVA 0x1492434) into it at runtime.
 *
 * Output: /data/user/0/com.ihuman.pinyin/files/bss_code.bin (chunked appends)
 */
var DIR = '/data/user/0/com.ihuman.pinyin/files/';
var START_RVA = 0xdf1000;
var END_RVA = 0x250e000;
var CHUNK = 0x180000;  // 1.5MB per read

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
  if (!m) { send({ ev: 'bss_no_module' }); return; }
  var start = m.base.add(START_RVA);
  var total = END_RVA - START_RVA;
  // sanity: first bytes should be code (packer-decrypted) not zeros
  try {
    var head = new Uint8Array(start.readByteArray(16));
    send({ ev: 'bss_head', head: Array.prototype.map.call(head, function (b) {
      return ('0' + b.toString(16)).slice(-2); }).join(''), base: m.base.toString() });
  } catch (e) { send({ ev: 'bss_read_err', e: String(e) }); return; }

  var path = DIR + 'bss_code.bin';
  var first = true;
  var off = 0;
  while (off < total) {
    var len = Math.min(CHUNK, total - off);
    try {
      var bytes = new Uint8Array(start.add(off).readByteArray(len));
      if (!writeChunk(path, bytes, len, !first ? true : false)) {
        send({ ev: 'bss_write_err', off: off });
        return;
      }
      first = false;
      off += len;
    } catch (e) {
      send({ ev: 'bss_chunk_err', off: off, e: String(e) });
      return;
    }
  }
  // entropy hint: count nonzero bytes in first 64KB
  var probe = new Uint8Array(start.readByteArray(65536));
  var nz = 0;
  for (var i = 0; i < probe.length; i++) if (probe[i] !== 0) nz++;
  send({ ev: 'bss_done', bytes: off, nonzero_first64k: nz, base: m.base.toString() });
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
    // wait for the packer to finish decrypting (shell init ~2-6s)
    setTimeout(function () {
      try { run(); } catch (e) { send({ ev: 'bss_exc', e: String(e) }); }
    }, 6000);
  } else if (tries > 200) {
    clearInterval(poll);
    send({ ev: 'bss_timeout', ok: ok });
  }
}, 100);
