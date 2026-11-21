'use strict';
/*
 * bss_dump v2 (feasibility): at T+45s walk the ENTIRE hidden tail
 * (RVA 0xdf1000 .. 0x24fdeb0, 38.8MB) in 64KB chunks, per-chunk:
 *   - readable? (PROT_NONE pages -> readByteArray throws)  => fault-on-demand
 *   - nonzero ratio (decrypted code vs zero/cipher)
 *   - first 8 bytes hex (cipher vs code hint)
 * Emits a compact per-chunk map (readable, nz%, head). No file IO in loop.
 *
 * Outcome interpretation:
 *   most chunks readable & nz>0   -> decrypt-once model; ELF rebuild viable
 *   many unreadable near end      -> fault-on-demand w/ PROT_NONE; rebuild hard
 */
var START_RVA = 0xdf1000;
var END_RVA = 0x24fdeb0;
var CHUNK = 0x10000;
var DELAY_MS = 15000;

function run() {
  var m = null;
  try {
    Process.enumerateModules().forEach(function (x) {
      if (!m && /libcocos2dlua/.test(x.name)) m = x;
    });
  } catch (e) {}
  if (!m) { send({ ev: 'bss2_no_module' }); return; }

  var total = END_RVA - START_RVA;
  var n = Math.ceil(total / CHUNK);
  var readable = 0, unreadable = 0, zerochunks = 0;
  var map = [];
  for (var i = 0; i < n; i++) {
    var rva = START_RVA + i * CHUNK;
    var len = Math.min(CHUNK, total - i * CHUNK);
    var row = { i: i, rva: '0x' + rva.toString(16) };
    try {
      var b = new Uint8Array(m.base.add(rva).readByteArray(Math.min(len, 4096)));
      readable++;
      var nz = 0;
      for (var j = 0; j < b.length; j++) if (b[j] !== 0) nz++;
      var pct = Math.round(nz * 100 / b.length);
      if (nz === 0) zerochunks++;
      row.r = 1; row.nz = pct;
      var h = '';
      for (var k = 0; k < 8; k++) h += ('0' + b[k].toString(16)).slice(-2);
      row.h = h;
    } catch (e) {
      unreadable++;
      row.r = 0;
    }
    map.push(row);
  }
  send({ ev: 'bss2_done', n: n, readable: readable, unreadable: unreadable,
         zerochunks: zerochunks, base: m.base.toString() });
  for (var off = 0; off < map.length; off += 40) {
    send({ ev: 'bss2_map', seg: off / 40, rows: map.slice(off, off + 40) });
  }
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
  if (m) {
    clearInterval(poll);
    setTimeout(function () {
      try { run(); } catch (e) { send({ ev: 'bss2_exc', e: String(e) }); }
    }, DELAY_MS);
  } else if (tries > 300) {
    clearInterval(poll);
    send({ ev: 'bss2_timeout' });
  }
}, 100);

send({ ev: 'bss2_ready', delay_ms: DELAY_MS });
