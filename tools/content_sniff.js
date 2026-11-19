'use strict';
/*
 * Content sniffer v3: minimal-interference reader locator.
 *
 * Proven: clean-run engine opens our plain main.ihi (fd211) — the gate is
 * AFTER the read. Previous multi-hook probe interfered with fopen (never
 * returned). This probe attaches ONLY read/pread64 (never touches fopen)
 * and matches on CONTENT:
 *   - our override plain text  ("print(\"OV...")
 *   - SZAQ bytecode magic      (1b 53 5a 41)
 *   - .ihi container magic     (ASCII "42a64166")
 * On match: send head hex + caller stack (module+RVA) -> identifies the
 * reader function for static analysis of the post-read gate.
 */
var seen = {};
var hits = 0;

function hex(b) {
  var s = '';
  for (var i = 0; i < b.length; i++) s += ('0' + b[i].toString(16)).slice(-2);
  return s;
}

function classify(head) {
  if (head.length >= 8 && head.slice(0, 8) === '7072696e74') return 'plain';   // "print"
  if (head.length >= 8 && head.slice(0, 8) === '1b535a41') return 'szaq';
  if (head.length >= 16 && head.slice(0, 16) === '3432613634313636') return 'ihi42';
  if (head.length >= 4 && head.slice(0, 4) === '7b0d0a20') return 'json';
  if (head.length >= 4 && head.slice(0, 4) === '7b226275') return 'json2';
  return null;
}

function describe(addr) {
  var s = addr.toString();
  try {
    var m = Process.findModuleByAddress(addr);
    if (m) s = m.name + '+0x' + addr.sub(m.base).toString(16);
  } catch (e) {}
  return s;
}

function onRet(ret, buf) {
  if (hits > 40) return;
  try {
    var got = ret.toInt32();
    if (got < 8) return;
    // fast path: single-byte prefilter to keep read-hook cost near zero
    var b0 = buf.readU8();
    if (b0 !== 0x70 && b0 !== 0x1b && b0 !== 0x34 && b0 !== 0x7b) return;
    var n = Math.min(got, 32);
    var b = new Uint8Array(buf.readByteArray(n));
    var h = hex(b);
    var kind = classify(h);
    if (!kind) return;
    var key = kind + '|' + h.slice(0, 16);
    if (seen[key]) return;
    seen[key] = 1;
    hits++;
    var bt = [];
    try {
      var frames = Thread.backtrace(this.context, Backtracer.ACCURATE);
      for (var i = 0; i < Math.min(frames.length, 8); i++) bt.push(describe(frames[i]));
    } catch (e) {}
    send({ ev: 'sniff', kind: kind, got: got, head: h, bt: bt, t: Date.now() });
  } catch (e) {}
}

['read', 'pread64'].forEach(function (sym) {
  var p = null;
  try { p = Module.getGlobalExportByName(sym); } catch (e) {}
  if (!p) { send({ ev: 'sniff_miss', sym: sym }); return; }
  Interceptor.attach(p, {
    onEnter: function (a) { this.buf = a[1]; },
    onLeave: function (ret) { onRet.call(this, ret, this.buf); }
  });
  send({ ev: 'sniff_armed', sym: sym });
});

setInterval(function () {
  send({ ev: 'sniff_stat', hits: hits, keys: Object.keys(seen).length });
}, 8000);
