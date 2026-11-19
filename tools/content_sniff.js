'use strict';
/*
 * Content sniffer v6: fopen(FILE*) -> fread force-report for *.ihi only.
 *
 * Evidence:
 *   - bridge FOPEN sees main.ihi; exported open/openat never do (libc-internal)
 *   - read/pread content-match hits=0 (fread uses libc-internal __read)
 * This probe attaches ONLY fopen/fopen64/fread/fclose, and only emits for
 * paths ending .ihi. Minimal surface, no global read hooks.
 */
var seen = {};
var hits = 0;
var streamMap = {};   // FILE* -> {path, reads, bytes}
var openN = 0, readN = 0, closeN = 0;

function hex(b) {
  var s = '';
  for (var i = 0; i < b.length; i++) s += ('0' + b[i].toString(16)).slice(-2);
  return s;
}

function classify(head) {
  if (head.length >= 8 && head.slice(0, 8) === '7072696e74') return 'plain';
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

['fopen', 'fopen64'].forEach(function (sym) {
  var p = null;
  try { p = Module.getGlobalExportByName(sym); } catch (e) {}
  if (!p) { send({ ev: 'sniff_miss', sym: sym }); return; }
  Interceptor.attach(p, {
    onEnter: function (a) {
      try { this.path = a[0].readCString(); } catch (e) { this.path = ''; }
    },
    onLeave: function (ret) {
      if (!this.path || !/\.ihi$/.test(this.path)) return;
      if (ret.isNull()) {
        send({ ev: 'sniff_fopen', via: sym, p: this.path.slice(0, 140), ok: 0 });
        return;
      }
      var k = ret.toString();
      streamMap[k] = { path: this.path, reads: 0, bytes: 0 };
      openN++;
      send({ ev: 'sniff_fopen', via: sym, p: this.path.slice(0, 140), ok: 1, fp: k });
    }
  });
});

var filenoF = null;
try { filenoF = new NativeFunction(Module.getGlobalExportByName('fileno'), 'int', ['pointer']); } catch (e) {}

try {
  var fpr = Module.getGlobalExportByName('fread');
  Interceptor.attach(fpr, {
    onEnter: function (a) {
      this.buf = a[0];
      this.sz = a[1].toInt32();
      this.fp = a[3].toString();
      this.meta = streamMap[this.fp] || null;
    },
    onLeave: function (ret) {
      if (!this.meta) return;
      var items = ret.toInt32();
      if (items <= 0) return;
      var got = items * (this.sz || 1);
      this.meta.reads++;
      this.meta.bytes += got;
      if (hits > 40) return;
      try {
        var n = Math.min(got, 32);
        var b = new Uint8Array(this.buf.readByteArray(n));
        var h = hex(b);
        var key = h.slice(0, 16);
        if (seen[key]) return;
        seen[key] = 1;
        hits++;
        readN++;
        var bt = [];
        try {
          var frames = Thread.backtrace(this.context, Backtracer.ACCURATE);
          for (var i = 0; i < Math.min(frames.length, 8); i++) bt.push(describe(frames[i]));
        } catch (e) {}
        send({ ev: 'sniff', kind: classify(h) || 'other', via: 'fread',
               got: got, head: h, p: this.meta.path.slice(0, 140),
               reads: this.meta.reads, bt: bt, t: Date.now() });
      } catch (e) {}
    }
  });
} catch (e) { send({ ev: 'sniff_miss', sym: 'fread' }); }

try {
  var fcr = Module.getGlobalExportByName('fclose');
  Interceptor.attach(fcr, {
    onEnter: function (a) {
      var k = a[0].toString();
      var meta = streamMap[k];
      if (!meta) return;
      delete streamMap[k];
      closeN++;
      send({ ev: 'sniff_fclose', p: meta.path.slice(0, 140),
             reads: meta.reads, bytes: meta.bytes });
    }
  });
} catch (e) { send({ ev: 'sniff_miss', sym: 'fclose' }); }

send({ ev: 'sniff_armed4' });

setInterval(function () {
  send({ ev: 'sniff_stat', hits: hits, opens: openN, reads: readN,
         closes: closeN, live: Object.keys(streamMap).length });
}, 8000);
