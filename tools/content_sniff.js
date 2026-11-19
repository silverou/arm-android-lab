'use strict';
/*
 * Content sniffer v5: locate WHO consumes .ihi bytes after open.
 *
 * v3/v4 lesson: engine open()s main.ihi but plain read/pread64 content-match
 * can miss (libc-internal __read, offset reads, fread path). This version:
 *   1) open/openat ONLY to map fd -> path for *.ihi (minimal, path-only)
 *   2) read-family + fread + mmap: if fd is a known .ihi fd -> always report
 *      first bytes; else content-classify (plain/szaq/ihi42/json)
 * On match: head hex + caller stack (module+RVA).
 */
var seen = {};
var hits = 0;
var armed = [];
var ihiFd = {};   // fd -> path
var openN = 0;

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

function report(got, buf, via, force) {
  if (hits > 50) return;
  if (!buf || got < 1) return;
  try {
    var n = Math.min(got, 32);
    var b = new Uint8Array(buf.readByteArray(n));
    var h = hex(b);
    if (!force) {
      var b0 = b[0];
      if (b0 !== 0x70 && b0 !== 0x1b && b0 !== 0x34 && b0 !== 0x7b) return;
      var k = classify(h);
      if (!k) return;
      var key = k + '|' + h.slice(0, 16) + '|' + via;
      if (seen[key]) return;
      seen[key] = 1;
    } else {
      var fkey = 'ihi|' + via + '|' + h.slice(0, 16);
      if (seen[fkey]) return;
      seen[fkey] = 1;
    }
    hits++;
    var bt = [];
    try {
      var frames = Thread.backtrace(this.context, Backtracer.ACCURATE);
      for (var i = 0; i < Math.min(frames.length, 8); i++) bt.push(describe(frames[i]));
    } catch (e) {}
    var kind = classify(h) || 'other';
    send({ ev: 'sniff', kind: kind, via: via, got: got, head: h, force: !!force, bt: bt, t: Date.now() });
  } catch (e) {}
}

// --- fd map for .ihi only (path string check, no other side effects)
function trackOpen(sym) {
  var p = null;
  try { p = Module.getGlobalExportByName(sym); } catch (e) {}
  if (!p) return;
  var pathIdx = (sym.indexOf('at') >= 0) ? 1 : 0;
  Interceptor.attach(p, {
    onEnter: function (a) {
      try { this.path = a[pathIdx].readCString(); } catch (e) { this.path = ''; }
    },
    onLeave: function (ret) {
      if (!this.path || !/\.ihi$/.test(this.path)) return;
      var fd = ret.toInt32();
      if (fd >= 0) {
        ihiFd[fd] = this.path;
        openN++;
        if (openN <= 20) send({ ev: 'sniff_open', fd: fd, p: this.path.slice(0, 140) });
      }
    }
  });
  armed.push('open:' + sym);
}
['open', 'open64', 'openat', 'openat64'].forEach(trackOpen);

// close: drop fd
try {
  var closeP = Module.getGlobalExportByName('close');
  Interceptor.attach(closeP, {
    onEnter: function (a) {
      var fd = a[0].toInt32();
      if (ihiFd[fd]) delete ihiFd[fd];
    }
  });
} catch (e) {}

function attachRead(sym) {
  var p = null;
  try { p = Module.getGlobalExportByName(sym); } catch (e) {}
  if (!p) { send({ ev: 'sniff_miss', sym: sym }); return; }
  try {
    Interceptor.attach(p, {
      onEnter: function (a) {
        this.fd = a[0].toInt32();
        this.buf = a[1];
      },
      onLeave: function (ret) {
        var force = !!ihiFd[this.fd];
        if (!force && openN === 0) {
          // still content-classify in case fd map missed
        }
        report.call(this, ret.toInt32(), this.buf, sym, force);
      }
    });
    armed.push(sym);
  } catch (e) {
    send({ ev: 'sniff_hook_err', sym: sym, e: String(e) });
  }
}
['read', 'pread', 'pread64', 'read64', '__read'].forEach(attachRead);

// fread(ptr, size, nmemb, stream): need fileno(stream)
var filenoF = null;
try { filenoF = new NativeFunction(Module.getGlobalExportByName('fileno'), 'int', ['pointer']); } catch (e) {}
try {
  var fpr = Module.getGlobalExportByName('fread');
  Interceptor.attach(fpr, {
    onEnter: function (a) {
      this.buf = a[0];
      this.sz = a[1].toInt32();
      this.fd = -1;
      try { if (filenoF) this.fd = filenoF(a[3]); } catch (e) {}
    },
    onLeave: function (ret) {
      var items = ret.toInt32();
      var got = items > 0 ? items * (this.sz || 1) : 0;
      var force = !!ihiFd[this.fd];
      report.call(this, got, this.buf, 'fread', force);
    }
  });
  armed.push('fread');
} catch (e) { send({ ev: 'sniff_miss', sym: 'fread' }); }

// mmap: if fd is .ihi, classify mapped head
['mmap', 'mmap64'].forEach(function (sym) {
  var p = null;
  try { p = Module.getGlobalExportByName(sym); } catch (e) {}
  if (!p) return;
  try {
    Interceptor.attach(p, {
      onEnter: function (a) {
        this.len = a[1].toInt32();
        this.fd = a[4].toInt32();
      },
      onLeave: function (ret) {
        try {
          if (ret.toInt32() === -1) return;
          var force = !!ihiFd[this.fd];
          if (!force) return;  // only report .ihi mappings
          report.call(this, Math.min(this.len || 0, 64), ret, sym, true);
        } catch (e) {}
      }
    });
    armed.push(sym);
  } catch (e) {}
});

// AAsset_read
try {
  var m = null;
  Process.enumerateModules().forEach(function (x) {
    if (!m && /libandroid\.so/.test(x.name)) m = x;
  });
  if (m) {
    var ar = m.findExportByName('AAsset_read') || m.findExportByName('AAssetRead');
    if (ar && !ar.isNull()) {
      Interceptor.attach(ar, {
        onEnter: function (a) { this.buf = a[1]; },
        onLeave: function (ret) { report.call(this, ret.toInt32(), this.buf, 'AAsset_read', false); }
      });
      armed.push('AAsset_read');
    }
  }
} catch (e) {}

send({ ev: 'sniff_armed3', lanes: armed });

setInterval(function () {
  send({ ev: 'sniff_stat', hits: hits, keys: Object.keys(seen).length,
         opens: openN, fds: Object.keys(ihiFd).length, lanes: armed.length });
}, 8000);
