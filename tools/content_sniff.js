'use strict';
/*
 * Content sniffer v9: global-state fopen tracking + fstat size + fclose.
 *
 * v8: onEnter saw main.ihi twice, onLeave never fired (this-context broken
 * by multi-hook). opens=0, hits=0, immediate fstat after fopen, no content
 * read -> hypothesize size/magic gate BEFORE any fread.
 *
 * This version:
 *   - fopen/fopen64 via attach; global pending stack (not this)
 *   - leave counter proves whether onLeave runs at all
 *   - after ihi fopen, log fstat st_size for next few fstats
 *   - fclose of mapped FILE* logs whether any read happened
 *   - fread/read still content-classify (exact magic only)
 */
var seen = {};
var hits = 0;
var pending = [];          // paths waiting for fopen return
var fpMap = {};            // FILE* -> path
var fdMap = {};            // fd -> path
var readCount = {};        // path -> nreads
var leaveN = 0;
var enterIhi = 0;
var statWatch = 0;         // countdown of fstats to inspect after ihi open
var lastStatSize = null;
var lanes = [];
var errs = [];

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

function tryAttach(name, fn) {
  try { fn(); lanes.push(name); }
  catch (e) {
    errs.push(name + ':' + e);
    send({ ev: 'sniff_attach_err', name: name, e: String(e) });
  }
}

// --- fopen / fopen64
['fopen', 'fopen64'].forEach(function (sym) {
  tryAttach(sym, function () {
    var p = Module.getGlobalExportByName(sym);
    Interceptor.attach(p, {
      onEnter: function (a) {
        try { this.path = a[0].readCString(); } catch (e) { this.path = ''; }
        this.isIhi = !!(this.path && /\.ihi$/.test(this.path));
        if (this.isIhi) {
          enterIhi++;
          pending.push(this.path);
          send({ ev: 'sniff_fopen_ihi', via: sym, n: enterIhi, p: this.path.slice(0, 140) });
        }
      },
      onLeave: function (ret) {
        leaveN++;
        if (!this.isIhi) return;
        var path = pending.length ? pending.pop() : (this.path || '?');
        if (ret.isNull()) {
          send({ ev: 'sniff_fopen_ihi_leave', p: path.slice(0, 140), ok: 0, leaveN: leaveN });
          return;
        }
        var fp = ret.toString();
        fpMap[fp] = path;
        var fd = -1;
        try {
          var fileno = new NativeFunction(Module.getGlobalExportByName('fileno'), 'int', ['pointer']);
          fd = fileno(ret);
        } catch (e) {}
        if (fd >= 0) fdMap[fd] = path;
        statWatch = 6;
        send({ ev: 'sniff_fopen_ihi_leave', p: path.slice(0, 140), ok: 1,
               fp: fp, fd: fd, leaveN: leaveN });
      }
    });
  });
});

// --- fstat: after ihi open, report st_size (gate hypothesis)
tryAttach('fstat', function () {
  var p = Module.getGlobalExportByName('fstat');
  Interceptor.attach(p, {
    onEnter: function (a) {
      this.fd = a[0].toInt32();
      this.buf = a[1];
      this.watch = statWatch > 0;
      this.path = fdMap[this.fd] || null;
    },
    onLeave: function (ret) {
      var r = ret.toInt32();
      if (r !== 0) return;
      if (!this.watch && !this.path) return;
      try {
        // struct stat st_size at offset 48 on arm64 bionic (off_t at 48)
        // safer: use fstat64 layout — arm64 linux stat: st_size @ 48
        var size = this.buf.add(48).readS64().toString();
        var ino = this.buf.add(8).readU64().toString();
        if (this.path || this.watch) {
          if (statWatch > 0) statWatch--;
          send({ ev: 'sniff_fstat', fd: this.fd, size: size, ino: ino,
                 path: this.path ? this.path.slice(0, 140) : null,
                 watch: this.watch, r: r });
          lastStatSize = size;
        }
      } catch (e) {
        send({ ev: 'sniff_fstat_err', fd: this.fd, e: String(e) });
      }
    }
  });
});

// also fstatat for path-based
tryAttach('fstatat', function () {
  var p = null;
  try { p = Module.getGlobalExportByName('fstatat'); } catch (e) {}
  if (!p) return;
  Interceptor.attach(p, {
    onEnter: function (a) {
      try { this.path = a[1].readCString(); } catch (e) { this.path = ''; }
      this.buf = a[2];
      this.isIhi = !!(this.path && /\.ihi$/.test(this.path));
    },
    onLeave: function (ret) {
      if (!this.isIhi || ret.toInt32() !== 0) return;
      try {
        var size = this.buf.add(48).readS64().toString();
        send({ ev: 'sniff_fstatat', p: this.path.slice(0, 140), size: size });
      } catch (e) {}
    }
  });
});

// --- open family: map fd
['open', 'open64', 'openat', 'openat64'].forEach(function (sym) {
  tryAttach(sym, function () {
    var p = Module.getGlobalExportByName(sym);
    var pi = (sym.indexOf('at') >= 0) ? 1 : 0;
    Interceptor.attach(p, {
      onEnter: function (a) {
        try { this.path = a[pi].readCString(); } catch (e) { this.path = ''; }
      },
      onLeave: function (ret) {
        if (!this.path || !/\.ihi$/.test(this.path)) return;
        var fd = ret.toInt32();
        if (fd >= 0) {
          fdMap[fd] = this.path;
          statWatch = 6;
          send({ ev: 'sniff_open_ihi', sym: sym, fd: fd, p: this.path.slice(0, 140) });
        } else {
          send({ ev: 'sniff_open_ihi', sym: sym, fd: fd, p: this.path.slice(0, 140), err: 1 });
        }
      }
    });
  });
});

// --- close / fclose
tryAttach('close', function () {
  var p = Module.getGlobalExportByName('close');
  Interceptor.attach(p, {
    onEnter: function (a) {
      var fd = a[0].toInt32();
      if (fdMap[fd]) {
        send({ ev: 'sniff_close_ihi', fd: fd, p: fdMap[fd].slice(0, 140),
               reads: readCount[fdMap[fd]] || 0 });
        delete fdMap[fd];
      }
    }
  });
});
tryAttach('fclose', function () {
  var p = Module.getGlobalExportByName('fclose');
  Interceptor.attach(p, {
    onEnter: function (a) {
      var k = a[0].toString();
      if (fpMap[k]) {
        send({ ev: 'sniff_fclose_ihi', p: fpMap[k].slice(0, 140), fp: k,
               reads: readCount[fpMap[k]] || 0 });
        delete fpMap[k];
      }
    }
  });
});

function bumpRead(path) {
  if (!path) return;
  readCount[path] = (readCount[path] || 0) + 1;
}

function maybeReport(fd, fpKey, buf, got, via) {
  if (hits >= 30 || got < 4) return;
  var path = null;
  if (fd >= 0 && fdMap[fd]) path = fdMap[fd];
  else if (fpKey && fpMap[fpKey]) path = fpMap[fpKey];
  if (path) bumpRead(path);
  var force = !!path;
  try {
    var n = Math.min(got, 48);
    var b = new Uint8Array(buf.readByteArray(n));
    var h = hex(b);
    var kind = classify(h);
    if (!force && !kind) return;
    if (force && !kind) kind = 'other';
    var key = (force ? 'F' : 'C') + via + '|' + h.slice(0, 16);
    if (seen[key]) return;
    seen[key] = 1;
    hits++;
    var bt = [];
    try {
      var frames = Thread.backtrace(this.context, Backtracer.ACCURATE);
      for (var i = 0; i < Math.min(frames.length, 8); i++) bt.push(describe(frames[i]));
    } catch (e) {}
    send({ ev: 'sniff', kind: kind, via: via, force: force, fd: fd,
           got: got, head: h, p: path ? path.slice(0, 140) : null, bt: bt, t: Date.now() });
  } catch (e) {}
}

['read', 'pread', 'pread64'].forEach(function (sym) {
  tryAttach('read:' + sym, function () {
    var p = Module.getGlobalExportByName(sym);
    Interceptor.attach(p, {
      onEnter: function (a) {
        this.fd = a[0].toInt32();
        this.buf = a[1];
      },
      onLeave: function (ret) {
        maybeReport.call(this, this.fd, null, this.buf, ret.toInt32(), sym);
      }
    });
  });
});

var filenoF = null;
try { filenoF = new NativeFunction(Module.getGlobalExportByName('fileno'), 'int', ['pointer']); } catch (e) {}

tryAttach('fread', function () {
  var p = Module.getGlobalExportByName('fread');
  Interceptor.attach(p, {
    onEnter: function (a) {
      this.buf = a[0];
      this.sz = a[1].toInt32();
      this.fp = a[3].toString();
      this.fd = -1;
      try { if (filenoF) this.fd = filenoF(a[3]); } catch (e) {}
    },
    onLeave: function (ret) {
      var items = ret.toInt32();
      var got = items > 0 ? items * (this.sz || 1) : 0;
      maybeReport.call(this, this.fd, this.fp, this.buf, got, 'fread');
    }
  });
});

send({ ev: 'sniff_armed8', lanes: lanes, errs: errs });

setInterval(function () {
  send({ ev: 'sniff_stat', hits: hits, enterIhi: enterIhi, leaveN: leaveN,
         pending: pending.length, fps: Object.keys(fpMap).length,
         fds: Object.keys(fdMap).length,
         reads: JSON.stringify(readCount),
         lanes: lanes.length, errs: errs.length, lastStatSize: lastStatSize });
}, 8000);
