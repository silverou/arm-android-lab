'use strict';
/*
 * Content sniffer v7: self-checking fopen/fd tracker.
 *
 * v6 failed silently (sniff_fopen=0 while bridge FOPEN saw main.ihi).
 * This version:
 *   - counts EVERY fopen enter (first 30 paths) to prove the hook lives
 *   - tracks open/openat fd for *.ihi (trace already proved open r=205 works)
 *   - force-reports read/pread/fread on those fds (content + backtrace)
 */
var seen = {};
var hits = 0;
var fopenN = 0;
var ihiFd = {};
var openN = 0;
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
  try {
    fn();
    lanes.push(name);
  } catch (e) {
    errs.push(name + ':' + e);
    send({ ev: 'sniff_attach_err', name: name, e: String(e) });
  }
}

// --- fopen: count all + special-case .ihi
tryAttach('fopen', function () {
  var p = Module.getGlobalExportByName('fopen');
  Interceptor.attach(p, {
    onEnter: function (a) {
      fopenN++;
      try { this.path = a[0].readCString(); } catch (e) { this.path = '?'; }
      if (fopenN <= 30) {
        send({ ev: 'sniff_fopen_any', n: fopenN, p: (this.path || '').slice(0, 140) });
      }
      if (this.path && /\.ihi$/.test(this.path)) {
        send({ ev: 'sniff_fopen_ihi', p: this.path.slice(0, 140) });
        this.ihi = 1;
      }
    },
    onLeave: function (ret) {
      if (this.ihi) {
        send({ ev: 'sniff_fopen_ihi_leave', ok: ret.isNull() ? 0 : 1,
               fp: ret.isNull() ? '0' : ret.toString() });
      }
    }
  });
});

// --- open family: fd map for .ihi
['open', 'open64', 'openat', 'openat64'].forEach(function (sym) {
  tryAttach('open:' + sym, function () {
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
          ihiFd[fd] = this.path;
          openN++;
          send({ ev: 'sniff_open_ihi', sym: sym, fd: fd, p: this.path.slice(0, 140) });
        } else {
          send({ ev: 'sniff_open_ihi', sym: sym, fd: fd, p: this.path.slice(0, 140), err: 1 });
        }
      }
    });
  });
});

tryAttach('close', function () {
  var p = Module.getGlobalExportByName('close');
  Interceptor.attach(p, {
    onEnter: function (a) {
      var fd = a[0].toInt32();
      if (ihiFd[fd]) {
        send({ ev: 'sniff_close_ihi', fd: fd, p: ihiFd[fd].slice(0, 140) });
        delete ihiFd[fd];
      }
    }
  });
});

function forceRead(fd, buf, got, via) {
  if (hits > 40 || got < 1) return;
  var force = !!ihiFd[fd];
  if (!force) {
    // content classify fallback
    if (got < 4) return;
    try {
      var b0 = buf.readU8();
      if (b0 !== 0x70 && b0 !== 0x1b && b0 !== 0x34 && b0 !== 0x7b) return;
    } catch (e) { return; }
  }
  try {
    var n = Math.min(got, 48);
    var b = new Uint8Array(buf.readByteArray(n));
    var h = hex(b);
    var key = (force ? 'F' : 'C') + via + '|' + h.slice(0, 16);
    if (seen[key]) return;
    seen[key] = 1;
    hits++;
    var bt = [];
    try {
      var frames = Thread.backtrace(this.context, Backtracer.ACCURATE);
      for (var i = 0; i < Math.min(frames.length, 8); i++) bt.push(describe(frames[i]));
    } catch (e) {}
    send({ ev: 'sniff', kind: classify(h) || 'other', via: via, force: force,
           fd: fd, got: got, head: h, p: ihiFd[fd] ? ihiFd[fd].slice(0, 140) : null,
           bt: bt, t: Date.now() });
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
        forceRead.call(this, this.fd, this.buf, ret.toInt32(), sym);
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
      this.fd = -1;
      try { if (filenoF) this.fd = filenoF(a[3]); } catch (e) {}
    },
    onLeave: function (ret) {
      var items = ret.toInt32();
      var got = items > 0 ? items * (this.sz || 1) : 0;
      forceRead.call(this, this.fd, this.buf, got, 'fread');
    }
  });
});

send({ ev: 'sniff_armed5', lanes: lanes, errs: errs });

setInterval(function () {
  send({ ev: 'sniff_stat', hits: hits, fopenN: fopenN, opens: openN,
         fds: Object.keys(ihiFd).length, lanes: lanes.length, errs: errs.length });
}, 8000);
