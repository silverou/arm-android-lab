'use strict';
/*
 * Sniffer v13: libc fopen hook (always armed) -> one-shot at returnAddress.
 * At the loader's fopen return (RVA 0x1492d98) capture x0=FILE*, fileno,
 * AND Thread.backtrace so we see who called the loader function.
 * v10 proved: existence-check fopen (ret 0x1492434, no read, closes)
 * then loader fopen (ret 0x1492d98) freads FULL file (192B plain) via
 * libcocos2dlua+0x1492df0, then process dies ~42ms later.
 */
var seen = {};
var retHooks = {};
var fpMap = {};
var fdMap = {};
var readCount = {};
var enterIhi = 0;
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
  catch (e) { errs.push(name + ':' + e); send({ ev: 'sniff_attach_err', name: name, e: String(e) }); }
}

function armReturnCapture(path, via) {
  var retAddr = null;
  try { retAddr = this.returnAddress; } catch (e) {}
  if (!retAddr) { send({ ev: 'sniff_retmiss', via: via }); return; }
  var key = retAddr.toString();
  if (retHooks[key]) {
    // already hooked (existence-check and loader share nothing, so this is safe)
    send({ ev: 'sniff_retarm_dup', at: describe(retAddr), via: via });
    return;
  }
  retHooks[key] = 1;
  try {
    Interceptor.attach(retAddr, {
      onEnter: function () {
        var fp = null;
        try { fp = this.context.x0; } catch (e) {}
        if (!fp || fp.isNull()) { send({ ev: 'sniff_retfail', at: describe(retAddr), via: via }); return; }
        var fpk = fp.toString();
        fpMap[fpk] = path;
        var fd = -1;
        try {
          var fileno = new NativeFunction(Module.getGlobalExportByName('fileno'), 'int', ['pointer']);
          fd = fileno(fp);
        } catch (e) {}
        if (fd >= 0) fdMap[fd] = path;
        var bt = [];
        try {
          var frames = Thread.backtrace(this.context, Backtracer.ACCURATE);
          for (var i = 0; i < Math.min(frames.length, 10); i++) bt.push(describe(frames[i]));
        } catch (e) {}
        send({ ev: 'sniff_ret', p: path.slice(0, 140), via: via, fp: fpk, fd: fd,
               at: describe(retAddr), bt: bt, t: Date.now() });
      }
    });
    send({ ev: 'sniff_retarm', p: path.slice(0, 100), via: via, at: describe(retAddr) });
  } catch (e) {
    send({ ev: 'sniff_retarm_err', e: String(e), at: describe(retAddr) });
  }
}

['fopen', 'fopen64'].forEach(function (sym) {
  tryAttach(sym, function () {
    var p = Module.getGlobalExportByName(sym);
    Interceptor.attach(p, {
      onEnter: function (a) {
        var path = '';
        try { path = a[0].readCString(); } catch (e) {}
        if (!path || !/\.ihi$/.test(path)) return;
        enterIhi++;
        send({ ev: 'sniff_fopen_ihi', via: sym, n: enterIhi, p: path.slice(0, 140),
               ret: describe(this.returnAddress) });
        armReturnCapture.call(this, path, sym);
      }
    });
  });
});

// open family (for completeness)
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
        if (fd >= 0) { fdMap[fd] = this.path; send({ ev: 'sniff_open_ihi', sym: sym, fd: fd, p: this.path.slice(0, 140) }); }
      }
    });
  });
});

tryAttach('close', function () {
  var p = Module.getGlobalExportByName('close');
  Interceptor.attach(p, {
    onEnter: function (a) {
      var fd = a[0].toInt32();
      if (fdMap[fd]) {
        send({ ev: 'sniff_close_ihi', fd: fd, p: fdMap[fd].slice(0, 140), reads: readCount[fdMap[fd]] || 0 });
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
        send({ ev: 'sniff_fclose_ihi', p: fpMap[k].slice(0, 140), fp: k, reads: readCount[fpMap[k]] || 0 });
        delete fpMap[k];
      }
    }
  });
});

function maybeReport(fd, fpKey, buf, got, via) {
  if (got < 4) return;
  var path = null;
  if (fd >= 0 && fdMap[fd]) path = fdMap[fd];
  else if (fpKey && fpMap[fpKey]) path = fpMap[fpKey];
  if (path) readCount[path] = (readCount[path] || 0) + 1;
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
    var bt = [];
    try {
      var frames = Thread.backtrace(this.context, Backtracer.ACCURATE);
      for (var i = 0; i < Math.min(frames.length, 10); i++) bt.push(describe(frames[i]));
    } catch (e) {}
    send({ ev: 'sniff', kind: kind, via: via, force: force, fd: fd,
           got: got, head: h, p: path ? path.slice(0, 140) : null, bt: bt, t: Date.now() });
  } catch (e) {}
}

['read', 'pread', 'pread64'].forEach(function (sym) {
  tryAttach('read:' + sym, function () {
    var p = Module.getGlobalExportByName(sym);
    Interceptor.attach(p, {
      onEnter: function (a) { this.fd = a[0].toInt32(); this.buf = a[1]; },
      onLeave: function (ret) { maybeReport.call(this, this.fd, null, this.buf, ret.toInt32(), sym); }
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

send({ ev: 'sniff_armed12', lanes: lanes, errs: errs });

setInterval(function () {
  send({ ev: 'sniff_stat', enterIhi: enterIhi, fps: Object.keys(fpMap).length,
         fds: Object.keys(fdMap).length, reads: JSON.stringify(readCount),
         lanes: lanes.length, errs: errs.length });
}, 8000);
