'use strict';
/*
 * Read-tracer: dedup-log the absolute paths and properties the shell reads,
 * with return values and errno, so a gate crash maps to the exact input.
 * Also dumps the real /proc/self/status header at load (pre any later hooks).
 */
var seen = {};
var n = 0;
var CAP = 650;

function log(o, key) {
  if (seen[key] || n >= CAP) return;
  seen[key] = 1;
  n++;
  send(o);
}

var errnoFn = null;
try {
  errnoFn = new NativeFunction(Module.getGlobalExportByName('__errno'), 'pointer', []);
} catch (e) {
  try {
    errnoFn = new NativeFunction(Module.getGlobalExportByName('__errno_location'), 'pointer', []);
  } catch (e2) {}
}

function errnoNow() {
  if (!errnoFn) return -1;
  try {
    var p = errnoFn();
    return p.isNull() ? -1 : p.readS32();
  } catch (e) {
    return -1;
  }
}

// real status header at load: TracerPid tells us if frida gates via ptrace
try {
  var open0 = new NativeFunction(Module.getGlobalExportByName('open'), 'int', ['pointer', 'int', 'int']);
  var read0 = new NativeFunction(Module.getGlobalExportByName('read'), 'long', ['int', 'pointer', 'long']);
  var close0 = new NativeFunction(Module.getGlobalExportByName('close'), 'int', ['int']);
  var fd0 = open0(Memory.allocUtf8String('/proc/self/status'), 0, 0);
  if (fd0 >= 0) {
    var buf0 = Memory.alloc(2048);
    var n0 = read0(fd0, buf0, 2047);
    close0(fd0);
    if (n0 > 0) {
      var txt = buf0.readUtf8String(Number(n0));
      var keep = txt.split('\n').filter(function (l) {
        return /^(Name|TracerPid|Threads|Pid|Tgid):/.test(l);
      });
      send({ ev: 'status0', s: keep.join(' | ') });
    }
  } else {
    send({ ev: 'status0_err', e: 'open failed', code: fd0 });
  }
} catch (e) {
  send({ ev: 'status0_err', e: String(e) });
}

var PATH_IDX = { openat: 1, newfstatat: 1 };

function hookPath(sym, tag) {
  try {
    var p = Module.getGlobalExportByName(sym);
    var idx = PATH_IDX[sym] || 0;
    Interceptor.attach(p, {
      onEnter: function (a) {
        try {
          var path = a[idx].readCString();
          if (path && path.charCodeAt(0) === 47) this.k = path;
        } catch (e) {}
      },
      onLeave: function (ret) {
        if (!this.k) return;
        var r = ret.toInt32();
        var o = { ev: 'tr', t: tag, p: this.k, r: r };
        if (r < 0 || (tag === 'access' && r !== 0)) o.e = errnoNow();
        log(o, tag + '|' + this.k + '|' + (o.e || 0));
      }
    });
  } catch (e) {
    send({ ev: 'tr_err', s: sym, e: String(e) });
  }
}

['fopen', 'open', 'openat', 'access', 'stat', 'lstat', 'newfstatat', 'readlink', 'opendir']
  .forEach(function (s) { hookPath(s, s); });

try {
  var pg = Module.getGlobalExportByName('__system_property_get');
  Interceptor.attach(pg, {
    onEnter: function (a) {
      try { this.nm = a[0].readCString(); } catch (e) { this.nm = '?'; }
      this.buf = a[1];
    },
    onLeave: function (ret) {
      try {
        if (this.nm) log({ ev: 'tr', t: 'prop', p: this.nm, v: this.buf.readCString() }, 'prop|' + this.nm);
      } catch (e) {}
    }
  });
} catch (e) {
  send({ ev: 'tr_err', s: 'prop', e: String(e) });
}

send({ ev: 'trace_ready' });
