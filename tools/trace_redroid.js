'use strict';
/*
 * Read-tracer: dedup-log paths/properties the shell reads (with errno),
 * plus content snapshots of /proc/self/maps and /proc/self/cmdline
 * (pread at offset 0 so the shell's own reads are unaffected).
 */
var seen = {};
var n = 0;
var CAP = 700;

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

var openF = new NativeFunction(Module.getGlobalExportByName('open'), 'int', ['pointer', 'int', 'int']);
var readF = new NativeFunction(Module.getGlobalExportByName('read'), 'long', ['int', 'pointer', 'long']);
var closeF = new NativeFunction(Module.getGlobalExportByName('close'), 'int', ['int']);
var preadF = new NativeFunction(Module.getGlobalExportByName('pread'), 'long', ['int', 'pointer', 'long', 'long']);
var filenoF = null;
try {
  filenoF = new NativeFunction(Module.getGlobalExportByName('fileno'), 'int', ['pointer']);
} catch (e) {}

// real status header at load: TracerPid tells us if frida gates via ptrace
try {
  var fd0 = openF(Memory.allocUtf8String('/proc/self/status'), 0, 0);
  if (fd0 >= 0) {
    var buf0 = Memory.alloc(2048);
    var n0 = readF(fd0, buf0, 2047);
    closeF(fd0);
    if (n0 > 0) {
      var txt = buf0.readUtf8String(Number(n0));
      var keep = txt.split('\n').filter(function (l) {
        return /^(Name|PPid|TracerPid|Threads|Pid|Tgid):/.test(l);
      });
      send({ ev: 'status0', s: keep.join(' | ') });
    }
  } else {
    send({ ev: 'status0_err', e: 'open failed', code: fd0 });
  }
} catch (e) {
  send({ ev: 'status0_err', e: String(e) });
}

var BADMAP = /frida|angle|pastel|qemu|houdini|goldfish|emulator|mumu|nox|vbox|bluestacks|droid4x|tiantian|nemu|microvirt|binderfs|memtrack/i;

function captureFd(fd, kind) {
  try {
    var buf = Memory.alloc(8192);
    if (kind === 'cmdline') {
      var r0 = preadF(fd, buf, 512, 0);
      if (r0 <= 0) return;
      var arr = new Uint8Array(buf.readByteArray(Number(r0)));
      var s = '';
      for (var ci = 0; ci < arr.length; ci++) {
        if (arr[ci] === 0) break;
        s += String.fromCharCode(arr[ci]);
      }
      log({ ev: 'cap', k: 'cmdline', v: s }, 'cap|cmdline');
      return;
    }
    var out = '';
    var off = 0;
    for (var c = 0; c < 8; c++) {
      var r = preadF(fd, buf, 8192, off);
      if (r <= 0) break;
      out += buf.readUtf8String(Number(r));
      off += Number(r);
      if (out.length > 60000) break;
    }
    if (kind !== 'maps') {
      // generic content snapshot (status/stat files the shell consumed)
      log({ ev: 'cap', k: kind, v: out.slice(0, 800) }, 'cap|' + kind);
      return;
    }
    var lines = out.split('\n');
    var hits = [];
    for (var i = 0; i < lines.length && hits.length < 25; i++) {
      if (BADMAP.test(lines[i])) hits.push(lines[i]);
    }
    log({ ev: 'cap', k: 'maps', total: lines.length, hits: hits }, 'cap|maps');
  } catch (e) {
    send({ ev: 'cap_err', k: kind, e: String(e) });
  }
}

var PATH_IDX = { openat: 1, newfstatat: 1, unlinkat: 1 };
var CAP_PATHS = { '/proc/self/maps': 'maps', '/proc/self/cmdline': 'cmdline' };

function capKind(p) {
  if (CAP_PATHS[p]) return CAP_PATHS[p];
  if (p === '/proc/self/status') return 'realst';
  if (p === '/proc/self/stat') return 'realstf';
  if (/\/cache\/self_status\.txt$/.test(p)) return 'selfst';
  if (/\/cache\/self_stat\.txt$/.test(p)) return 'selfstf';
  if (/\/faketask\/\d+\/status$/.test(p)) return 'tidst';
  if (/\/faketask\/\d+\/stat$/.test(p)) return 'tidstf';
  return null;
}

function hookPath(sym, tag) {
  try {
    var p = Module.getGlobalExportByName(sym);
    var idx = PATH_IDX[sym] || 0;
    Interceptor.attach(p, {
      onEnter: function (a) {
        try {
          var path = a[idx].readCString();
          if (path && path.charCodeAt(0) === 47) {
            this.k = path;
            this.cap = capKind(path);
          }
        } catch (e) {}
      },
      onLeave: function (ret) {
        if (!this.k) return;
        var r = ret.toInt32();
        var ok = tag === 'fopen' ? !ret.isNull() : r >= 0;
        if (this.cap && ok) {
          var fd = tag === 'fopen' ? (filenoF ? filenoF(ret) : -1) : r;
          if (fd >= 0) captureFd(fd, this.cap);
        }
        var o = { ev: 'tr', t: tag, p: this.k, r: r };
        if (r < 0 || (tag === 'access' && r !== 0)) o.e = errnoNow();
        log(o, tag + '|' + this.k + '|' + (o.e || 0));
      }
    });
  } catch (e) {
    send({ ev: 'tr_err', s: sym, e: String(e) });
  }
}

['fopen', 'open', 'openat', 'access', 'stat', 'lstat', 'readlink', 'opendir', 'unlink', 'unlinkat']
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
