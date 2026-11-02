'use strict';
/*
 * Read-tracer: dedup-log the absolute paths and properties the shell reads,
 * with return values, so a gate crash maps to the exact distinguishing input.
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
        if (this.k) log({ ev: 'tr', t: tag, p: this.k, r: ret.toInt32() }, tag + '|' + this.k);
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
