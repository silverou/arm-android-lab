'use strict';
/*
 * Runtime string scan: the Lua layer is XXTEA-encrypted on disk, but its
 * decrypted chunks live in the app heap. Scan readable rw ranges for the
 * resource URL builder fragments and print surrounding printable context.
 */
var KWS = [
  'asset/android',
  'cos-8-resource',
  'moduleVersionMd5',
  'pySwitchCfg',
  'get_resource_list',
  'resource-auth',
  'resource/books'
];
var seen = {};
var outN = 0;
var CAPOUT = 300;

function pat(s) {
  var h = '';
  for (var i = 0; i < s.length; i++) {
    h += s.charCodeAt(i).toString(16).padStart(2, '0') + ' ';
  }
  return h.trim();
}

function ctxAt(addr, len) {
  try {
    var start = addr.sub(120);
    var buf = start.readByteArray(120 + len + 200);
    var arr = new Uint8Array(buf);
    var s = '';
    for (var i = 0; i < arr.length; i++) {
      var c = arr[i];
      s += (c >= 32 && c < 127) ? String.fromCharCode(c) : '.';
    }
    return s;
  } catch (e) {
    return '';
  }
}

function scanKw(kw) {
  if (outN >= CAPOUT) return;
  var p = pat(kw);
  var ranges = Process.enumerateRanges('rw-');
  for (var ri = 0; ri < ranges.length && outN < CAPOUT; ri++) {
    var r = ranges[ri];
    if (r.size > 512 * 1024 * 1024) continue;
    try {
      var matches = Memory.scanSync(r.base, r.size, p);
      for (var mi = 0; mi < matches.length && outN < CAPOUT; mi++) {
        var m = matches[mi];
        var c = ctxAt(m.address, kw.length);
        var key = c.slice(60, 220);
        if (seen[key]) continue;
        seen[key] = 1;
        outN++;
        send({ ev: 'hit', kw: kw, addr: m.address.toString(), ctx: c });
      }
    } catch (e) {}
  }
}

function run() {
  send({ ev: 'scan_start', mods: Process.enumerateModules().length });
  KWS.forEach(scanKw);
  send({ ev: 'scan_done', total: outN });
}

setTimeout(run, 20000);
setTimeout(run, 75000);
