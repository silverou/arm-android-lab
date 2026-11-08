'use strict';
/*
 * Runtime string scan: Lua is XXTEA-encrypted on disk but decrypted in the
 * heap. Scan rw ranges for builder fragments and dump the printable runs in
 * a wide window around each hit (catches sibling literals such as the CDN
 * base host, "/asset/android/" and ".zip" pieces).
 */
var KWS = ['asset/android', 'cos-8-resource', 'moduleVersionMd5', 'pySwitchCfg', 'get_resource_list', 'resource-auth'];
var seen = {};
var total = 0;
var CAP = 600;

function printable(bufAddr, len) {
  try {
    var arr = new Uint8Array(bufAddr.readByteArray(len));
    var runs = [];
    var cur = '';
    for (var i = 0; i < arr.length; i++) {
      var c = arr[i];
      if (c >= 32 && c < 127) {
        cur += String.fromCharCode(c);
      } else {
        if (cur.length >= 8) runs.push(cur);
        cur = '';
      }
    }
    if (cur.length >= 8) runs.push(cur);
    return runs;
  } catch (e) {
    return [];
  }
}

function scanKw(kw) {
  if (total >= CAP) return;
  var h = '';
  for (var i = 0; i < kw.length; i++) h += kw.charCodeAt(i).toString(16).padStart(2, '0') + ' ';
  h = h.trim();
  var ranges = Process.enumerateRanges('rw-');
  for (var ri = 0; ri < ranges.length && total < CAP; ri++) {
    var r = ranges[ri];
    if (r.size > 512 * 1024 * 1024) continue;
    try {
      var ms = Memory.scanSync(r.base, r.size, h);
      for (var mi = 0; mi < ms.length && total < CAP; mi++) {
        var addr = ms[mi].address;
        var start = addr.sub(4000);
        if (start.compare(r.base) < 0) start = r.base;
        var span = addr.add(kw.length + 4000).sub(start);
        var len = Number(span);
        if (len > 10000) len = 10000;
        var runs = printable(start, len);
        var keep = [];
        runs.forEach(function (s) {
          if (s.length < 10) return;
          if (!/http|asset|zip|resource|\.json|ihumand|ihuman|%s/.test(s)) return;
          if (seen[s]) return;
          seen[s] = 1;
          keep.push(s);
        });
        if (keep.length) {
          total += keep.length;
          send({ ev: 'srclit', kw: kw, addr: addr.toString(), n: keep.length, items: keep.slice(0, 40) });
        }
      }
    } catch (e) {}
  }
}

function run() {
  send({ ev: 'scan_start' });
  KWS.forEach(scanKw);
  send({ ev: 'scan_done', total: total });
}

setTimeout(run, 20000);
setTimeout(run, 75000);
