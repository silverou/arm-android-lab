'use strict';
/*
 * File-level Lua chunk extractor v2: native-speed SZAQ magic scan.
 *
 * The engine's internal loader decrypts each .ihi to a heap buffer with
 * the fork's bytecode header (\x1bSZAQ) and undumps it. v1 used a JS byte
 * loop (too slow for the startup burst window). v2 uses Memory.scanSync
 * (native speed) per rw- range, densest rounds first.
 *
 * Dedupe by content hash (first 32 bytes) — the same chunk may sit at
 * several VAs over time. Window = min(256KB, range end - hit); offline
 * parsing of the Lua 5.1 undump format trims to exact boundaries.
 *
 * Output: /data/user/0/com.ihuman.pinyin/files/mems_lua_<n>_<vahex>.bin
 */
var DIR = '/data/user/0/com.ihuman.pinyin/files/';
var fns = {};
['fopen', 'fwrite', 'fclose'].forEach(function (n) {
  var p = null;
  try { p = Module.getGlobalExportByName(n); } catch (e) {}
  if (p) fns[n] = new NativeFunction(p,
    n === 'fwrite' ? 'size_t' : (n === 'fclose' ? 'int' : 'pointer'),
    n === 'fwrite' ? ['pointer', 'size_t', 'size_t', 'pointer'] :
    n === 'fclose' ? ['pointer'] : ['pointer', 'pointer']);
});
var ok = !!(fns.fopen && fns.fwrite && fns.fclose);
send({ ev: 'mem_ready', ok: ok });

function writeFile(path, bytes, len) {
  if (!ok) return false;
  var fp = fns.fopen(Memory.allocUtf8String(path), Memory.allocUtf8String('wb'));
  if (fp.isNull()) return false;
  var buf = Memory.alloc(len);
  buf.writeByteArray(bytes);
  fns.fwrite(buf, 1, len, fp);
  fns.fclose(fp);
  return true;
}

var n = 0, dup = 0;
var seen = {};

function hashKey(bytes) {
  var s = '';
  for (var i = 0; i < bytes.length && i < 32; i++) s += ('0' + bytes[i].toString(16)).slice(-2);
  return s;
}

function scanRound(round) {
  var found = 0;
  var ranges;
  try { ranges = Process.enumerateRanges('rw-'); } catch (e) { return; }
  for (var ri = 0; ri < ranges.length; ri++) {
    var r = ranges[ri];
    if (r.size < 64 || r.size > 64 * 1024 * 1024) continue;
    var matches;
    try { matches = Memory.scanSync(r.base, r.size, '1b 53 5a 41'); } catch (e) { continue; }
    for (var mi = 0; mi < matches.length; mi++) {
      var va = matches[mi].address;
      var winLen = Math.min(256 * 1024, r.base.add(r.size).sub(va).toInt32());
      if (winLen < 32) continue;
      var win;
      try { win = new Uint8Array(va.readByteArray(winLen)); } catch (e) { continue; }
      var key = hashKey(win);
      if (seen[key]) { dup++; continue; }
      seen[key] = 1;
      n++;
      var fn = 'mems_lua_' + n + '_' + va.toString().replace('0x', '') + '.bin';
      if (writeFile(DIR + fn, win, win.length)) {
        found++;
        if (n <= 5 || n % 50 === 0) {
          send({ ev: 'mem_hit', n: n, va: va.toString(), len: winLen, round: round });
        }
      }
    }
  }
  if (found) send({ ev: 'mem_round', round: round, new: found, total: n, dup: dup });
}

// densest at startup (the decrypt burst), then back off
var round = 0;
var plan = [];
for (var i = 0; i < 80; i++) plan.push(80);      // ~6.4s dense
for (var i = 0; i < 40; i++) plan.push(250);     // next 10s
for (var i = 0; i < 20; i++) plan.push(1000);    // next 20s
function next() {
  if (round >= plan.length) return;
  var delay = plan[round];
  round++;
  setTimeout(function () {
    try { scanRound(round); } catch (e) { send({ ev: 'mem_err', e: String(e) }); }
    next();
  }, delay);
}
next();
setInterval(function () {
  send({ ev: 'mem_stat', files: n, dup: dup, round: round });
}, 10000);
