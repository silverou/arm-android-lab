'use strict';
/*
 * Probe B v2: dex-dump feasibility, two lanes.
 *
 * Lane 1 (native, primary): scan /proc/self/maps for readable anonymous /
 * memfd mappings containing the dex magic (64 65 78 0a = "dex\n") and dump
 * them to files. InMemoryDexClassLoader keeps dex as ByteBuffer -> memfd or
 * anonymous mmap; this finds it regardless of the Java loader used.
 *
 * Lane 2 (Java): hook DexClassLoader / InMemoryDexClassLoader constructors
 * and record the loading path (file paths => trivially dumpable; buffers =>
 * lane 1 carries it).
 *
 * Output: /data/user/0/com.ihuman.pinyin/files/dexdump_<n>.bin
 */
var DIR = '/data/user/0/com.ihuman.pinyin/files/';
var fns = {};
['fopen', 'fwrite', 'fclose'].forEach(function (n) {
  var p = null;
  try { p = Module.getGlobalExportByName(n); } catch (e) {}
  if (p) fns[n] = new NativeFunction(p, 'pointer',
    n === 'fwrite' ? ['pointer', 'size_t', 'size_t', 'pointer'] :
    n === 'fclose' ? ['pointer'] : ['pointer', 'pointer']);
});
var ok = !!(fns.fopen && fns.fwrite && fns.fclose);

function writeFile(path, bytes, len) {
  if (!ok) return false;
  try {
    var fp = fns.fopen(Memory.allocUtf8String(path), Memory.allocUtf8String('wb'));
    if (fp.isNull()) return false;
    var buf = Memory.alloc(len);
    buf.writeByteArray(bytes);
    fns.fwrite(buf, 1, len, fp);
    fns.fclose(fp);
    return true;
  } catch (e) { return false; }
}

var dumpedRanges = {};
function dumpDexRanges() {
  var found = 0;
  var ranges;
  try { ranges = Process.enumerateRanges('r--'); } catch (e) { send({ ev: 'dex_range_err', e: String(e) }); return; }
  ranges.forEach(function (r) {
    if (r.size < 4096 || r.size > 64 * 1024 * 1024) return;
    var key = r.base.toString() + ':' + r.size;
    if (dumpedRanges[key]) return;
    var sig = null;
    try { sig = r.base.readCString(4); } catch (e) { return; }
    if (sig !== 'dex\n') return;
    dumpedRanges[key] = 1;
    found++;
    try {
      var size = Math.min(r.size, 32 * 1024 * 1024);
      var bytes = new Uint8Array(r.base.readByteArray(size));
      var fn = 'dexdump_' + found + '_' + r.base.toString().replace('0x', '') + '.bin';
      var w = writeFile(DIR + fn, bytes, size);
      send({ ev: 'dexdump', file: fn, base: r.base.toString(), size: size, written: w });
    } catch (e2) {
      send({ ev: 'dexdump_err', base: r.base.toString(), e: String(e2) });
    }
  });
  send({ ev: 'dexdump_done', found: found });
}

// Lane 2: Java hooks (late-boot safe; uses the jprobe-proven pattern)
var javaDone = false;
function javaLane() {
  if (javaDone) return;
  if (typeof Java === 'undefined') {
    send({ ev: 'jnope' });
    return;
  }
  javaDone = true;
  try {
    Java.perform(function () {
      var targets = [
        ['dalvik.system.InMemoryDexClassLoader', '<init>', ['buffer', 'parent', 'loader']],
        ['dalvik.system.DexClassLoader', '<init>', ['dexPath', 'optDir', 'libPath', 'parent']],
        ['dalvik.system.PathClassLoader', '<init>', ['path', 'parent']],
      ];
      targets.forEach(function (t) {
        try {
          var C = Java.use(t[0]);
          C[t[1]].overloads.forEach(function (ov) {
            ov.implementation = function () {
              var out = { ev: 'dex_loader', cls: t[0] };
              for (var i = 0; i < t[2].length && i < arguments.length; i++) {
                try {
                  var a = arguments[i];
                  if (a === null || a === undefined) { out[t[2][i]] = String(a); continue; }
                  if (typeof a === 'string') out[t[2][i]] = a.slice(0, 140);
                  else if (typeof a === 'object') out[t[2][i]] = (a.getClass ? a.getClass().getName() : 'obj');
                  else out[t[2][i]] = String(a);
                } catch (e) {}
              }
              send(out);
              return ov.apply(this, arguments);
            };
          });
          send({ ev: 'dex_hooked', cls: t[0] });
        } catch (e) {
          send({ ev: 'dex_hook_miss', cls: t[0], e: String(e).slice(0, 100) });
        }
      });
    });
  } catch (e) {
    send({ ev: 'dex_java_err', e: String(e) });
  }
}

var tick = 0;
var poll = setInterval(function () {
  tick++;
  if (tick === 4 || tick === 12 || tick === 30) dumpDexRanges();
  if (tick >= 6) javaLane();
  if (tick > 70) clearInterval(poll);
}, 1200);
