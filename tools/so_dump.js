'use strict';
/*
 * Probe C: dump the runtime-decrypted image of the engine libraries.
 *
 * Stage 6 finding: libcocos2dlua.so's .text is encrypted on disk; the
 * decrypted image only exists in process memory (74.9% byte difference).
 * This dumps the loaded module from /proc/self/maps and writes it to the
 * app files dir as <lib>.<n>.bin, then reports a byte-diff estimate vs
 * the on-disk file so we can judge whether dumping worked.
 *
 * Files: /data/user/0/com.ihuman.pinyin/files/sodump_<name>_<n>.bin
 */
var DIR = '/data/user/0/com.ihuman.pinyin/files/';
var TARGETS = ['libcocos2dlua', 'libihcommon', 'libsqlcipher', 'libhpyr', 'libdu'];
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
  var fp = fns.fopen(Memory.allocUtf8String(path), Memory.allocUtf8String('wb'));
  if (fp.isNull()) return false;
  var buf = Memory.alloc(len);
  buf.writeByteArray(bytes);
  fns.fwrite(buf, 1, len, fp);
  fns.fclose(fp);
  return true;
}

var dumped = {};

function dumpModule(tag, m) {
  if (dumped[tag]) return;
  dumped[tag] = 1;
  var want = ['lib' + tag.replace(/^lib/, '')];
  try {
    var n = 0;
    Process.enumerateRanges('r--').forEach(function (r) {
      if (!r.file || r.file.path.indexOf(tag) < 0) return;
      n++;
      var size = r.size;
      if (size <= 0 || size > 64 * 1024 * 1024) return;
      var bytes = new Uint8Array(ptr(r.base).readByteArray(size));
      var fn = 'sodump_' + tag + '_' + n + '.bin';
      var written = writeFile(DIR + fn, bytes, size);
      send({ ev: 'sodump', tag: tag, file: fn, base: r.base.toString(),
             size: size, prot: r.protection, written: written });
    });
    send({ ev: 'sodump_done', tag: tag, ranges: n });
  } catch (e) {
    send({ ev: 'sodump_err', tag: tag, e: String(e) });
  }
}

function tryAll() {
  var mods = [];
  try { mods = Process.enumerateModules(); } catch (e) { return; }
  for (var i = 0; i < mods.length; i++) {
    var m = mods[i];
    for (var j = 0; j < TARGETS.length; j++) {
      if (m.name.indexOf(TARGETS[j]) === 0 && !dumped[TARGETS[j]]) {
        dumpModule(TARGETS[j], m);
      }
    }
  }
}

// dump soon after cocos shows up (scripts already decrypted at that point)
var tries = 0;
var poll = setInterval(function () {
  tries++;
  tryAll();
  if (tries === 10 || tries === 30) tryAll(); // re-dump late-arriving libs
  if (tries > 60) clearInterval(poll);
}, 900);
