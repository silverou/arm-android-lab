'use strict';
/*
 * File-read probe: capture WHAT bytes the engine actually reads for .ihi.
 *
 * Established: RVA 0x1492424 site is existence-check only (fopen64+fclose).
 * Real content flows: (a) disk fread after fopen64, (b) AAsset_read for
 * APK-internal assets. This probe:
 *   1) tracks fopen64 FILE* -> path (so fread's stream can be mapped)
 *   2) hooks fread: when stream is an .ihi path, dump first bytes read
 *      + total size read -> tells disk format (plain? SZAQ? 42a64166?)
 *   3) hooks AAsset_read (module export): dump first bytes -> confirms
 *      APK-internal .ihi container format
 *
 * Output: gate_probe-style events + files/read_head_<n>.bin (first 64B)
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

var fileMap = {};      // FILE* -> path
var openN = 0, readN = 0;
var seenHeads = {};

function hex(b, n) {
  var s = '';
  for (var i = 0; i < b.length && i < n; i++) s += ('0' + b[i].toString(16)).slice(-2);
  return s;
}

// --- fopen64 + fopen: record FILE* -> path (bionic keeps both symbols;
// engine may call either — bridge's FOPEN logger attaches `fopen` only)
var fopen64 = null;
try { fopen64 = Module.getGlobalExportByName('fopen64'); } catch (e) {}
var fopenPlain = null;
try { fopenPlain = Module.getGlobalExportByName('fopen'); } catch (e) {}
function attachOpen(p, label) {
  if (!p) { send({ ev: 'rd_miss', sym: label }); return; }
  Interceptor.attach(p, {
    onEnter: function (a) {
      try { this.path = a[0].readCString(); } catch (e) { this.path = ''; }
      if (this.path && /\.ihi$/.test(this.path)) {
        send({ ev: 'rd_open_enter', via: label, p: this.path.slice(0, 130) });
      }
    },
    onLeave: function (ret) {
      if (!ret.isNull() && this.path && /\.ihi$/.test(this.path)) {
        fileMap[ret.toString()] = this.path;
        openN++;
        send({ ev: 'rd_open', via: label, p: this.path.slice(0, 130), fp: ret.toString() });
      }
    }
  });
}
attachOpen(fopen64, 'fopen64');
attachOpen(fopenPlain, 'fopen');
send({ ev: 'rd_openlanes', f64: !!fopen64, f: !!fopenPlain });

// --- fclose: drop mapping
var fclose = null;
try { fclose = Module.getGlobalExportByName('fclose'); } catch (e) {}
if (fclose) {
  Interceptor.attach(fclose, {
    onEnter: function (a) {
      var k = a[0].toString();
      if (fileMap[k]) delete fileMap[k];
    }
  });
}

// --- fread: dump head when stream is .ihi
var fread = null;
try { fread = Module.getGlobalExportByName('fread'); } catch (e) {}
if (fread) {
  Interceptor.attach(fread, {
    onEnter: function (a) {
      this.buf = a[0];
      this.stream = a[3].toString();
      this.path = fileMap[this.stream] || null;
    },
    onLeave: function (ret) {
      if (!this.path) return;
      var got = ret.toInt32();
      if (got <= 0) return;
      try {
        var head = new Uint8Array(this.buf.readByteArray(Math.min(got, 32)));
        var h = hex(head, 32);
        var key = this.path + '|' + h.slice(0, 16);
        if (seenHeads[key]) return;
        seenHeads[key] = 1;
        readN++;
        send({ ev: 'rd_read', p: this.path.slice(0, 130), got: got, head: h });
        if (readN <= 8) {
          writeFile(DIR + 'read_head_' + readN + '.bin', head, head.length);
        }
      } catch (e) { send({ ev: 'rd_read_err', e: String(e) }); }
    }
  });
} else {
  send({ ev: 'rd_miss', sym: 'fread' });
}

// --- AAsset_read: dump head of APK-internal reads
var aassetRead = null;
var tries = 0;
var assetPoll = setInterval(function () {
  tries++;
  var m = null;
  try {
    Process.enumerateModules().forEach(function (x) {
      if (!m && /libandroid\.so/.test(x.name)) m = x;
    });
  } catch (e) {}
  if (m) {
    try { aassetRead = m.findExportByName('AAsset_read'); } catch (e) {}
    if (!aassetRead) { try { aassetRead = m.findExportByName('AAssetRead'); } catch (e) {} }
    if (aassetRead && !aassetRead.isNull()) {
      Interceptor.attach(aassetRead, {
        onEnter: function (a) { this.buf = a[1]; this.sz = a[2].toInt32(); },
        onLeave: function (ret) {
          var got = ret.toInt32();
          if (got <= 0) return;
          try {
            var head = new Uint8Array(this.buf.readByteArray(Math.min(got, 32)));
            var h = hex(head, 32);
            var key = 'aasset|' + h.slice(0, 16);
            if (seenHeads[key]) return;
            seenHeads[key] = 1;
            send({ ev: 'rd_aasset', got: got, head: h, want: this.sz });
            if (readN < 8) {
              readN++;
              writeFile(DIR + 'read_head_' + readN + '.bin', head, head.length);
            }
          } catch (e) {}
        }
      });
      send({ ev: 'rd_hooked', sym: 'AAsset_read' });
    }
    if (tries > 1) clearInterval(assetPoll);
  } else if (tries > 100) {
    clearInterval(assetPoll);
    send({ ev: 'rd_miss', sym: 'libandroid' });
  }
}, 100);

// --- syscall lane: open/openat -> fd map; read/pread64 -> head dump
var fdMap = {};
var fileno = null;
try { fileno = new NativeFunction(Module.getGlobalExportByName('fileno'), 'int', ['pointer']); } catch (e) {}
if (fileno) {
  [fopen64, fopenPlain].forEach(function (fp) {
    if (!fp) return;
    Interceptor.attach(fp, {
      onEnter: function (a) { try { this.path = a[0].readCString(); } catch (e) { this.path = ''; } },
      onLeave: function (ret) {
        if (!ret.isNull() && this.path && /\.ihi$/.test(this.path)) {
          try { fdMap[fileno(ret)] = this.path; } catch (e) {}
        }
      }
    });
  });
}
['open', 'openat', 'open64', 'openat64'].forEach(function (sym) {
  var p = null;
  try { p = Module.getGlobalExportByName(sym); } catch (e) {}
  if (!p) return;
  Interceptor.attach(p, {
    onEnter: function (a) {
      // open(path,...) / openat(dirfd, path, ...)
      var pi = (sym.indexOf('at') >= 0) ? 1 : 0;
      try { this.path = a[pi].readCString(); } catch (e) { this.path = ''; }
    },
    onLeave: function (ret) {
      var fd = ret.toInt32();
      if (fd >= 0 && this.path && /\.ihi$/.test(this.path)) {
        fdMap[fd] = this.path;
        send({ ev: 'rd_openat', sym: sym, fd: fd, p: this.path.slice(0, 130) });
      }
    }
  });
});
function hookReadLike(sym) {
  var p = null;
  try { p = Module.getGlobalExportByName(sym); } catch (e) {}
  if (!p) return false;
  Interceptor.attach(p, {
    onEnter: function (a) {
      var fd = a[0].toInt32();
      this.path = fdMap[fd] || null;
      this.buf = a[1];
      if (sym === 'pread64') this.count = a[2].toInt32();
      else this.count = a[2].toInt32();
    },
    onLeave: function (ret) {
      if (!this.path) return;
      var got = ret.toInt32();
      if (got <= 0) return;
      try {
        var head = new Uint8Array(this.buf.readByteArray(Math.min(got, 32)));
        var h = hex(head, 32);
        var key = this.path + '|' + h.slice(0, 16);
        if (seenHeads[key]) return;
        seenHeads[key] = 1;
        readN++;
        send({ ev: 'rd_read', via: sym, p: this.path.slice(0, 130), got: got, head: h });
        if (readN <= 8) writeFile(DIR + 'read_head_' + readN + '.bin', head, head.length);
      } catch (e) {}
    }
  });
  return true;
}
var readLanes = ['read', 'pread64', 'read64'].filter(hookReadLike);
send({ ev: 'rd_lanes', read: readLanes });

setInterval(function () {
  send({ ev: 'rd_stat', opens: openN, reads: readN, mapped: Object.keys(fileMap).length,
         fds: Object.keys(fdMap).length });
}, 8000);
