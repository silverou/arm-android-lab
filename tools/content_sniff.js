'use strict';
/*
 * Sniffer v14: live code capture around the .ihi loader.
 *
 * Facts: loader fn @ libcocos2dlua+0x1492bdc; its fopen returns to 0x1492d98;
 * fread @ 0x1492df0 reads full file; caller (bt) = libcocos2dlua+0x1492490 —
 * but bss_code.bin (offline dump) shows non-code there (stale/encrypted page).
 * So dump the LIVE window at runtime and also hook the loader entry, arming
 * it as soon as the first .ihi fopen is observed (module is loaded by then).
 *
 * Outputs: files/loader_win_<k>.bin (0x800 bytes each)
 */
var DIR = '/data/user/0/com.ihuman.pinyin/files/';
var MODRE = /libcocos2dlua/;
var armedLoader = false;
var armedRet = {};
var winN = 0;
var fpMap = {};
var fdMap = {};
var enterIhi = 0;

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

function describe(addr) {
  var s = addr.toString();
  try {
    var m = Process.findModuleByAddress(addr);
    if (m) s = m.name + '+0x' + addr.sub(m.base).toString(16);
  } catch (e) {}
  return s;
}

function findMod() {
  var m = null;
  try {
    Process.enumerateModules().forEach(function (x) {
      if (!m && MODRE.test(x.name)) m = x;
    });
  } catch (e) {}
  return m;
}

function dumpWindow(m, rva, label) {
  try {
    var n = 0x800;
    var bytes = new Uint8Array(m.base.add(rva).readByteArray(n));
    winN++;
    var path = DIR + 'loader_win_' + winN + '_' + label + '_' + rva.toString(16) + '.bin';
    var wrote = writeFile(path, bytes, n);
    send({ ev: 'dumpwin', label: label, rva: '0x' + rva.toString(16), n: n, wrote: wrote });
  } catch (e) {
    send({ ev: 'dumpwin_err', label: label, e: String(e) });
  }
}

function frameWalk(ctx) {
  var out = [];
  try {
    var fp = ctx.fp;
    for (var i = 0; i < 6; i++) {
      if (fp.isNull()) break;
      var next = fp.readPointer();
      var lr = fp.add(8).readPointer();
      out.push(describe(lr));
      if (next.compare(fp) <= 0) break;
      fp = next;
    }
  } catch (e) { out.push('walk_err:' + e); }
  return out;
}

function armLoader(m) {
  if (armedLoader) return;
  armedLoader = true;
  try {
    Interceptor.attach(m.base.add(0x1492bdc), {
      onEnter: function (a) {
        var bt = [];
        try {
          var frames = Thread.backtrace(this.context, Backtracer.ACCURATE);
          for (var i = 0; i < Math.min(frames.length, 10); i++) bt.push(describe(frames[i]));
        } catch (e) {}
        send({ ev: 'loader_enter', x0: a[0].toString(), x1: a[1].toString(),
               ret: describe(this.returnAddress), bt: bt, fpw: frameWalk(this.context) });
        dumpWindow(m, 0x1492400, 'caller');
        dumpWindow(m, 0x1492b00, 'loader');
      }
    });
    // success-path ret: capture the Data{ptr,size} handed back to caller
    Interceptor.attach(m.base.add(0x1492e40), {
      onEnter: function () {
        var o = { ev: 'loader_ret', t: Date.now() };
        try { o.x0 = this.context.x0.toString(); } catch (e) {}
        try { o.x1 = this.context.x1.toString(); } catch (e) {}
        try { o.x19 = this.context.x19.toString(); } catch (e) {}
        try {
          var d = this.context.x0;
          if (d && !d.isNull()) {
            o.dptr = d.readPointer().toString();
            o.dsize = d.add(8).readPointer().toString();
            var sz = d.add(8).readPointer().toInt32();
            if (sz > 0 && sz < 65536) {
              var head = new Uint8Array(d.readPointer().readByteArray(Math.min(sz, 16)));
              var h = '';
              for (var i = 0; i < head.length; i++) h += ('0' + head[i].toString(16)).slice(-2);
              o.dhead = h;
            }
          }
        } catch (e) {}
        send(o);
        dumpWindow(m, 0x1492400, 'ret');
      }
    });
    send({ ev: 'loader_armed' });
  } catch (e) {
    send({ ev: 'loader_arm_err', e: String(e) });
  }
}

['fopen', 'fopen64'].forEach(function (sym) {
  var p = null;
  try { p = Module.getGlobalExportByName(sym); } catch (e) {}
  if (!p) return;
  Interceptor.attach(p, {
    onEnter: function (a) {
      var path = '';
      try { path = a[0].readCString(); } catch (e) {}
      if (!path || !/\.ihi$/.test(path)) return;
      enterIhi++;
      send({ ev: 'fopen_ihi', via: sym, n: enterIhi, p: path.slice(0, 140),
             ret: describe(this.returnAddress) });
      var m = findMod();
      if (m && !armedLoader) armLoader(m);
      // one-shot at return address
      var retAddr = null;
      try { retAddr = this.returnAddress; } catch (e) {}
      if (!retAddr) return;
      var key = retAddr.toString();
      if (armedRet[key]) return;
      armedRet[key] = 1;
      try {
        Interceptor.attach(retAddr, {
          onEnter: function () {
            var fp = null;
            try { fp = this.context.x0; } catch (e) {}
            if (!fp || fp.isNull()) return;
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
            send({ ev: 'ret_cap', at: describe(retAddr), fp: fpk, fd: fd,
                   bt: bt, fpw: frameWalk(this.context) });
          }
        });
      } catch (e) { send({ ev: 'ret_arm_err', e: String(e) }); }
    }
  });
});

['read', 'pread', 'pread64'].forEach(function (sym) {
  var p = null;
  try { p = Module.getGlobalExportByName(sym); } catch (e) {}
  if (!p) return;
  Interceptor.attach(p, {
    onEnter: function (a) { this.fd = a[0].toInt32(); this.buf = a[1]; },
    onLeave: function (ret) {
      var fd = this.fd;
      if (!fdMap[fd]) return;
      var got = ret.toInt32();
      if (got < 4) return;
      var h = '';
      try {
        var b = new Uint8Array(this.buf.readByteArray(Math.min(got, 24)));
        for (var i = 0; i < b.length; i++) h += ('0' + b[i].toString(16)).slice(-2);
      } catch (e) { return; }
      send({ ev: 'ihi_read', via: sym, got: got, head: h });
    }
  });
});

try {
  var fp2 = Module.getGlobalExportByName('fread');
  var filenoF = new NativeFunction(Module.getGlobalExportByName('fileno'), 'int', ['pointer']);
  Interceptor.attach(fp2, {
    onEnter: function (a) {
      this.buf = a[0]; this.sz = a[1].toInt32();
      this.fp = a[3].toString();
      this.fd = -1;
      try { this.fd = filenoF(a[3]); } catch (e) {}
    },
    onLeave: function (ret) {
      var k = this.fp;
      var fd = this.fd;
      if (!fpMap[k] && !fdMap[fd]) return;
      var items = ret.toInt32();
      if (items <= 0) return;
      var got = items * (this.sz || 1);
      var h = '';
      try {
        var b = new Uint8Array(this.buf.readByteArray(Math.min(got, 24)));
        for (var i = 0; i < b.length; i++) h += ('0' + b[i].toString(16)).slice(-2);
      } catch (e) {}
      var bt = [];
      try {
        var frames = Thread.backtrace(this.context, Backtracer.ACCURATE);
        for (var i = 0; i < Math.min(frames.length, 6); i++) bt.push(describe(frames[i]));
      } catch (e) {}
      send({ ev: 'ihi_fread', got: got, head: h, bt: bt });
    }
  });
} catch (e) { send({ ev: 'fread_hook_err', e: String(e) }); }

send({ ev: 'v14_ready' });
