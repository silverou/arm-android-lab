'use strict';
/*
 * Sniffer v15: capture the LIVE caller code after the .ihi loader returns.
 *
 * Proven: loader @ libcocos2dlua+0x1492bdc freads the full file, returns
 * Data{ptr,size=0xC0} containing our PLAIN lua; caller resumes at
 * libcocos2dlua+0x1492490. Offline bss_code.bin has stale/encrypted bytes
 * there, so this probe streams the LIVE 0x1000-byte window as hex.
 *
 * Arm lazily at the first .ihi fopen (module + decrypted text exist by then).
 * Light: only hex send()s, no file IO inside hooks.
 */
var MODRE = /libcocos2dlua/;
var armed = false;
var enterIhi = 0;
var fpMap = {};
var fdMap = {};
var sentWin = {};

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

function sendWindow(m, rva, len, label) {
  var key = label + '|' + rva;
  if (sentWin[key]) return;
  sentWin[key] = 1;
  try {
    var b = new Uint8Array(m.base.add(rva).readByteArray(len));
    var h = '';
    for (var i = 0; i < b.length; i++) h += ('0' + b[i].toString(16)).slice(-2);
    for (var off = 0; off < h.length; off += 3000) {
      send({ ev: 'win', label: label, rva: '0x' + rva.toString(16),
             len: len, seg: off / 3000, hex: h.slice(off, off + 3000) });
    }
  } catch (e) {
    send({ ev: 'win_err', label: label, e: String(e) });
  }
}

function armLoader(m) {
  if (armed) return;
  armed = true;
  try {
    Interceptor.attach(m.base.add(0x1492bdc), {
      onEnter: function (a) {
        var o = { ev: 'loader_enter', x0: a[0].toString(), x1: a[1].toString(),
                  ret: describe(this.returnAddress), t: Date.now() };
        try {
          var s = a[0].readCString();
          if (s) o.str0 = s.slice(0, 160);
        } catch (e) {}
        try { o.str1 = a[1].readCString(); } catch (e) {}
        send(o);
        // caller function region just before + around the call site
        sendWindow(m, 0x1492300, 0x1000, 'caller_entry');
      }
    });
    // success return site: caller resumes at 0x1492490
    Interceptor.attach(m.base.add(0x1492e40), {
      onEnter: function () {
        var o = { ev: 'loader_ret', t: Date.now() };
        try { o.x0 = this.context.x0.toString(); } catch (e) {}
        try {
          var d = this.context.x0;
          if (d && !d.isNull()) {
            o.dptr = d.readPointer().toString();
            o.dsize = d.add(8).readPointer().toString();
            var sz = d.add(8).readPointer().toInt32();
            if (sz > 0 && sz < 4096) {
              var hd = new Uint8Array(d.readPointer().readByteArray(Math.min(sz, 32)));
              var hh = '';
              for (var i = 0; i < hd.length; i++) hh += ('0' + hd[i].toString(16)).slice(-2);
              o.dhead = hh;
            }
          }
        } catch (e) {}
        send(o);
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
      var ret = describe(this.returnAddress);
      var m = findMod();
      if (m && !armed) armLoader(m);
      // Map FILE* -> path at this call's return, but only arm once per site.
      var retAddr = null;
      try { retAddr = this.returnAddress; } catch (e) {}
      if (retAddr) {
        var k = retAddr.toString();
        if (!fpMap['__armed_' + k]) {
          fpMap['__armed_' + k] = 1;
          try {
            var fpk = path;
            Interceptor.attach(retAddr, {
              onEnter: function () {
                var fp = null;
                try { fp = this.context.x0; } catch (e) {}
                if (!fp || fp.isNull()) return;
                var f = fp.toString();
                fpMap[f] = fpk;
                var fd = -1;
                try {
                  var fileno = new NativeFunction(Module.getGlobalExportByName('fileno'), 'int', ['pointer']);
                  fd = fileno(fp);
                } catch (e) {}
                if (fd >= 0) fdMap[fd] = fpk;
                send({ ev: 'ret_cap', at: describe(retAddr), fp: f, fd: fd });
              }
            });
          } catch (e) { send({ ev: 'ret_arm_err', e: String(e) }); }
        }
      }
      send({ ev: 'fopen_ihi', via: sym, n: enterIhi, p: path.slice(0, 140), ret: ret });
    }
  });
});

var filenoF = null;
try { filenoF = new NativeFunction(Module.getGlobalExportByName('fileno'), 'int', ['pointer']); } catch (e) {}

try {
  var fr = Module.getGlobalExportByName('fread');
  Interceptor.attach(fr, {
    onEnter: function (a) {
      this.buf = a[0]; this.sz = a[1].toInt32();
      this.fp = a[3].toString();
      this.match = fpMap[this.fp] || null;
    },
    onLeave: function (ret) {
      if (!this.match) return;
      var items = ret.toInt32();
      if (items <= 0) return;
      var got = items * (this.sz || 1);
      var h = '';
      try {
        var b = new Uint8Array(this.buf.readByteArray(Math.min(got, 16)));
        for (var i = 0; i < b.length; i++) h += ('0' + b[i].toString(16)).slice(-2);
      } catch (e) {}
      send({ ev: 'ihi_fread', got: got, head: h });
    }
  });
} catch (e) { send({ ev: 'fread_hook_err', e: String(e) }); }

send({ ev: 'v15_ready' });
