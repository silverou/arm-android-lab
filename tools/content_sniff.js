'use strict';
/*
 * Sniffer v19: cmp hooks installed ONLY after loader_ret.
 *
 * v18 lesson: memcmp/strcmp hooks armed at spawn -> shell thread gate
 * 0xdead5014/5019 kills the process before main.ihi loads (2/2 runs).
 * This version: at spawn only fopen tracking + loader_ret site; the
 * moment loader returns our Data, install memcmp/strcmp/strncmp/strstr
 * hooks (caller-filtered to libcocos2dlua) for the next 3 seconds to
 * catch the validation step.
 */
var MODRE = /libcocos2dlua/;
var armed = false;
var enterIhi = 0;
var cmpN = 0;

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

function hexHead(p, n) {
  try {
    var b = new Uint8Array(p.readByteArray(n));
    var h = '';
    for (var i = 0; i < b.length; i++) h += ('0' + b[i].toString(16)).slice(-2);
    return h;
  } catch (e) { return 'err'; }
}

function bt() {
  var out = [];
  try {
    var frames = Thread.backtrace(this.context, Backtracer.ACCURATE);
    for (var i = 0; i < Math.min(frames.length, 8); i++) out.push(describe(frames[i]));
  } catch (e) {}
  return out;
}

function installCmpHooks() {
  var lanes = [];
  var EMPTY = Memory.allocUtf8String('');
  function makeHandler(sym, nargs) {
    return {
      onEnter: function (a) {
        // NULL-fix unconditional — gate crashes on strncmp(NULL,...)
        if (a[0].isNull()) { a[0] = EMPTY; send({ ev: 'cmp_nullfix', sym: sym, arg: 0,
            caller: describe(this.returnAddress) }); }
        if (nargs >= 2 && a[1].isNull()) { a[1] = EMPTY; send({ ev: 'cmp_nullfix', sym: sym, arg: 1,
            caller: describe(this.returnAddress) }); }
        // report only interesting callers: cocos module or anon (shell-decrypted) pages
        this.report = false;
        try {
          var mm = Process.findModuleByAddress(this.returnAddress);
          this.report = !mm || MODRE.test(mm.name);
        } catch (e) { this.report = true; }
        this.a0 = a[0]; this.a1 = a[1];
        this.n = nargs >= 3 ? a[2].toInt32() : -1;
      },
      onLeave: function (ret) {
        if (!this.report) return;
        if (cmpN > 60) return;
        cmpN++;
        send({ ev: 'cmp', sym: sym, ret: ret.toInt32(), n: this.n,
               h0: hexHead(this.a0, 24),
               h1: (this.a1 && !this.a1.isNull()) ? hexHead(this.a1, 24) : null,
               caller: describe(this.returnAddress), t: Date.now() });
      }
    };
  }
  function hookOne(sym, nargs) {
    var p = null;
    try { p = Module.getGlobalExportByName(sym); } catch (e) {}
    if (!p) { send({ ev: 'cmp_miss', sym: sym }); return; }
    try {
      Interceptor.attach(p, makeHandler(sym, nargs));
      lanes.push(sym);
    } catch (e) { send({ ev: 'cmp_err', sym: sym, e: String(e) }); }
  }
  // the shell code calls __strncmp_aarch64 directly (crash pc), hook both
  hookOne('strncmp', 3);
  hookOne('__strncmp_aarch64', 3);
  hookOne('strcmp', 2);
  hookOne('__strcmp_aarch64', 2);
  hookOne('memcmp', 3);
  send({ ev: 'cmp_installed', lanes: lanes });
}

function arm(m) {
  if (armed) return;
  armed = true;
  try {
    Interceptor.attach(m.base.add(0x1492e40), {
      onEnter: function () {
        var o = { ev: 'loader_ret', t: Date.now() };
        try {
          var d = this.context.x0;
          if (d && !d.isNull()) {
            o.dsize = d.add(8).readPointer().toString();
            var sz = d.add(8).readPointer().toInt32();
            if (sz > 0 && sz < 4096) o.dhead = hexHead(d.readPointer(), 16);
          }
        } catch (e) {}
        try { o.lr = describe(this.context.lr); } catch (e) {}
        send(o);
        // LIVE dump of the gate region: offline bss_code.bin has ciphertext
        // at 0x1bf5244+ (two strncmp sites decrypt only at runtime)
        try {
          var win = new Uint8Array(m.base.add(0x1bf5100).readByteArray(0x500));
          var h = '';
          for (var i = 0; i < win.length; i++) h += ('0' + win[i].toString(16)).slice(-2);
          for (var off = 0; off < h.length; off += 3000) {
            send({ ev: 'gate_win', seg: off / 3000, hex: h.slice(off, off + 3000) });
          }
        } catch (e) { send({ ev: 'gate_win_err', e: String(e) }); }
        // validation happens right after return — install cmp hooks now
        installCmpHooks();
        // auto-disable heavy reporting after 3s
        setTimeout(function () { cmpN = 1000; }, 3000);
      }
    });
    // island fns (cheap, only these three)
    [0x10f9d98, 0x110d7d8, 0x12bb618].forEach(function (rva) {
      try {
        Interceptor.attach(m.base.add(rva), {
          onEnter: function (a) {
            send({ ev: 'fn_call', at: '0x' + rva.toString(16),
                   x0: a[0].toString(), x1: a[1].toString(), x2: a[2].toString(),
                   h0: hexHead(a[0], 16), bt: bt.call(this) });
          }
        });
      } catch (e) {}
    });
    send({ ev: 'v19_armed' });
  } catch (e) { send({ ev: 'arm_err', e: String(e) }); }
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
      var m = findMod();
      if (m && !armed) arm(m);
      send({ ev: 'fopen_ihi', via: sym, n: enterIhi, p: path.slice(0, 140) });
    }
  });
});

send({ ev: 'v19_ready' });
