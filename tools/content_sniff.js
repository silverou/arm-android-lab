'use strict';
/*
 * Sniffer v18: catch the post-loader validation statically.
 *
 * Facts: loader returns Data{plain lua,0xc0}, LR=0x1492490 -> b 0x1168a48
 * (obfuscated island). Stalker missed the fast path; island bl targets are
 * statically known. This probe:
 *   1) hooks the 5 known island bl targets (arg dump + backtrace)
 *   2) hooks libc memcmp/strcmp/strncmp/strstr: when the CALLER is inside
 *      libcocos2dlua, dump both buffers' heads + backtrace — catches any
 *      magic ("42a64166") / format comparison on our data
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

function arm(m) {
  if (armed) return;
  armed = true;

  // island bl targets
  [0x10f9d98, 0x110d7d8, 0x12bb618].forEach(function (rva) {
    try {
      Interceptor.attach(m.base.add(rva), {
        onEnter: function (a) {
          send({ ev: 'fn_call', at: '0x' + rva.toString(16),
                 x0: a[0].toString(), x1: a[1].toString(), x2: a[2].toString(),
                 h0: hexHead(a[0], 16), h1: (a[1] && !a[1].isNull()) ? hexHead(a[1], 16) : null,
                 bt: bt.call(this) });
        }
      });
    } catch (e) { send({ ev: 'fn_arm_err', at: '0x' + rva.toString(16), e: String(e) }); }
  });

  // loader return site for orientation
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
      }
    });
  } catch (e) { send({ ev: 'arm_err', pad: 'ret', e: String(e) }); }

  send({ ev: 'v18_armed' });
}

function hookCmp(sym, nargs) {
  var p = null;
  try { p = Module.getGlobalExportByName(sym); } catch (e) {}
  if (!p) return;
  try {
    Interceptor.attach(p, {
      onEnter: function (a) {
        this.inCocos = false;
        try {
          var lr = this.returnAddress;
          var mm = Process.findModuleByAddress(lr);
          if (mm && MODRE.test(mm.name)) this.inCocos = true;
        } catch (e) {}
        if (!this.inCocos) return;
        if (cmpN > 60) return;
        this.a0 = a[0]; this.a1 = a[1];
        this.n = nargs === 3 ? a[2].toInt32() : -1;
      },
      onLeave: function (ret) {
        if (!this.inCocos) return;
        cmpN++;
        send({ ev: 'cmp', sym: sym, ret: ret.toInt32(), n: this.n,
               h0: hexHead(this.a0, 24), h1: (this.a1 && !this.a1.isNull()) ? hexHead(this.a1, 24) : null,
               caller: describe(this.returnAddress), t: Date.now() });
      }
    });
    lanes.push(sym);
  } catch (e) {}
}

var lanes = [];

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

hookCmp('memcmp', 3);
hookCmp('strcmp', 2);
hookCmp('strncmp', 3);
hookCmp('strstr', 2);

send({ ev: 'v18_ready', cmp_lanes: lanes });
