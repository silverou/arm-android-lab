'use strict';
/*
 * Sniffer v17: Stalker-trace the thread right from loader_ret (0x1492e40).
 *
 * v16 lesson: cannot Interceptor.attach at resume pad 0x1492490 ("unable to
 * intercept"), so start Stalker at the loader epilogue instead — control
 * has not yet left the loader, so the whole post-return path
 * (0x1492490 -> obfuscated 0x1168a48 region) gets traced.
 *
 * Collect call/ret summary for 800ms, filter interesting frames.
 */
var MODRE = /libcocos2dlua/;
var armed = false;
var enterIhi = 0;
var tracing = false;

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

function startTrace() {
  if (tracing) return;
  tracing = true;
  var tid = Process.getCurrentThreadId();
  try {
    var summary = {};
    var execs = [];
    Stalker.follow(tid, {
      events: { call: true, ret: false, exec: false, block: false, compile: false },
      onCallSummary: function (s) {
        for (var k in s) summary[k] = (summary[k] || 0) + s[k];
      }
    });
    send({ ev: 'stalker_on', tid: tid });
    setTimeout(function () {
      try { Stalker.unfollow(tid); } catch (e) { send({ ev: 'stalker_unfollow_err', e: String(e) }); }
      setTimeout(function () {
        try { Stalker.garbageCollect(); } catch (e) {}
        var out = [];
        for (var k in summary) out.push({ a: describe(k), n: summary[k] });
        out.sort(function (x, y) { return y.n - x.n; });
        send({ ev: 'stalker_summary', total: out.length, calls: out.slice(0, 80) });
        tracing = false;
      }, 300);
    }, 800);
  } catch (e) {
    send({ ev: 'stalker_err', e: String(e) });
    tracing = false;
  }
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
            o.dptr = d.readPointer().toString();
            o.dsize = d.add(8).readPointer().toString();
            var sz = d.add(8).readPointer().toInt32();
            if (sz > 0 && sz < 4096) {
              var hd = new Uint8Array(d.readPointer().readByteArray(Math.min(sz, 16)));
              var hh = '';
              for (var i = 0; i < hd.length; i++) hh += ('0' + hd[i].toString(16)).slice(-2);
              o.dhead = hh;
            }
          }
        } catch (e) {}
        try { o.lr = describe(this.context.lr); } catch (e) {}
        send(o);
        startTrace();
      }
    });
  } catch (e) { send({ ev: 'arm_err', pad: 'ret', e: String(e) }); }

  // island bl sites (statically found): report if reached
  [{r: 0x1168c7c, t: 0x10f9d98}, {r: 0x1168de4, t: 0x110d7d8},
   {r: 0x1168eac, t: 0x110d7d8}, {r: 0x11690ac, t: 0x110d7d8},
   {r: 0x1169148, t: 0x12bb618}].forEach(function (c) {
    try {
      Interceptor.attach(m.base.add(c.r), {
        onEnter: function (a) {
          send({ ev: 'island_call', at: '0x' + c.r.toString(16),
                 tgt: '0x' + c.t.toString(16),
                 x0: a[0].toString(), x1: a[1].toString(), x2: a[2].toString() });
        }
      });
    } catch (e) { send({ ev: 'island_arm_err', at: '0x' + c.r.toString(16), e: String(e) }); }
  });

  send({ ev: 'v17_armed' });
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

send({ ev: 'v17_ready' });
