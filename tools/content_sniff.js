'use strict';
/*
 * Sniffer v16: Stalker short-trace after the .ihi loader returns.
 *
 * Established: loader @ libcocos2dlua+0x1492bdc reads FULL file (no magic
 * check), returns Data{ptr,size} of our PLAIN lua. Resume address
 * 0x1492490 is a branch island -> 0x1168a48 (OLLVM-obfuscated region).
 * Static analysis stalls; this probe Stalker-traces the current thread for
 * ~600ms after first resume, collecting call/ret targets, then unfollows.
 * Also logs registers at the landing pad.
 *
 * Light: send() only, no file IO inside hooks.
 */
var MODRE = /libcocos2dlua/;
var armed = false;
var enterIhi = 0;
var tracing = false;
var fpMap = {};

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

function regs(ctx) {
  var o = {};
  ['x0','x1','x2','x3','x4','x8','x19','x20','x21','x22','x29','lr'].forEach(function (r) {
    try { o[r] = ctx[r].toString(); } catch (e) {}
  });
  return o;
}

function startTrace() {
  if (tracing) return;
  tracing = true;
  var tid = Process.id; // follow main thread; loader runs on it (bt showed art frames)
  // Actually follow the CURRENT thread (the one resuming)
  try {
    var summary = {};
    var blocks = [];
    Stalker.follow(Process.getCurrentThreadId(), {
      events: { call: true, ret: true, exec: false, block: false, compile: false },
      onCallSummary: function (s) {
        for (var k in s) summary[k] = (summary[k] || 0) + s[k];
      },
      onReceive: function (raw) {
        if (blocks.length < 4) blocks.push(raw.slice(0, 64));
      }
    });
    send({ ev: 'stalker_on', tid: Process.getCurrentThreadId() });
    setTimeout(function () {
      try { Stalker.unfollow(); } catch (e) {}
      setTimeout(function () {
        try { Stalker.garbageCollect(); } catch (e) {}
        var out = [];
        for (var k in summary) out.push({ a: describe(k), n: summary[k] });
        out.sort(function (x, y) { return y.n - x.n; });
        send({ ev: 'stalker_summary', calls: out.slice(0, 60), total: out.length });
        tracing = false;
      }, 200);
    }, 600);
  } catch (e) {
    send({ ev: 'stalker_err', e: String(e) });
    tracing = false;
  }
}

function arm(m) {
  if (armed) return;
  armed = true;

  // landing pad: resume address after loader
  try {
    Interceptor.attach(m.base.add(0x1492490), {
      onEnter: function () {
        var o = { ev: 'landing', at: '0x1492490', r: regs(this.context), t: Date.now() };
        send(o);
        startTrace();
      }
    });
  } catch (e) { send({ ev: 'arm_err', pad: '1492490', e: String(e) }); }

  // loader return site (Data in flight)
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
        send(o);
      }
    });
  } catch (e) { send({ ev: 'arm_err', pad: 'ret', e: String(e) }); }

  // island bl targets seen statically
  [0x1168c7c, 0x1168de4, 0x1169148].forEach(function (rva) {
    try {
      Interceptor.attach(m.base.add(rva), {
        onEnter: function (a) {
          send({ ev: 'island_call', at: '0x' + rva.toString(16),
                 x0: a[0].toString(), x1: a[1].toString(), x2: a[2].toString() });
        }
      });
    } catch (e) {}
  });

  send({ ev: 'v16_armed' });
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

send({ ev: 'v16_ready' });
