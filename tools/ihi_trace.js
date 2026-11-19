'use strict';
/*
 * .ihi loader call-chain tracer.
 *
 * Evidence so far: engine fopens our override file (fd valid) then silently
 * falls back to APK assets — the decrypt/undump gate lives somewhere in
 * libcocos2dlua internals (static Lua copy, not hookable by symbol). This
 * probe takes CALL STACKS at the two observable boundaries:
 *   1) fopen of any *.ihi path (top caller frames -> loader RVA)
 *   2) exported luaL_loadbuffer calls made by the ENGINE (not our injects)
 * Frames are reported as module + RVA so they map onto our runtime image
 * dumps for static disassembly regardless of ASLR.
 */
var TRACES = 0;
var MAX_TRACES = 6;
var ihiSeen = {};

function frameInfo() {
  var out = [];
  try {
    var addrs = Thread.backtrace(this.context, Backtracer.ACCURATE);
    for (var i = 0; i < addrs.length && i < 10; i++) {
      var a = addrs[i];
      var rec = a.toString();
      try {
        var m = Process.findModuleByAddress(a);
        if (m) rec = m.name + '+0x' + a.sub(m.base).toString(16) + ' (' + a.toString() + ')';
      } catch (e) {}
      out.push(rec);
    }
  } catch (e) {
    try {
      var addrs2 = Thread.backtrace(this.context, Backtracer.FUZZY);
      for (var i = 0; i < addrs2.length && i < 10; i++) out.push(addrs2[i].toString());
    } catch (e2) { out.push('bt_err:' + e2); }
  }
  return out;
}

// 1) fopen backtrace for .ihi
var fopen = null;
try { fopen = Module.getGlobalExportByName('fopen'); } catch (e) {}
if (fopen) {
  Interceptor.attach(fopen, {
    onEnter: function (a) {
      try {
        var path = a[0].readCString();
        if (/\.ihi$/.test(path) && TRACES < MAX_TRACES && !ihiSeen[path]) {
          ihiSeen[path] = 1;
          TRACES++;
          var bt = frameInfo.call(this);
          send({ ev: 'ihi_open', p: path.slice(0, 130), bt: bt });
        }
      } catch (e) {}
    }
  });
  send({ ev: 'ihi_trace_armed', sym: 'fopen' });
} else {
  send({ ev: 'ihi_trace_miss', sym: 'fopen' });
}

// 2) engine-side loadbuffer backtrace (skip our own injected chunks by name)
var lb = null;
try { lb = Module.getGlobalExportByName('luaL_loadbuffer'); } catch (e) {}
if (lb) {
  Interceptor.attach(lb, {
    onEnter: function (a) {
      if (TRACES >= MAX_TRACES + 3) return;
      try {
        var nm = a[3].readCString();
        if (/frida|inject|plant|probe|bc$/.test(nm)) return;
        TRACES++;
        var bt = frameInfo.call(this);
        var sz = a[2].toInt32();
        send({ ev: 'ihi_loadbuffer', name: String(nm).slice(0, 100), sz: sz, bt: bt });
      } catch (e) {}
    }
  });
  send({ ev: 'ihi_trace_armed', sym: 'luaL_loadbuffer' });
}
