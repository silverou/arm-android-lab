'use strict';
/*
 * Sniffer v11: hook the .ihi loader entry (libcocos2dlua RVA 0x1492bdc)
 * to capture its CALLER via LR (x30) — static scan found no direct bl
 * callers, so it is reached via indirect/virtual dispatch (blr).
 *
 * Also hook helper 0x1498374 (called with the path Data before return).
 * Emits module+RVA of caller for offline disassembly.
 */
var seen = {};
var lanes = [];
var errs = [];
var MODRE = /libcocos2dlua/;

function hex(b) {
  var s = '';
  for (var i = 0; i < b.length; i++) s += ('0' + b[i].toString(16)).slice(-2);
  return s;
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

function hookEntry(name, rva, max) {
  var m = findMod();
  if (!m) { send({ ev: 'sniff_no_module', name: name }); return false; }
  var addr = m.base.add(rva);
  try {
    Interceptor.attach(addr, {
      onEnter: function (a) {
        var key = name + '|' + (this.returnAddress ? this.returnAddress.toString() : '?');
        if (seen[key]) return;
        seen[key] = 1;
        var o = { ev: 'sniff_entry', name: name, at: describe(addr),
                  caller: describe(this.returnAddress),
                  x0: a[0].toString(), x1: a[1].toString(),
                  x2: a[2].toString(), x8: a[8].toString(),
                  t: Date.now() };
        try { o.lr = describe(this.context.lr); } catch (e) {}
        try { o.pc = describe(this.context.pc); } catch (e) {}
        // x1 often a std::string/Data: try read printable
        try {
          var s = a[1].readCString();
          if (s && /^[\x20-\x7e\/\.]{3,140}$/.test(s)) o.str1 = s;
        } catch (e) {}
        send(o);
      }
    });
    lanes.push(name);
    return true;
  } catch (e) {
    errs.push(name + ':' + e);
    send({ ev: 'sniff_attach_err', name: name, e: String(e) });
    return false;
  }
}

hookEntry('loader', 0x1492bdc);
hookEntry('helper1498374', 0x1498374);
hookEntry('openPath1492df0', 0x1492df0);

send({ ev: 'sniff_armed10', lanes: lanes, errs: errs });

setInterval(function () {
  send({ ev: 'sniff_stat', seen: Object.keys(seen).length, lanes: lanes.length, errs: errs.length });
}, 8000);
