'use strict';
/*
 * Sniffer v12: poll for libcocos2dlua, then hook loader entry RVA 0x1492bdc
 * (+ helper 0x1498374, consume 0x1492df0) to capture the CALLER via LR.
 * v11 raced module load (sniff_no_module). Wait until module + code decrypted.
 */
var seen = {};
var lanes = [];
var errs = [];
var MODRE = /libcocos2dlua/;

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

function hookEntry(m, name, rva) {
  var addr = m.base.add(rva);
  try {
    Interceptor.attach(addr, {
      onEnter: function (a) {
        var caller = '?';
        try { caller = describe(this.returnAddress); } catch (e) {}
        var key = name + '|' + caller;
        var o = { ev: 'sniff_entry', name: name, at: describe(addr), caller: caller,
                  x0: a[0].toString(), x1: a[1].toString(), t: Date.now() };
        try { o.str1 = a[1].readCString(); } catch (e) {}
        if (seen[key] >= 3) return;
        seen[key] = (seen[key] || 0) + 1;
        send(o);
      }
    });
    lanes.push(name);
  } catch (e) {
    errs.push(name + ':' + e);
    send({ ev: 'sniff_attach_err', name: name, e: String(e) });
  }
}

var tries = 0;
var poll = setInterval(function () {
  tries++;
  var m = findMod();
  if (m) {
    clearInterval(poll);
    // wait for packer to decrypt the hidden .text
    setTimeout(function () {
      // sanity: head of loader should be non-zero code
      try {
        var head = new Uint8Array(m.base.add(0x1492bdc).readByteArray(8));
        var hx = '';
        for (var i = 0; i < head.length; i++) hx += ('0' + head[i].toString(16)).slice(-2);
        send({ ev: 'sniff_loader_head', head: hx });
      } catch (e) { send({ ev: 'sniff_head_err', e: String(e) }); }
      hookEntry(m, 'loader', 0x1492bdc);
      hookEntry(m, 'helper1498374', 0x1498374);
      hookEntry(m, 'consume1492df0', 0x1492df0);
      send({ ev: 'sniff_armed11', lanes: lanes, errs: errs, after_ms: tries * 100 });
    }, 6000);
  } else if (tries > 300) {
    clearInterval(poll);
    send({ ev: 'sniff_timeout' });
  }
}, 100);

setInterval(function () {
  send({ ev: 'sniff_stat', seen: Object.keys(seen).length, lanes: lanes.length, errs: errs.length });
}, 8000);
