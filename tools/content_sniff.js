'use strict';
/*
 * Sniffer v23: intercept the REAL decrypt path.
 *
 * Gate analysis so far:
 *   loader fread -> Data{bytes} -> gate1 strncmp(data,"42a64166",8) at
 *   libcocos2dlua+0x1bf52b8 -> gate2 strncmp(field,"753c1715",8) at
 *   +0x1bf5398 (field NULL for our plain file -> decrypt failed upstream).
 * Trampoline analysis: FileUtils::decryptDataIfNeed -> real body 0x1113d90.
 *
 * This probe hooks the exported symbols (cold functions, safe at spawn):
 *   - _ZN7cocos2d9FileUtils17decryptDataIfNeedERNS_4DataERKSs
 *     onLeave: Data{ptr,size} = decrypted output -> head hex (SZAQ magic?)
 *   - _Z13xxtea_decryptPhjS_jPj  (data,len,key,keylen,retlen)
 *     -> capture key bytes + data head (this would be THE key)
 * Keep fopen_ihi/loader_ret for orientation.
 */
var MODRE = /libcocos2dlua/;
var armed = false;
var enterIhi = 0;
var sawN = 0;

function describe(addr) {
  var s = addr.toString();
  try {
    var m = Process.findModuleByAddress(addr);
    if (m) s = m.name + '+0x' + addr.sub(m.base).toString(16);
  } catch (e) {}
  return s;
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

function readStdString(p) {
  try {
    var cap = p.add(16).readU32();            // size (libc++ layout: ptr,size,cap|ssodata)
    var len = p.add(8).readU64().toNumber();
    if (cap <= 22) return p.readUtf8String(Math.min(Math.max(len, cap + 1), 128));
    var ptr = p.readPointer();
    return ptr.readUtf8String(Math.min(len, 200));
  } catch (e) { return null; }
}

function tryHook(name, handlers) {
  var p = null;
  try { p = Module.getGlobalExportByName(name); } catch (e) {}
  if (!p) { send({ ev: 'hook_miss', name: name }); return false; }
  try {
    Interceptor.attach(p, handlers);
    send({ ev: 'hooked', name: name, at: describe(p) });
    return true;
  } catch (e) {
    send({ ev: 'hook_err', name: name, e: String(e) });
    return false;
  }
}

// attaach by RVA when export is stripped by the packer
function attachRva(m, rva, handlers) {
  try {
    var addr = m.base.add(rva);
    Interceptor.attach(addr, handlers);
    send({ ev: 'hooked_rva', rva: '0x' + rva.toString(16), at: describe(addr) });
    return true;
  } catch (e) {
    send({ ev: 'hook_rva_err', rva: '0x' + rva.toString(16), e: String(e) });
    return false;
  }
}

function arm(m) {
  if (armed) return;
  armed = true;

  // real decrypt entry (cold): Data& in x0, const string& path in x1
  var ddnHandlers = {
    onEnter: function (a) {
      sawN++;
      if (sawN > 40) return;
      this.data = a[0];
      var o = { ev: 'ddn_enter', path: readStdString(a[1]), size: -1, head: null, t: Date.now() };
      try {
        o.size = this.data.add(8).readPointer().toInt32();
        o.head = hexHead(this.data.readPointer(), 16);
      } catch (e) {}
      send(o);
    },
    onLeave: function (ret) {
      try {
        var o = { ev: 'ddn_leave' };
        var ptr = this.data.readPointer();
        var size = this.data.add(8).readPointer().toInt32();
        o.size_after = size;
        o.head_after = hexHead(ptr, 24);
        o.is_szaq = o.head_after.indexOf('1b535a41') === 0;
        o.is_plain = o.head_after.indexOf('7072696e74') === 0;
        send(o);
      } catch (e) { send({ ev: 'ddn_leave_err', e: String(e) }); }
    }
  };
  if (!tryHook('_ZN7cocos2d9FileUtils17decryptDataIfNeedERNS_4DataERKSs', ddnHandlers)) {
    attachRva(m, 0x44660, ddnHandlers);
  }

  // xxtea_decrypt(data, len, key, keylen, retlen) — capture the key if used
  var xteaHandlers = {
    onEnter: function (a) {
      if (sawN > 60) return;
      var o = { ev: 'xxtea', dlen: a[1].toInt32(), klen: a[3].toInt32(),
                dhead: hexHead(a[0], 16),
                key: (a[3].toInt32() > 0 && a[3].toInt32() < 64) ? hexHead(a[2], a[3].toInt32()) : null,
                bt: bt.call(this) };
      send(o);
    }
  };
  if (!tryHook('_Z13xxtea_decryptPhjS_jPj', xteaHandlers)) {
    attachRva(m, 0xdea900, xteaHandlers);
  }

  // gate2 bypass experiment: force strncmp(field,"753c1715",8) == 0
  // gate2 sits at libcocos2dlua+0x1bf5394, return addr 0x1bf5398
  try {
    var sn = Module.getGlobalExportByName('strncmp');
    Interceptor.attach(sn, {
      onEnter: function (a) {
        this.isGate2 = false;
        try {
          var off = this.returnAddress.sub(m.base).toInt32();
          if (off === 0x1bf5398) {
            this.isGate2 = true;
            this.h0 = hexHead(a[0], 8);
            this.h1 = hexHead(a[1], 8);
          }
        } catch (e) {}
      },
      onLeave: function (ret) {
        if (!this.isGate2) return;
        send({ ev: 'gate2_force', was: ret.toInt32(), h0: this.h0, h1: this.h1 });
        ret.replace(ptr(0));
      }
    });
    send({ ev: 'gate2_hook', at: describe(sn) });
  } catch (e) { send({ ev: 'gate2_hook_err', e: String(e) }); }

  send({ ev: 'v23_armed' });
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
      var m = null;
      try {
        Process.enumerateModules().forEach(function (x) {
          if (!m && MODRE.test(x.name)) m = x;
        });
      } catch (e) {}
      // arm decrypt hooks lazily at first .ihi (module certainly loaded);
      // m unused by arm() but keep call site stable
      if (!armed) arm(m);
      send({ ev: 'fopen_ihi', via: sym, n: enterIhi, p: path.slice(0, 140) });
    }
  });
});

send({ ev: 'v23_ready' });
