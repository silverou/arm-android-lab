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

  // capture loader Data for later comparison
  var loaderDataPtr = null, loaderDataSize = -1;
  // gate hooks: export strncmp + bionic internal __strncmp_aarch64
  // (tombstone gave __strncmp_aarch64 = libc+0x49c80 for this build)
  var EMPTY = Memory.allocUtf8String('');
  var GATE2 = '3735336331373135'; // hex of "753c1715"

  function mkSnHandler(tag) {
    return {
      onEnter: function (a) {
        this.force = false;
        this.touched = false;
        try {
          var n = a[2].toInt32();
          var nullArg = a[0].isNull() || a[1].isNull();
          var c1 = (!a[1].isNull() && n <= 16) ? hexHead(a[1], Math.min(n, 8)) : null;
          var c0 = (!a[0].isNull() && n <= 16) ? hexHead(a[0], Math.min(n, 8)) : null;
          var gate2 = (n === 8) && ((c1 && c1.indexOf(GATE2) === 0) || (c0 && c0.indexOf(GATE2) === 0));
          if (nullArg || gate2) {
            this.touched = true;
            var o = { ev: 'sn_touch', tag: tag, n: n, nullArg: !!nullArg, gate2: !!gate2,
                      c0: c0, c1: c1, caller: describe(this.returnAddress) };
            if (gate2) {
              // field bytes (arg0 of strncmp) — decrypted already?
              try { o.f0_64 = hexHead(a[0], 64); } catch (e) { o.f0_64 = 'err'; }
              try { o.f1_64 = hexHead(a[1], 64); } catch (e) { o.f1_64 = 'err'; }
              try { o.f0s = a[0].readUtf8String(32); } catch (e) {}
              try { o.bt = bt.call(this); } catch (e) {}
            }
            send(o);
          }
          if (nullArg) {
            if (a[0].isNull()) a[0] = EMPTY;
            if (a[1].isNull()) a[1] = EMPTY;
          }
          if (gate2) this.force = true;
        } catch (e) {}
      },
      onLeave: function (ret) {
        if (!this.touched) return;
        var was = ret.toInt32();
        if (this.force) {
          ret.replace(ptr(0));
          send({ ev: 'sn_force0', tag: tag, was: was });
        } else {
          send({ ev: 'sn_ret', tag: tag, was: was });
        }
      }
    };
  }

  try {
    var sn = Module.getGlobalExportByName('strncmp');
    Interceptor.attach(sn, mkSnHandler('export'));
    send({ ev: 'sn_hook', tag: 'export', at: describe(sn) });
  } catch (e) { send({ ev: 'sn_hook_err', tag: 'export', e: String(e) }); }

  try {
    var libcMod = null;
    Process.enumerateModules().forEach(function (x) {
      if (!libcMod && /^libc\.so$/.test(x.name)) libcMod = x;
    });
    if (libcMod) {
      var internal = libcMod.base.add(0x49c80);
      Interceptor.attach(internal, mkSnHandler('internal'));
      send({ ev: 'sn_hook', tag: 'internal', at: describe(internal) });
    } else {
      send({ ev: 'sn_hook_err', tag: 'internal', e: 'libc.so not found' });
    }
  } catch (e) { send({ ev: 'sn_hook_err', tag: 'internal', e: String(e) }); }

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
