'use strict';
/*
 * Dump every decrypted Lua chunk the engine loads (v3).
 *
 * v2 caught only 1 chunk: arming waited on a 500ms poll after cocos dlopen
 * (startup loads slip through), and only luaL_loadbuffer was hooked — the
 * engine may load via luaL_loadfile/luaL_loadstring instead.
 *
 * v3: attach the instant libcocos2dlua lands (dlopen observer), and hook
 * the whole load family: loadbuffer(x), loadfile(x), loadstring, lua_load
 * (log-only). loadfile reads the file straight from disk — if the shell
 * decrypts .ihi to disk first, we get both the dump and an on-disk copy.
 * Reports write failures explicitly.
 *
 * Output: /data/user/0/com.ihuman.pinyin/files/luadump_<n>.lua + map.
 */
var DIR = '/data/user/0/com.ihuman.pinyin/files/';
var fns = {};
function resolveGlobal(name) {
  try {
    var p = Module.getGlobalExportByName(name);
    if (p && !p.isNull()) return p;
  } catch (e) {}
  return null;
}

['fopen', 'fread', 'fwrite', 'fclose', 'fseek', 'ftell'].forEach(function (n) {
  var p = resolveGlobal(n);
  if (p) {
    var sig = {
      fopen: ['pointer', 'pointer', 'pointer'],
      fread: ['size_t', 'pointer', 'size_t', 'size_t', 'pointer'],
      fwrite: ['size_t', 'pointer', 'size_t', 'size_t', 'pointer'],
      fclose: ['int', 'pointer'],
      fseek: ['int', 'pointer', 'long', 'int'],
      ftell: ['long', 'pointer'],
    }[n];
    fns[n] = new NativeFunction(p, sig[0], sig.slice(1));
  }
});
var ok = !!(fns.fopen && fns.fread && fns.fwrite && fns.fclose);
send({ ev: 'dump_ready', ok: ok });

var n = 0, dup = 0, wfails = 0;
var seen = {};
var mapLines = [];

function writeFile(path, bytes, len) {
  var mode = Memory.allocUtf8String('wb');
  var fp = fns.fopen(Memory.allocUtf8String(path), mode);
  if (fp.isNull()) return false;
  var buf = Memory.alloc(len);
  buf.writeByteArray(bytes);
  fns.fwrite(buf, 1, len, fp);
  fns.fclose(fp);
  return true;
}

function readFile(path, maxLen) {
  var fp = fns.fopen(Memory.allocUtf8String(path), Memory.allocUtf8String('rb'));
  if (fp.isNull()) return null;
  fns.fseek(fp, 0, 2);
  var sz = fns.ftell(fp);
  fns.fseek(fp, 0, 0);
  if (sz <= 0 || sz > maxLen) { fns.fclose(fp); return null; }
  var buf = Memory.alloc(sz);
  var got = fns.fread(buf, 1, sz, fp);
  fns.fclose(fp);
  if (got !== sz) return null;
  return { bytes: new Uint8Array(buf.readByteArray(sz)), size: sz };
}

function sanitize(s) {
  s = String(s || '');
  return s.replace(/[^A-Za-z0-9_.\-\/]/g, '_').replace(/\//g, '__').slice(0, 120);
}

function flushMap() {
  if (!mapLines.length) return;
  var txt = mapLines.join('\n') + '\n';
  mapLines = [];
  var enc = [];
  for (var i = 0; i < txt.length; i++) enc.push(txt.charCodeAt(i) & 0xff);
  writeFile(DIR + 'luadump_map.txt', enc, enc.length);
}

function harvest(bufPtr, size, name) {
  if (!ok || size < 16 || size > 32 * 1024 * 1024) return;
  try {
    var head = new Uint8Array(bufPtr.readByteArray(16));
    var key = head.join(',') + '|' + size;
    if (seen[key]) { dup++; return; }
    seen[key] = 1;
    var bytes = new Uint8Array(bufPtr.readByteArray(size));
    n++;
    var fn = 'luadump_' + n + '.lua';
    if (writeFile(DIR + fn, bytes, size)) {
      mapLines.push(fn + '\t' + sanitize(name));
      flushMap();
      if (n === 1 || n % 25 === 0) send({ ev: 'dump_stat', files: n, dup: dup, wfails: wfails });
    } else {
      wfails++;
      send({ ev: 'dump_write_fail', file: fn, name: sanitize(name), wfails: wfails });
    }
  } catch (e) {
    send({ ev: 'dump_err', e: String(e) });
  }
}

var hooked = {};
function attach(p, label, kind) {
  var addr = p.toString();
  if (hooked[addr]) return false;
  hooked[addr] = 1;
  if (kind === 'file') {
    Interceptor.attach(p, {
      onEnter: function (a) {
        try {
          var path = a[1].readCString();
          var r = readFile(path, 32 * 1024 * 1024);
          if (r) {
            var key2 = path;
            if (seen[key2]) { dup++; return; }
            seen[key2] = 1;
            n++;
            var fn = 'luadump_' + n + '.lua';
            if (writeFile(DIR + fn, r.bytes, r.size)) {
              mapLines.push(fn + '\t' + sanitize(path));
              flushMap();
              if (n === 1 || n % 25 === 0) send({ ev: 'dump_stat', files: n, dup: dup, via: 'loadfile' });
            } else {
              wfails++;
              send({ ev: 'dump_write_fail', file: fn, name: sanitize(path) });
            }
          } else {
            send({ ev: 'dump_loadfile_miss', path: sanitize(path) });
          }
        } catch (e) {}
      }
    });
  } else if (kind === 'string') {
    Interceptor.attach(p, {
      onEnter: function (a) {
        try {
          var s = a[1].readCString();
          if (s && s.length >= 16) {
            var enc = [];
            for (var i = 0; i < s.length; i++) enc.push(s.charCodeAt(i) & 0xff);
            harvest(Memory.allocUtf8String(s), enc.length, 'loadstring');
          }
        } catch (e) {}
      }
    });
  } else if (kind === 'load') {
    Interceptor.attach(p, {
      onEnter: function (a) {
        try {
          var nm = '';
          try { nm = a[3].readCString(); } catch (e) {}
          send({ ev: 'dump_lua_load', name: sanitize(nm) });
        } catch (e) {}
      }
    });
  } else {
    // loadbuffer / loadbufferx: (L, buff, sz, name)
    Interceptor.attach(p, {
      onEnter: function (a) {
        try {
          var size = a[2].toInt32();
          var name = '';
          try { name = a[3].readCString(); } catch (e) {}
          harvest(a[1], size, name);
        } catch (e2) {}
      }
    });
  }
  send({ ev: 'dump_hook', sym: label, kind: kind, at: addr });
  return true;
}

function armModule(m) {
  if (!ok || !m) return 0;
  var got = 0;
  var names = ['luaL_loadbuffer', 'luaL_loadbufferx', 'luaL_loadfile', 'luaL_loadfilex', 'luaL_loadstring', 'lua_load'];
  names.forEach(function (nm) {
    var p = null;
    try { p = m.findExportByName(nm); } catch (e) {}
    if (p && !p.isNull()) {
      var kind = /loadfile/.test(nm) ? 'file' : (nm === 'luaL_loadstring' ? 'string' : (nm === 'lua_load' ? 'load' : 'buf'));
      if (attach(p, m.name + '!' + nm, kind)) got++;
    }
  });
  return got;
}

var ARMED = 0;
var armedAll = false;
function armAll() {
  if (!ok || armedAll) return;
  var got = ARMED;
  // global exports first
  ['luaL_loadbuffer', 'luaL_loadbufferx', 'luaL_loadfile', 'luaL_loadfilex', 'luaL_loadstring', 'lua_load'].forEach(function (nm) {
    var p = resolveGlobal(nm);
    if (p) {
      var kind = /loadfile/.test(nm) ? 'file' : (nm === 'luaL_loadstring' ? 'string' : (nm === 'lua_load' ? 'load' : 'buf'));
      if (attach(p, nm, kind)) got++;
    }
  });
  // per-module symbol walk (static links) — heavy; only until armed
  if (got < 4) {
    try {
      Process.enumerateModules().forEach(function (m) {
        if (!/cocos|lua|ihuman/i.test(m.name)) return;
        var syms;
        try { syms = m.enumerateSymbols(); } catch (e) { return; }
        syms.forEach(function (s) {
          if (s.type !== 'function') return;
          var nm = s.name || '';
          if (/^luaL_loadbufferx?$/.test(nm)) { if (attach(s.address, m.name + '!' + nm, 'buf')) got++; }
          else if (/^luaL_loadfilex?$/.test(nm)) { if (attach(s.address, m.name + '!' + nm, 'file')) got++; }
          else if (nm === 'luaL_loadstring') { if (attach(s.address, m.name + '!' + nm, 'string')) got++; }
          else if (nm === 'lua_load') { if (attach(s.address, m.name + '!' + nm, 'load')) got++; }
        });
      });
    } catch (e) {}
  }
  if (got > ARMED) {
    ARMED = got;
    send({ ev: 'dump_armed', count: ARMED });
    if (ARMED >= 4) armedAll = true;   // stop all further polling work
  }
}

// instant attach the moment cocos lands (scripts load right after dlopen)
['android_dlopen_ext', 'dlopen', '__loader_dlopen', '__loader_android_dlopen_ext'].forEach(function (sym) {
  var p = resolveGlobal(sym);
  if (!p) return;
  Interceptor.attach(p, {
    onEnter: function (a) {
      try { this.pth = a[0].readCString(); } catch (e) { this.pth = ''; }
    },
    onLeave: function () {
      if (this.pth && /cocos2dlua/.test(this.pth)) {
        send({ ev: 'dump_dl', p: this.pth });
        armAll();
      }
    }
  });
});

armAll();
var tries = 0;
var armTimer = setInterval(function () {
  tries++;
  if (armedAll || tries > 40) { clearInterval(armTimer); return; }
  armAll();
}, 250);
setInterval(function () {
  send({ ev: 'dump_stat', files: n, dup: dup, wfails: wfails, armed: ARMED });
}, 10000);
