'use strict';
/*
 * Dump every decrypted Lua chunk the engine loads.
 * Hooks luaL_loadbuffer & friends; writes each chunk to the app's files dir
 * as /data/user/0/com.ihuman.pinyin/files/luadump_<n>.lua plus an index file
 * mapping n -> original chunk name.
 */
var DIR = '/data/user/0/com.ihuman.pinyin/files/';
var bits = {};
function resolve(name) {
  try {
    var p = Module.getGlobalExportByName(name);
    if (p && !p.isNull()) return p;
  } catch (e) {}
  try {
    var mods = Process.enumerateModules();
    for (var i = 0; i < mods.length; i++) {
      try {
        var q = mods[i].findExportByName(name);
        if (q && !q.isNull()) return q;
      } catch (e2) {}
    }
  } catch (e3) {}
  return null;
}

var fns = {};
['fopen', 'fwrite', 'fclose'].forEach(function (n) {
  var p = resolve(n);
  if (p) fns[n] = new NativeFunction(p, 'pointer', n === 'fwrite' ? ['pointer', 'size_t', 'size_t', 'pointer'] : n === 'fclose' ? ['pointer'] : ['pointer', 'pointer']);
});
var ok = !!(fns.fopen && fns.fwrite && fns.fclose);
send({ ev: 'dump_ready', ok: ok });

var n = 0, dup = 0;
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

function sanitize(s) {
  s = String(s || '');
  return s.replace(/[^A-Za-z0-9_.\-\/]/g, '_').replace(/\//g, '__').slice(0, 120);
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
      if (mapLines.length >= 20) flushMap();
    }
  } catch (e) {
    send({ ev: 'dump_err', e: String(e) });
  }
}
function flushMap() {
  if (!mapLines.length) return;
  var txt = mapLines.join('\n') + '\n';
  mapLines = [];
  var enc = [];
  for (var i = 0; i < txt.length; i++) enc.push(txt.charCodeAt(i) & 0xff);
  writeFile(DIR + 'luadump_map.txt', enc, enc.length);
}

function attach(p, label) {
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
  send({ ev: 'dump_hook', sym: label });
}

var armed = false;
function armAll() {
  if (armed) return;
  var got = 0;
  ['luaL_loadbuffer', 'luaL_loadbufferx'].forEach(function (nm) {
    var p = resolve(nm);
    if (p) { try { attach(p, nm); got++; } catch (e) {} }
  });
  armed = got > 0;
}
setInterval(armAll, 800);
setInterval(function () {
  send({ ev: 'dump_stat', files: n, dup: dup });
}, 10000);
