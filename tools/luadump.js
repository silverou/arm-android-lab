'use strict';
/*
 * Dump interesting literals out of Lua chunk loads. Chunks are often Lua
 * bytecode with embedded nulls, so read raw bytes and scan as latin1.
 * Captures: absolute URLs, plus any literal around "asset"/"resource"/".zip"
 * fragments so the runtime-built download template becomes visible.
 */
var seen = {};
var total = 0;
var CAP = 4000;
var hooked = {};

function harvest(txt, who) {
  var out = [];
  var reUrl = /https?:\/\/[A-Za-z0-9._~:/?#\[\]@!$&'()*+,;=%\-]{8,300}/g;
  var m;
  while ((m = reUrl.exec(txt))) {
    if (!seen[m[0]]) { seen[m[0]] = 1; out.push(m[0]); }
  }
  var reFrag = /[A-Za-z0-9._~:/?#\[\]@!$&'()*+,;=%\-]{0,60}(?:asset\/|resource|\.zip)[A-Za-z0-9._~:/?#\[\]@!$&'()*+,;=%\-]{0,80}/g;
  while ((m = reFrag.exec(txt))) {
    var s = m[0];
    if (s.length < 10) continue;
    if (!seen[s]) { seen[s] = 1; out.push(s); }
  }
  if (out.length) {
    total += out.length;
    send({ ev: 'lua_lit', who: who, n: out.length, items: out.slice(0, 60) });
  }
}

function attach(p, name) {
  Interceptor.attach(p, {
    onEnter: function (a) {
      if (total >= CAP) return;
      try {
        var which = name;
        if (which === 'lua_load') return;
        var buf = a[1];
        var sz = a[2].toUInt32();
        if (sz < 16 || sz > 8 * 1024 * 1024) return;
        var raw = new Uint8Array(buf.readByteArray(Math.min(sz, 4 * 1024 * 1024)));
        var s = '';
        for (var i = 0; i < raw.length; i++) s += String.fromCharCode(raw[i]);
        harvest(s, which);
      } catch (e) {}
    }
  });
  send({ ev: 'luadump_hook', sym: name });
}

function arm() {
  Process.enumerateModules().forEach(function (m) {
    ['luaL_loadbuffer', 'luaL_loadbufferx'].forEach(function (n) {
      if (hooked[n]) return;
      try {
        var p = m.findExportByName(n);
        if (p) { hooked[n] = 1; attach(p, n); }
      } catch (e) {}
    });
  });
}

var iv = setInterval(arm, 1000);
var ticks = 0;
setInterval(function () {
  ticks++;
  if (ticks > 200) clearInterval(iv);
}, 1000);
setTimeout(function () { send({ ev: 'luadump_done', total: total, syms: Object.keys(hooked) }); }, 180000);
