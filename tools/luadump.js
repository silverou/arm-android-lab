'use strict';
/*
 * Dump URL literals out of Lua chunk loads: the Lua scripts arrive at
 * luaL_loadbuffer already decrypted, so any URL template literal (e.g. the
 * resource-zip builder) becomes visible here even when the final string is
 * assembled at runtime.
 */
var seen = {};
var total = 0;
var CAP = 800;
var hooked = {};

function tryHook(mod, name) {
  try {
    if (hooked[name]) return true;
    var p = mod.findExportByName(name);
    if (!p) return false;
    hooked[name] = true;
    var isLoad = name === 'lua_load';
    Interceptor.attach(p, {
      onEnter: function (a) {
        if (total >= CAP) return;
        try {
          var buf, sz;
          if (isLoad) return; // lua_load uses a reader callback; skip
          buf = a[1];
          sz = a[2].toUInt32();
          if (sz < 16 || sz > 8 * 1024 * 1024) return;
          var txt = buf.readUtf8String(Math.min(sz, 2 * 1024 * 1024)) || '';
          if (txt.length < 16) return;
          var urls = txt.match(/https?:\/\/[A-Za-z0-9._~:/?#\[\]@!$&'()*+,;=%-]{8,300}/g);
          if (!urls) return;
          var uniq = [];
          urls.forEach(function (u) {
            if (!seen[u]) { seen[u] = 1; uniq.push(u); }
          });
          if (!uniq.length) return;
          total += uniq.length;
          send({ ev: 'lua_url', n: uniq.length, urls: uniq.slice(0, 40) });
        } catch (e) {}
      }
    });
    send({ ev: 'luadump_hook', sym: name, mod: mod.name });
    return true;
  } catch (e) {
    return false;
  }
}

function arm() {
  Process.enumerateModules().forEach(function (m) {
    ['luaL_loadbuffer', 'luaL_loadbufferx'].forEach(function (n) { tryHook(m, n); });
  });
}

var iv = setInterval(arm, 1000);
var ticks = 0;
var iv2 = setInterval(function () {
  ticks++;
  if (ticks > 300) { clearInterval(iv2); clearInterval(iv); }
}, 1000);
setTimeout(function () { send({ ev: 'luadump_done', total: total, syms: Object.keys(hooked) }); }, 200000);
