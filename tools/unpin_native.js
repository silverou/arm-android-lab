'use strict';
/*
 * Native-only TLS unpin (frida 17 dropped the bundled Java bridge, so
 * Java.perform is unavailable). Forces OpenSSL/BoringSSL verify paths open
 * for the app's native HTTP stack (libcurl inside cocos libs) and retries
 * until the ssl module appears, since libs load after spawn.
 */
var installed = {};

function tryHook(mod, name, cb) {
  try {
    var p = mod.findExportByName(name);
    if (!p) return false;
    if (installed[name]) return true;
    cb(p);
    installed[name] = true;
    send({ ev: 'unpin_native', sym: name, mod: mod.name });
    return true;
  } catch (e) {
    return false;
  }
}

var armed = false;
function arm() {
  if (armed) return;
  var mods = Process.enumerateModules();
  var sslMods = mods.filter(function (m) { return /ssl|crypto|curl|hpyr|ihcommon/i.test(m.name); });
  var ok = 0;
  sslMods.forEach(function (m) {
    ok += tryHook(m, 'SSL_CTX_set_verify', function (p) {
      Interceptor.attach(p, {
        onEnter: function (a) {
          // (ctx, mode, cb): force SSL_VERIFY_NONE
          a[1] = ptr(0);
        }
      });
    }) ? 1 : 0;
    ok += tryHook(m, 'SSL_get_verify_result', function (p) {
      Interceptor.attach(p, {
        onLeave: function (r) { r.replace(0); }
      });
    }) ? 1 : 0;
    ok += tryHook(m, 'X509_verify_cert', function (p) {
      Interceptor.attach(p, {
        onLeave: function (r) { r.replace(1); }
      });
    }) ? 1 : 0;
    ok += tryHook(m, '__ssl_verify_cert_chain', function (p) {
      Interceptor.attach(p, {
        onLeave: function (r) { r.replace(0); }
      });
    }) ? 1 : 0;
    ok += tryHook(m, 'SSL_CTX_set_default_verify_paths', function (p) {
      Interceptor.attach(p, {
        onLeave: function (r) { r.replace(1); }
      });
    }) ? 1 : 0;
  });
  if (Object.keys(installed).length > 0) {
    armed = true;
    clearInterval(iv);
    send({ ev: 'unpin_native_ready', n: Object.keys(installed).length });
  }
}

var iv = setInterval(arm, 500);
var ticks = 0;
var iv2 = setInterval(function () {
  ticks++;
  if (ticks > 240) { clearInterval(iv2); clearInterval(iv); }
}, 500);
