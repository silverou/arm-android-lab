'use strict';
/*
 * Probe B: dex-dump feasibility.
 *
 * The shell decrypts the business dex in memory and loads it; nothing
 * lands on disk. Before writing an ART-level dumper, this probes which
 * loading path the shell uses:
 *   - InMemoryDexClassLoader construction (constructor hook)
 *   - DexClassLoader with a file path (hook + record paths)
 *   - java.nio.ByteBuffer / dex decode entry points
 * Any hit tells us whether a memory-image dump is reachable at all.
 *
 * All events go through send() and land in hook_out*.txt.
 */
var EV = [];
function ev(o) { send(o); }

function hookMethod(clsName, method, argNames, tag) {
  try {
    var C = Java.use(clsName);
    C[method].overloads.forEach(function (ov) {
      var where = tag + ':' + clsName + '.' + method;
      ov.implementation = function () {
        var out = { ev: 'dex_path', tag: where };
        for (var i = 0; i < argNames.length && i < arguments.length; i++) {
          try {
            var a = arguments[i];
            if (a === null || a === undefined) { out[argNames[i]] = String(a); continue; }
            if (typeof a === 'string') {
              out[argNames[i]] = a.slice(0, 160);
            } else if (typeof a === 'number' || typeof a === 'boolean') {
              out[argNames[i]] = a;
            } else {
              out[argNames[i]] = a.getClass ? a.getClass().getName() : String(a);
            }
          } catch (e) { out[argNames[i]] = '?'; }
        }
        try {
          if (cacheDir) {
            var r = Java.use('java.io.File').$new(cacheDir, 'dexdump_probe.txt');
            var fos = Java.use('java.io.FileOutputStream').$new(r, true);
            for (var k in out) {
              if (k === 'ev' || k === 'tag') continue;
              var v = String(out[k]) + '\n';
              var b = Java.array('byte', (v.length));
              for (var q = 0; q < v.length; q++) b[q] = v.charCodeAt(q) & 0xff;
              fos.write(b);
            }
            fos.close();
          }
        } catch (e2) {}
        ev(out);
        return ov.apply(this, arguments);
      };
    });
    ev({ ev: 'dex_hooked', tag: where });
    return true;
  } catch (e) {
    ev({ ev: 'dex_hook_miss', tag: tag + ':' + clsName + '.' + method, e: String(e).slice(0, 120) });
    return false;
  }
}

var cacheDir = null;
var booted = false;
var counter = 0;

function start() {
  if (booted) return;
  try { Java.perform(function () {}); } catch (e) { return; }
  booted = true;
  try {
    var ctx = Java.use('android.app.ActivityThread').currentApplication().getApplicationContext();
    cacheDir = ctx.getFilesDir().getAbsolutePath();
    ev({ ev: 'dex_files_dir', dir: cacheDir });
  } catch (e) { ev({ ev: 'dex_ctx_err', e: String(e).slice(0, 120) }); }

  // loaders used by packers to run memory-only dex
  hookMethod('dalvik.system.InMemoryDexClassLoader', '<init>',
             ['byteBuffer', 'parent', 'loader'], 'inmem');
  hookMethod('dalvik.system.DexClassLoader', '<init>',
             ['dexPath', 'optDir', 'libPath', 'parent'], 'dexcl');
  hookMethod('dalvik.system.PathClassLoader', '<init>',
             ['path', 'parent'], 'pathcl');
  hookMethod('dalvik.system.BaseDexClassLoader', '<init>',
             ['dexPath', 'libPath', 'parent'], 'base');

  // runtime dex-image surface (first step toward a real dumper)
  try {
    var DexFile = Java.use('dalvik.system.DexFile');
    ev({ ev: 'dex_class', cls: 'dalvik.system.DexFile', ok: true });
  } catch (e) {}

  // scan loaded classes for dex-bearing names once the app is up
  setInterval(function () {
    counter++;
    if (counter === 6 || counter === 20) {
      try {
        Java.perform(function () {
          Java.enumerateClassLoaders({
            onMatch: function (cl) {
              var s = String(cl);
              if (s.indexOf('Dex') >= 0 || s.indexOf('Path') >= 0 || s.indexOf('InMemory') >= 0) {
                ev({ ev: 'dex_loader_seen', loader: s.slice(0, 160) });
              }
            },
            onComplete: function () {}
          });
        });
      } catch (e) { ev({ ev: 'dex_enum_err', e: String(e).slice(0, 120) }); }
    }
    if (counter > 40) { /* keep running; cheap */ }
  }, 1500);
}

start();
var tries = 0;
var poll = setInterval(function () {
  tries++;
  start();
  if (booted && tries > 10) clearInterval(poll);
}, 500);
