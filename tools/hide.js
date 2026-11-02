'use strict';
/*
 * Scrub frida-owned thread names before app code runs so anti-frida
 * scans of /proc/self/task/*/comm only see boring names.
 */
var openF = new NativeFunction(Module.getGlobalExportByName('open'), 'int', ['pointer', 'int', 'int']);
var writeF = new NativeFunction(Module.getGlobalExportByName('write'), 'long', ['int', 'pointer', 'long']);
var closeF = new NativeFunction(Module.getGlobalExportByName('close'), 'int', ['int']);

var BAD = ['gum-js', 'gmain', 'gdbus', 'frida', 'ptmain', 'js-main', 'pool-frida'];
var FAKE = ['Jit thread pool', 'Binder:2843_2', 'FinalizerDae', 'Profile Saver', 'ADB-JDWP Conn'];

function setComm(tid, name) {
  var path = Memory.allocUtf8String('/proc/' + Process.id + '/task/' + tid + '/comm');
  var buf = Memory.allocUtf8String(name);
  var fd = openF(path, 1, 0);
  if (fd < 0) return false;
  writeF(fd, buf, name.length);
  closeF(fd);
  return true;
}

function scrub() {
  var changed = [];
  var threads;
  try { threads = Process.enumerateThreads(); } catch (e) { return; }
  for (var i = 0; i < threads.length; i++) {
    var t = threads[i];
    var n = (t.name || '').toLowerCase();
    for (var j = 0; j < BAD.length; j++) {
      if (n.indexOf(BAD[j]) >= 0) {
        var fake = FAKE[(t.id + j) % FAKE.length];
        if (setComm(t.id, fake)) changed.push({ tid: t.id, was: t.name, now: fake });
        break;
      }
    }
  }
  if (changed.length) send({ ev: 'scrubbed', list: changed });
}

scrub();
setInterval(scrub, 400);
send({ ev: 'hide_ready' });
