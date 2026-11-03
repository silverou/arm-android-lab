'use strict';
/*
 * Uniform thread identity: rename EVERY thread comm to m.ihuman.pinyin so
 * real /proc/self/task/<tid>/status reads present a uniform Name field (the
 * shape that passed the gate on MuMu), and intercept prctl(PR_SET_NAME)
 * so threads created later are named uniformly at birth.
 */
var TARGET = 'm.ihuman.pinyin';
var TARGET15 = 'm.ihuman.pinyin\u0000';

function setComm(tid, name) {
  var path = Memory.allocUtf8String('/proc/' + Process.id + '/task/' + tid + '/comm');
  var buf = Memory.allocUtf8String(name);
  var fd = openF(path, 1, 0);
  if (fd < 0) return false;
  writeF(fd, buf, name.length);
  closeF(fd);
  return true;
}

var openF = new NativeFunction(Module.getGlobalExportByName('open'), 'int', ['pointer', 'int', 'int']);
var writeF = new NativeFunction(Module.getGlobalExportByName('write'), 'long', ['int', 'pointer', 'long']);
var closeF = new NativeFunction(Module.getGlobalExportByName('close'), 'int', ['int']);

function scrub() {
  var renamed = 0;
  var threads;
  try { threads = Process.enumerateThreads(); } catch (e) { return; }
  for (var i = 0; i < threads.length; i++) {
    var t = threads[i];
    if ((t.name || '') !== TARGET) {
      if (setComm(t.id, TARGET)) renamed++;
    }
  }
  if (renamed) send({ ev: 'scrubbed', n: renamed });
}

// force every future PR_SET_NAME to the uniform name
try {
  var prctlP = Module.getGlobalExportByName('prctl');
  var uniform = Memory.allocUtf8String(TARGET);
  Interceptor.attach(prctlP, {
    onEnter: function (a) {
      try {
        if (a[0].toInt32() === 15) a[2] = uniform; // PR_SET_NAME
      } catch (e) {}
    }
  });
  send({ ev: 'prctl_hooked' });
} catch (e) {
  send({ ev: 'prctl_err', e: String(e) });
}

scrub();
setInterval(scrub, 150);
send({ ev: 'hide_ready' });
