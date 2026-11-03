/*
 * Read a guest-filesystem script file and eval it here.
 * __PATH__ is substituted by run_capture.py.
 * Not strict-mode so the evaluated bundle keeps sloppy-mode semantics.
 */
(function () {
  var path = '__PATH__';
  var openF = new NativeFunction(Module.getGlobalExportByName('open'), 'int', ['pointer', 'int', 'int']);
  var readF = new NativeFunction(Module.getGlobalExportByName('read'), 'long', ['int', 'pointer', 'long']);
  var closeF = new NativeFunction(Module.getGlobalExportByName('close'), 'int', ['int']);
  var p = Memory.allocUtf8String(path);
  var fd = openF(p, 0, 0);
  if (fd < 0) {
    send({ ev: 'loader_err', e: 'open failed', code: fd, path: path });
    return;
  }
  var parts = [];
  var buf = Memory.alloc(65536);
  var total = 0;
  for (;;) {
    var n = readF(fd, buf, 65536);
    if (n <= 0) break;
    total += n;
    parts.push(buf.readByteArray(n));
  }
  closeF(fd);
  if (total === 0) {
    send({ ev: 'loader_err', e: 'empty file', path: path });
    return;
  }
  var all = new Uint8Array(total);
  var off = 0;
  for (var i = 0; i < parts.length; i++) {
    var u = new Uint8Array(parts[i]);
    all.set(u, off);
    off += u.length;
  }
  var src = '';
  for (var j = 0; j < all.length; j += 8192) {
    src += String.fromCharCode.apply(null, all.subarray(j, Math.min(j + 8192, all.length)));
  }
  send({ ev: 'loader_eval', bytes: total });
  eval(src);
  send({ ev: 'loader_done' });
})();
