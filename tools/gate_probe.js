'use strict';
/*
 * Gate probe: resolve the .ihi fopen/consumer PLT via runtime GOT and hook
 * the resolved functions to observe the decrypt boundary.
 *
 * From BSS-code disasm (RVA 0x1492424..0x1492448):
 *   x19 = path
 *   bl 0x12c90c0  PLT -> GOT[0x25ce0c8]  = open_path(path, mode?) -> FILE*
 *   cbz fail -> return 0 (fallback to APK assets)
 *   bl 0x12c9d60  PLT -> GOT[0x25ce718]  = consumer(FILE*, out...)  (the gate)
 *
 * Disk .rela.plt is stripped by the packer; GOT slots are runtime-filled.
 * This probe reads the slots after packer init, identifies the resolved
 * targets (module+offset+DebugSymbol), hooks the consumer, and dumps
 * input/output so we can see what the gate expects from an .ihi file.
 *
 * Output: files/gate_probe.txt (log) + gate_out_<n>.bin (first outputs)
 */
var DIR = '/data/user/0/com.ihuman.pinyin/files/';
var SLOTS = {
  consumer: 0x25ce718,
  open_path: 0x25ce0c8,
  fnA: 0x25cdff0,
  fnB: 0x25cdbb8,
};
var fns = {};
['fopen', 'fwrite', 'fclose'].forEach(function (n) {
  var p = null;
  try { p = Module.getGlobalExportByName(n); } catch (e) {}
  if (p) fns[n] = new NativeFunction(p,
    n === 'fwrite' ? 'size_t' : (n === 'fclose' ? 'int' : 'pointer'),
    n === 'fwrite' ? ['pointer', 'size_t', 'size_t', 'pointer'] :
    n === 'fclose' ? ['pointer'] : ['pointer', 'pointer']);
});
var ok = !!(fns.fopen && fns.fwrite && fns.fclose);

function writeFile(path, bytes, len) {
  var fp = fns.fopen(Memory.allocUtf8String(path), Memory.allocUtf8String('wb'));
  if (fp.isNull()) return false;
  var buf = Memory.alloc(len);
  buf.writeByteArray(bytes);
  fns.fwrite(buf, 1, len, fp);
  fns.fclose(fp);
  return true;
}
function appendLog(line) {
  if (!ok) return;
  var enc = [];
  for (var i = 0; i < line.length; i++) enc.push(line.charCodeAt(i) & 0xff);
  var fp = fns.fopen(Memory.allocUtf8String(DIR + 'gate_probe.txt'), Memory.allocUtf8String('ab'));
  if (fp.isNull()) return;
  var buf = Memory.alloc(enc.length);
  buf.writeByteArray(enc);
  fns.fwrite(buf, 1, enc.length, fp);
  fns.fclose(fp);
}

function describe(addr) {
  var s = addr.toString();
  try {
    var m = Process.findModuleByAddress(addr);
    if (m) s = m.name + '+0x' + addr.sub(m.base).toString(16);
  } catch (e) {}
  try {
    var sym = DebugSymbol.fromAddress(addr);
    if (sym && sym.name) s += ' {' + sym.name + '}';
  } catch (e) {}
  return s;
}

var hooked = {};
var outN = 0;

function hookTarget(name, rva) {
  var m = null;
  try {
    Process.enumerateModules().forEach(function (x) {
      if (!m && /libcocos2dlua/.test(x.name)) m = x;
    });
  } catch (e) {}
  if (!m) return false;
  var slotAddr = m.base.add(rva);
  var target;
  try { target = slotAddr.readPointer(); } catch (e) { return false; }
  if (target.isNull()) { appendLog(name + " slot NULL\n"); return false; }
  var key = target.toString();
  if (hooked[key]) return true;
  hooked[key] = 1;
  var desc = describe(target);
  appendLog(name + " slot=0x" + rva.toString(16) + " -> " + key + " = " + desc + "\n");
  send({ ev: 'gate_target', name: name, target: key, desc: desc });
  try {
    Interceptor.attach(target, {
      onEnter: function (a) {
        this.a0 = a[0]; this.a1 = a[1]; this.a2 = a[2]; this.a3 = a[3];
        this.t0 = Date.now();
        var bt = [];
        try {
          var frames = Thread.backtrace(this.context, Backtracer.ACCURATE);
          for (var i = 0; i < Math.min(frames.length, 6); i++) bt.push(describe(frames[i]));
        } catch (e) {}
        send({ ev: 'gate_in', name: name, x0: a[0].toString(), x1: a[1].toString(),
               x2: a[2].toString(), x3: a[3].toString(), bt: bt });
      },
      onLeave: function (ret) {
        send({ ev: 'gate_out', name: name, ret: ret.toString(), dt: Date.now() - this.t0 });
        // consumer: try to dump an out-Data at x1 if it looks like {ptr,size}
        if (name === 'consumer') {
          try {
            var p = this.a1;
            if (p && !p.isNull()) {
              var bytes = p.readPointer();
              var size = p.add(8).readPointer().toInt32();
              send({ ev: 'gate_data', p: p.toString(), bytes: bytes.toString(), size: size });
              if (!bytes.isNull() && size > 8 && size < 8 * 1024 * 1024 && outN < 5) {
                var buf = new Uint8Array(bytes.readByteArray(size));
                outN++;
                var head = '';
                for (var i = 0; i < Math.min(size, 24); i++) head += ('0' + buf[i].toString(16)).slice(-2);
                send({ ev: 'gate_dump', n: outN, size: size, head: head });
                writeFile(DIR + 'gate_out_' + outN + '.bin', buf, size);
              }
            }
          } catch (e) { send({ ev: 'gate_data_err', e: String(e) }); }
        }
      }
    });
    send({ ev: 'gate_hooked', name: name, target: key });
    return true;
  } catch (e) {
    appendLog(name + " hook FAIL " + e + "\n");
    send({ ev: 'gate_hook_err', name: name, e: String(e) });
    return false;
  }
}

var tries = 0;
var poll = setInterval(function () {
  tries++;
  var m = null;
  try {
    Process.enumerateModules().forEach(function (x) {
      if (!m && /libcocos2dlua/.test(x.name)) m = x;
    });
  } catch (e) {}
  if (m) {
    // wait for packer to fill GOT (init ~2-6s after module load)
    setTimeout(function () {
      for (var k in SLOTS) hookTarget(k, SLOTS[k]);
      send({ ev: 'gate_armed', hooked: Object.keys(hooked).length });
    }, 4000);
    clearInterval(poll);
  } else if (tries > 300) {
    clearInterval(poll);
    send({ ev: 'gate_timeout' });
  }
}, 100);
