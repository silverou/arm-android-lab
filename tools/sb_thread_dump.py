"""CI: attach Frida to the self-built app and dump Java + native thread stacks.

Usage: python sb_thread_dump.py <pid> <out.json>
Env: FRIDA_DEVICE (default 127.0.0.1:27042)
"""
import json
import os
import sys
import time

import frida

JS = r"""
setTimeout(function () {
  try {
    Java.perform(function () {
      var Thread = Java.use('java.lang.Thread');
      var map = Thread.getAllStackTraces();
      var it = map.keySet().iterator();
      var res = [];
      while (it.hasNext()) {
        var t = it.next();
        var st = map.get(t);
        var frames = [];
        for (var i = 0; i < st.length && i < 60; i++) frames.push(String(st[i]));
        res.push({ name: String(t.getName()), state: String(t.getState()), frames: frames });
      }
      send({ java: res });
    });
  } catch (e) {
    send({ java_error: String(e) });
  }
  var nat = [];
  Process.enumerateThreads().forEach(function (t) {
    var bt = [];
    try {
      bt = Thread.backtrace(t.context, Backtracer.ACCURATE).slice(0, 24).map(function (a) {
        try { return DebugSymbol.fromAddress(a).toString(); } catch (e) { return a.toString(); }
      });
    } catch (e) { bt = ['bt_error ' + e]; }
    nat.push({ id: t.id, name: t.name || '', frames: bt });
  });
  send({ native: nat });
}, 200);
"""


def main():
    if len(sys.argv) < 3:
        print(__doc__)
        return 1
    pid = int(sys.argv[1])
    out = sys.argv[2]
    dev = frida.get_device_manager().add_remote_device(
        os.environ.get("FRIDA_DEVICE", "127.0.0.1:27042"))
    sess = dev.attach(pid)
    msgs = []

    def on_msg(msg, data):
        msgs.append(msg)

    script = sess.create_script(JS)
    script.on("message", on_msg)
    script.load()
    deadline = time.time() + 12
    while time.time() < deadline and not any(
            m.get("payload", {}).get(k) for m in msgs for k in ("native",)):
        time.sleep(0.3)
    time.sleep(1)
    json.dump(msgs, open(out, "w", encoding="utf-8"), ensure_ascii=False, indent=1)
    print("dumped %d messages -> %s" % (len(msgs), out))
    sess.detach()
    return 0


if __name__ == "__main__":
    sys.exit(main())
