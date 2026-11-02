"""CI driver: spawn the app under Frida and collect hook output.

Usage: python run_capture.py <duration_seconds> [extra_bundle.js ...]
Env: FRIDA_DEVICE (default 127.0.0.1:27042).
Loads default bundles that exist in tools/, then any extras.
"""
import json
import os
import sys
import time

import frida

DEFAULT_SCRIPTS = [
    "tools/hide.js",
    "tools/bridge_v20.js",
    "tools/trace_redroid.js",
    "tools/keyhook.js",
]


def on_message(m, data, out):
    if m.get("type") == "send":
        print("MSG", json.dumps(m.get("payload"), ensure_ascii=False), flush=True)
    else:
        print("ERR", json.dumps(m)[:2000], flush=True)


def connect(addr, tries=20):
    mgr = frida.get_device_manager()
    last = None
    for i in range(tries):
        try:
            dev = None
            for d in mgr.enumerate_devices():
                if d.type == "remote" and addr in d.id:
                    dev = d
                    break
            if dev is None:
                dev = mgr.add_remote_device(addr)
            dev.enumerate_processes()
            return dev
        except Exception as e:
            last = e
            print("CONNECT_RETRY", i, str(e)[:200], flush=True)
            time.sleep(2)
    raise RuntimeError("connect failed: %s" % last)


def main():
    dur = int(sys.argv[1]) if len(sys.argv) > 1 else 150
    scripts_paths = [p for p in DEFAULT_SCRIPTS if os.path.exists(p)]
    scripts_paths += sys.argv[2:]
    addr = os.environ.get("FRIDA_DEVICE", "127.0.0.1:27042")
    print("DEVICE", addr, flush=True)
    print("SCRIPTS", scripts_paths, flush=True)

    dev = connect(addr)
    pid = dev.spawn(["com.ihuman.pinyin"])
    print("SPAWN", pid, flush=True)
    sess = dev.attach(pid)
    sess.on("detached", lambda *a: print("DETACHED", a[0], flush=True))

    scripts = []
    for path in scripts_paths:
        src = open(path, encoding="utf-8").read()
        s = sess.create_script(src)
        s.on("message", lambda m, d: on_message(m, d, None))
        s.load()
        scripts.append(s)
    print("SCRIPTS_LOADED", scripts_paths, flush=True)
    dev.resume(pid)
    time.sleep(dur)
    try:
        for s in scripts:
            s.unload()
        sess.detach()
    except Exception:
        pass
    print("DONE", flush=True)


if __name__ == "__main__":
    main()
