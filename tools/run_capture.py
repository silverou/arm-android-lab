"""CI driver: spawn the app under Frida and collect hook output.

Usage: python run_capture.py <duration_seconds> [extra_bundle.js]
Connects to frida-server forwarded at 127.0.0.1:27042.
"""
import json
import sys
import time

import frida


def on_message(m, data, out):
    if m.get("type") == "send":
        print("MSG", json.dumps(m.get("payload"), ensure_ascii=False), flush=True)
    else:
        print("ERR", json.dumps(m)[:2000], flush=True)


def main():
    dur = int(sys.argv[1]) if len(sys.argv) > 1 else 150
    scripts_paths = ["tools/keyhook.js"]
    if len(sys.argv) > 2:
        scripts_paths.append(sys.argv[2])

    mgr = frida.get_device_manager()
    dev = mgr.add_remote_device("127.0.0.1:27042")
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
