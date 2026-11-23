"""Spawn the app under one frida bundle and keep it alive.

Usage: python run_classload.py <seconds> <bundle.js>
Env: FRIDA_DEVICE (default 127.0.0.1:27042)
"""
import json
import os
import subprocess
import sys
import time

import frida


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
            print("CONNECT_RETRY", i, str(e)[:160], flush=True)
            time.sleep(2)
    raise RuntimeError("connect failed: %s" % last)


def spawn_app(dev):
    attempts = [["com.ihuman.pinyin"], ["com.ihuman.pinyin/org.cocos2dx.lua.AppActivity"]]
    last = None
    for prog in attempts:
        for i in range(3):
            try:
                pid = dev.spawn(prog)
                print("SPAWN_OK", prog, pid, flush=True)
                return pid
            except Exception as e:
                last = e
                print("SPAWN_RETRY", prog, i, str(e)[:200], flush=True)
                try:
                    subprocess.run(["sudo", "docker", "exec", "redroid",
                                    "/system/bin/am", "force-stop", "com.ihuman.pinyin"],
                                   timeout=30)
                except Exception:
                    pass
                time.sleep(3)
    raise RuntimeError("spawn failed: %s" % last)


def main():
    dur = int(sys.argv[1]) if len(sys.argv) > 1 else 240
    bundle = sys.argv[2]
    addr = os.environ.get("FRIDA_DEVICE", "127.0.0.1:27042")
    size = os.path.getsize(bundle)
    if size > 100000:
        # too big for one create_script message; push already done by CI,
        # evaluate through the guest-side loader
        guest = "/data/local/tmp/" + os.path.basename(bundle)
        loader = open("tools/loadfile.js", encoding="utf-8").read()
        src = loader.replace("__PATH__", guest)
        print("USING_GUEST_LOADER", guest, flush=True)
    else:
        src = open(bundle, encoding="utf-8").read()

    dev = connect(addr)
    deadline = time.time() + dur
    for attempt in range(3):
        pid = spawn_app(dev)
        sess = dev.attach(pid)
        try:
            script = sess.create_script(src)
        except Exception as e:
            print("CREATE_SCRIPT_ERR", attempt, str(e)[:300], flush=True)
            try:
                sess.detach()
            except Exception:
                pass
            continue

        def on_msg(m, data):
            if m.get("type") == "send":
                print("MSG", json.dumps(m.get("payload"), ensure_ascii=False), flush=True)
            else:
                print("ERR", json.dumps(m)[:2000], flush=True)

        def on_detached(reason, crash=None):
            print("DETACHED", reason, flush=True)

        sess.on("detached", on_detached)
        script.on("message", on_msg)
        script.load()
        dev.resume(pid)
        print("RESUMED", pid, "attempt", attempt, flush=True)
        while time.time() < deadline:
            time.sleep(2)
        try:
            sess.detach()
        except Exception:
            pass
        print("DONE", flush=True)
        return 0
    print("GAVE_UP", flush=True)
    return 1


if __name__ == "__main__":
    sys.exit(main())
