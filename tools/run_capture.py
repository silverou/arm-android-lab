"""CI driver: spawn the app under Frida and collect hook output.

Usage: python run_capture.py <duration_seconds> [extra_bundle.js ...]
Env: FRIDA_DEVICE (default 127.0.0.1:27042).
Loads default bundles that exist in tools/, then any extras.
"""
import json
import os
import subprocess
import sys
import threading
import time

import frida


def dump_death(tag):
    """Capture logcat + newest tombstone the instant the target dies."""
    def _d():
        cmds = [
            (["sudo", "docker", "exec", "redroid", "/system/bin/sh", "-c",
              'ls -t /data/tombstones 2>/dev/null | head -3; '
              't=$(ls -t /data/tombstones 2>/dev/null | head -1); '
              '[ -n "$t" ] && echo "==== $t ====" && cat "/data/tombstones/$t"'],
             "tombstone_%s.txt" % tag),
            (["sudo", "docker", "exec", "redroid", "/system/bin/logcat", "-d", "-v", "time"],
             "logcat_death_%s.txt" % tag),
        ]
        for cmd, out in cmds:
            try:
                with open(out, "w", encoding="utf-8", errors="replace") as f:
                    subprocess.run(cmd, stdout=f, stderr=subprocess.STDOUT, timeout=60)
            except Exception as e:
                try:
                    with open(out + ".err", "w") as f:
                        f.write(str(e))
                except Exception:
                    pass
    threading.Thread(target=_d, daemon=True).start()

DEFAULT_SCRIPTS = [
    "tools/hide.js",
    "tools/bridge_v20.js",
    "tools/trace_redroid.js",
    "tools/keyhook.js",
]
# BUNDLE_SET=v21 swaps the bridge for the no-status-fakery variant;
# BUNDLE_SET=v23 = v20 with the Threads/faketask count arithmetic fixed;
# BUNDLE_SET=v24 = v23 with the totalT scope bug fixed (counts frozen equal);
# BUNDLE_SET=v25 = v24 + raw open() hooks (open-bypass was reading real status).
if os.environ.get("BUNDLE_SET") == "v21":
    DEFAULT_SCRIPTS[1] = "tools/bridge_v21.js"
elif os.environ.get("BUNDLE_SET") == "v23":
    DEFAULT_SCRIPTS[1] = "tools/bridge_v23.js"
elif os.environ.get("BUNDLE_SET") == "v24":
    DEFAULT_SCRIPTS[1] = "tools/bridge_v24.js"
elif os.environ.get("BUNDLE_SET") == "v25":
    DEFAULT_SCRIPTS[1] = "tools/bridge_v25.js"
elif os.environ.get("BUNDLE_SET") == "v26":
    DEFAULT_SCRIPTS[1] = "tools/bridge_v26.js"
elif os.environ.get("BUNDLE_SET") == "v27":
    DEFAULT_SCRIPTS[1] = "tools/bridge_v27.js"
elif os.environ.get("BUNDLE_SET") == "v28":
    DEFAULT_SCRIPTS[1] = "tools/bridge_v28.js"
elif os.environ.get("BUNDLE_SET") == "v29":
    DEFAULT_SCRIPTS[1] = "tools/bridge_v29.js"
elif os.environ.get("BUNDLE_SET") == "v30":
    DEFAULT_SCRIPTS[1] = "tools/bridge_v30.js"
elif os.environ.get("BUNDLE_SET") == "v31":
    DEFAULT_SCRIPTS[1] = "tools/bridge_v31.js"
elif os.environ.get("BUNDLE_SET") == "v32":
    DEFAULT_SCRIPTS[1] = "tools/bridge_v32.js"
elif os.environ.get("BUNDLE_SET") == "v33":
    DEFAULT_SCRIPTS[1] = "tools/bridge_v33.js"
elif os.environ.get("BUNDLE_SET") == "v34":
    DEFAULT_SCRIPTS[1] = "tools/bridge_v34.js"
elif os.environ.get("BUNDLE_SET") == "v35":
    DEFAULT_SCRIPTS[1] = "tools/bridge_v35.js"
elif os.environ.get("BUNDLE_SET") == "v36":
    DEFAULT_SCRIPTS[1] = "tools/bridge_v36.js"
elif os.environ.get("BUNDLE_SET") == "v37":
    DEFAULT_SCRIPTS[1] = "tools/bridge_v37.js"
elif os.environ.get("BUNDLE_SET") == "v38":
    DEFAULT_SCRIPTS[1] = "tools/bridge_v38.js"
elif os.environ.get("BUNDLE_SET") == "v39":
    DEFAULT_SCRIPTS[1] = "tools/bridge_v39.js"
elif os.environ.get("BUNDLE_SET") == "v42":
    DEFAULT_SCRIPTS[1] = "tools/bridge_v42.js"
elif os.environ.get("BUNDLE_SET") == "v43":
    DEFAULT_SCRIPTS[1] = "tools/bridge_v43.js"
elif os.environ.get("BUNDLE_SET") == "v44":
    DEFAULT_SCRIPTS[1] = "tools/bridge_v44.js"
elif os.environ.get("BUNDLE_SET") == "v45":
    DEFAULT_SCRIPTS[1] = "tools/bridge_v45.js"
elif os.environ.get("BUNDLE_SET") == "v46":
    DEFAULT_SCRIPTS[1] = "tools/bridge_v46.js"
elif os.environ.get("BUNDLE_SET") == "v47":
    DEFAULT_SCRIPTS[1] = "tools/bridge_v47.js"
elif os.environ.get("BUNDLE_SET") == "v48":
    DEFAULT_SCRIPTS[1] = "tools/bridge_v48.js"
elif os.environ.get("BUNDLE_SET") == "v49":
    DEFAULT_SCRIPTS[1] = "tools/bridge_v49.js"
elif os.environ.get("BUNDLE_SET") == "v50":
    DEFAULT_SCRIPTS[1] = "tools/bridge_v50.js"
elif os.environ.get("BUNDLE_SET") == "v54":
    DEFAULT_SCRIPTS[1] = "tools/bridge_v54.js"
elif os.environ.get("BUNDLE_SET") == "v56":
    DEFAULT_SCRIPTS[1] = "tools/bridge_v56.js"
elif os.environ.get("BUNDLE_SET") == "v57":
    DEFAULT_SCRIPTS[1] = "tools/bridge_v57.js"
elif os.environ.get("BUNDLE_SET") == "v58":
    DEFAULT_SCRIPTS[1] = "tools/bridge_v58.js"
# Bundles too big for a single create_script message are pushed to the
# guest filesystem; a small loader reads and evals them in-process.
GUEST_BUNDLE_PATHS = {
    "tools/bridge_v20.js": "/data/local/tmp/v20.js",
    "tools/bridge_v21.js": "/data/local/tmp/v21.js",
    "tools/bridge_v23.js": "/data/local/tmp/v23.js",
    "tools/bridge_v24.js": "/data/local/tmp/v24.js",
    "tools/bridge_v25.js": "/data/local/tmp/v25.js",
    "tools/bridge_v26.js": "/data/local/tmp/v26.js",
    "tools/bridge_v27.js": "/data/local/tmp/v27.js",
    "tools/bridge_v28.js": "/data/local/tmp/v28.js",
    "tools/bridge_v29.js": "/data/local/tmp/v29.js",
    "tools/bridge_v30.js": "/data/local/tmp/v30.js",
    "tools/bridge_v31.js": "/data/local/tmp/v31.js",
    "tools/bridge_v32.js": "/data/local/tmp/v32.js",
    "tools/bridge_v33.js": "/data/local/tmp/v33.js",
    "tools/bridge_v34.js": "/data/local/tmp/v34.js",
    "tools/bridge_v35.js": "/data/local/tmp/v35.js",
    "tools/bridge_v36.js": "/data/local/tmp/v36.js",
    "tools/bridge_v37.js": "/data/local/tmp/v37.js",
    "tools/bridge_v38.js": "/data/local/tmp/v38.js",
    "tools/bridge_v39.js": "/data/local/tmp/v39.js",
    "tools/bridge_v42.js": "/data/local/tmp/v42.js",
    "tools/bridge_v43.js": "/data/local/tmp/v43.js",
    "tools/bridge_v44.js": "/data/local/tmp/v44.js",
    "tools/bridge_v45.js": "/data/local/tmp/v45.js",
    "tools/bridge_v46.js": "/data/local/tmp/v46.js",
    "tools/bridge_v47.js": "/data/local/tmp/v47.js",
    "tools/bridge_v48.js": "/data/local/tmp/v48.js",
    "tools/bridge_v49.js": "/data/local/tmp/v49.js",
    "tools/bridge_v50.js": "/data/local/tmp/v50.js",
    "tools/bridge_v54.js": "/data/local/tmp/v54.js",
    "tools/bridge_v56.js": "/data/local/tmp/v56.js",
    "tools/bridge_v57.js": "/data/local/tmp/v57.js",
    "tools/bridge_v58.js": "/data/local/tmp/v58.js",
}


def script_source(path):
    if path in GUEST_BUNDLE_PATHS:
        loader = open("tools/loadfile.js", encoding="utf-8").read()
        return loader.replace("__PATH__", GUEST_BUNDLE_PATHS[path])
    return open(path, encoding="utf-8").read()


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



def spawn_app(dev):
    """Spawn with retries; fall back to explicit pkg/Activity when the
    launcher resolution (getLaunchIntentForPackage) fails."""
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
                print("SPAWN_RETRY", prog, i, str(e)[:220], flush=True)
                try:
                    subprocess.run(["sudo", "docker", "exec", "redroid",
                                    "/system/bin/am", "force-stop", "com.ihuman.pinyin"],
                                   timeout=30)
                except Exception as e2:
                    print("force-stop-err", str(e2)[:120], flush=True)
                time.sleep(3)
    raise RuntimeError("spawn failed: %s" % last)


def main():
    dur = int(sys.argv[1]) if len(sys.argv) > 1 else 150
    scripts_paths = [p for p in DEFAULT_SCRIPTS if os.path.exists(p)]
    scripts_paths += sys.argv[2:]
    addr = os.environ.get("FRIDA_DEVICE", "127.0.0.1:27042")
    print("DEVICE", addr, flush=True)
    print("SCRIPTS", scripts_paths, flush=True)

    dev = connect(addr)
    pid = spawn_app(dev)
    print("SPAWN", pid, flush=True)
    sess = dev.attach(pid)
    death_tag = os.environ.get("DEATH_TAG", "att")
    def on_detached(reason, crash=None):
        print("DETACHED", reason, flush=True)
        if crash is not None:
            try:
                rep = getattr(crash, "report", None)
                if rep:
                    print("CRASHREPORT", rep, flush=True)
                else:
                    print("CRASHREPORT-EMPTY", repr(crash), flush=True)
            except Exception as e:
                print("CRASHREPORT-ERR", str(e)[:200], flush=True)
        dump_death(death_tag)
    sess.on("detached", on_detached)

    scripts = []
    for path in scripts_paths:
        src = script_source(path)
        s = sess.create_script(src)
        s.on("message", lambda m, d: on_message(m, d, None))
        s.load()
        scripts.append(s)
        print("LOADED", path, "at", int(time.time()), flush=True)
        try:
            dev.enumerate_processes()
            print("PING_OK after", path, flush=True)
        except Exception as e:
            print("PING_FAIL after", path, str(e)[:200], flush=True)
            break
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
