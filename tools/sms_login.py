"""SMS login flow driver v4 (daemon-based).

All frida scripts are loaded BEFORE resume (app suspended). A persistent
Lua daemon then serves host-written command files, so phases never depend
on post-resume script creation (which times out under app load).

Env: FRIDA_DEVICE, LOGIN_PHONE, LOGIN_NONCE, OTP_URL.
"""
import json
import os
import subprocess
import sys
import tempfile
import time
import urllib.request

import frida

OUT_PATH = "/data/user/0/com.ihuman.pinyin/files/frida_out.txt"
CMD_PATH = "/data/local/tmp/lua_cmd.lua"


def guest_write(path, data, mode="644"):
    tmp = tempfile.NamedTemporaryFile(delete=False, mode="w", encoding="utf-8")
    tmp.write(data)
    tmp.close()
    subprocess.run(["sudo", "docker", "cp", tmp.name, "redroid:%s" % path], check=False)
    subprocess.run(["sudo", "docker", "exec", "redroid", "/system/bin/sh", "-c",
                    "chmod %s %s" % (mode, path)], check=False)
    os.unlink(tmp.name)


def guest_cat(path):
    try:
        r = subprocess.run(["sudo", "docker", "exec", "redroid", "/system/bin/cat", path],
                           capture_output=True, timeout=30)
        return r.stdout.decode("utf-8", "replace")
    except Exception:
        return ""


def guest_rm(path):
    subprocess.run(["sudo", "docker", "exec", "redroid", "/system/bin/sh", "-c",
                    "rm -f %s" % path], check=False,
                   stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)


def tap(x, y):
    subprocess.run(["sudo", "docker", "exec", "redroid", "/system/bin/input", "tap", str(x), str(y)],
                   check=False, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)


def tapper():
    for _ in range(5):
        tap(1108, 402)
        time.sleep(1)
        tap(592, 576)
        time.sleep(1)
        tap(1188, 76)
        time.sleep(2)


def connect(addr, tries=30):
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
            print("CONNECT_RETRY", i, str(e)[:150], flush=True)
            time.sleep(2)
    raise RuntimeError("connect failed: %s" % last)


def spawn_app(dev):
    attempts = [["com.ihuman.pinyin"], ["com.ihuman.pinyin/org.cocos2dx.lua.AppActivity"]]
    for prog in attempts:
        for i in range(3):
            try:
                pid = dev.spawn(prog)
                print("SPAWN_OK", prog, pid, flush=True)
                return pid
            except Exception as e:
                print("SPAWN_RETRY", prog, i, str(e)[:150], flush=True)
                subprocess.run(["sudo", "docker", "exec", "redroid",
                                "/system/bin/am", "force-stop", "com.ihuman.pinyin"], check=False)
                time.sleep(3)
    raise RuntimeError("spawn failed")


def js_str(text):
    return json.dumps(text)


def phase_script(tag, chunk):
    src = open("tools/luaphase.js", encoding="utf-8").read()
    src = src.replace("'__TAG__'", js_str(tag))
    src = src.replace("__CHUNK__", js_str(chunk))
    return src


def read_out(tag):
    return guest_cat("/data/user/0/com.ihuman.pinyin/files/out_%s.txt" % tag)


def open_gate(tag):
    guest_write("/data/local/tmp/%s.gate" % tag, "1")


def run_phase(rs, tag, chunk, timeout=150, quiet=False, pinger=None):
    """Post a run command to the RPC script and wait for the result file."""
    print("PHASE", tag, "start", flush=True)
    outp = "/data/user/0/com.ihuman.pinyin/files/out_%s.txt" % tag
    guest_rm(outp)
    try:
        rs.post({"type": "cmd", "action": "run", "tag": tag, "chunk": chunk})
    except Exception as e:
        print("POST_FAIL", tag, str(e)[:200], flush=True)
        return None
    t0 = time.time()
    result = None
    while time.time() - t0 < timeout:
        time.sleep(2)
        if pinger and int(time.time() - t0) % 10 < 3:
            try:
                rs.post({"type": "cmd", "action": "ping"})
            except Exception:
                pass
        raw = guest_cat(outp)
        if not raw:
            continue
        if raw.startswith("OK:"):
            parts = raw.split(":", 2)
            result = parts[2] if len(parts) > 2 else ""
            break
        if raw.startswith("ERR:"):
            print("PHASE", tag, "err:", raw[:200], flush=True)
            break
    if not quiet:
        print("PHASE", tag, "result:", (result or "<none>")[:800], flush=True)
    else:
        print("PHASE", tag, "done quiet" if result is not None else "empty", flush=True)
    return result


CHUNK_HEAD = r"""
local out = {}
local function P(s) out[#out+1] = s end
local IHM = package.loaded and package.loaded["app.common.ihumansdk.IHumanManager"]
local function pick(n)
  if type(IHM) ~= "table" then return nil end
  local f = IHM[n]
  if f == nil and type(IHM.class) == "table" then f = IHM.class[n] end
  if f == nil and type(IHM.class) == "table" and type(IHM.class.__index) == "table" then f = IHM.class.__index[n] end
  return f
end
"""


def chunk_send(phone):
    return CHUNK_HEAD + r"""
local f = pick("sendSMSWithMobile")
if type(f) ~= "function" then P("SEND:NOFN") return table.concat(out, "|") end
local phone = "%s"
local ok, r = pcall(function() return f(IHM, phone) end)
if not ok then ok, r = pcall(function() return f(phone) end) end
P("SEND:"..tostring(ok)..":"..tostring(r))
return table.concat(out, "|")
""" % phone


def chunk_probe():
    return CHUNK_HEAD + r"""
local g = {}
for k, v in pairs(_G) do g[k] = v end
P("PROBE.LM="..type(g.LoginManager))
P("PROBE.AM="..type(g.AssetMgr))
P("PROBE.IHM="..type(IHM))
return table.concat(out, "|")
"""


def chunk_login(phone, code):
    return CHUNK_HEAD + r"""
local phone = "%s"
local code = "%s"
local tried = {}
local function attempt(name, fn)
  local ok, r = pcall(fn)
  tried[#tried+1] = name.."="..tostring(ok)..":"..tostring(r)
  return ok, r
end
for _, pair in ipairs({{"loginWithMobile", pick("loginWithMobile")}, {"quickLoginWithMobile", pick("quickLoginWithMobile")}}) do
  local name, f = pair[1], pair[2]
  if type(f) == "function" then
    local cb = function(r) _G.FRIDA_LOGIN_RESULT = tostring(r) end
    local ok1 = attempt(name..".cb", function() return f(IHM, phone, code, cb) end)
    if not ok1 then ok1 = attempt(name..".tc", function() return f(IHM, phone, code) end) end
    if not ok1 then attempt(name..".u", function() return f(phone, code) end) end
  end
end
for _, s in ipairs(tried) do P("LOGIN:"..s) end
return table.concat(out, "|")
""" % (phone, code)


def chunk_state():
    return CHUNK_HEAD + r"""
local g = {}
for k, v in pairs(_G) do g[k] = v end
local LM = g.LoginManager
local function calln(t, n)
  if type(t) ~= "table" then return "NOTABLE" end
  local f = t[n]
  if f == nil and type(t.class) == "table" then f = t.class[n] end
  if f == nil and type(t.class) == "table" and type(t.class.__index) == "table" then f = t.class.__index[n] end
  if type(f) ~= "function" then return "NOFN" end
  local ok, r = pcall(function() return f(t) end)
  return tostring(ok)..":"..type(r)..":"..tostring(r)
end
P("LM.type="..type(LM))
P("STATE.islogin="..calln(LM, "islogin"))
P("STATE.accountId="..calln(LM, "getAccountID"))
P("AM.type="..type(g.AssetMgr))
P("FLAG="..tostring(_G.FRIDA_LOGIN_RESULT))
return table.concat(out, "|")
"""


def chunk_secret():
    return CHUNK_HEAD + r"""
local out = {}
local function add(k, v) out[#out+1] = tostring(k).."="..tostring(v) end
local g = {}
for k, v in pairs(_G) do g[k] = v end
local LM = g.LoginManager
if type(LM) == "table" then
  for k, v in pairs(LM) do
    if type(k) == "string" and type(v) == "string" and (k:lower():find("token") or k:lower():find("session") or k:lower():find("uid") or k:lower():find("userid") or k:lower():find("account")) then
      add(k, v)
    end
  end
  local function pickL(n)
    local f = LM[n]
    if f == nil and type(LM.class) == "table" then f = LM.class[n] end
    if f == nil and type(LM.class) == "table" and type(LM.class.__index) == "table" then f = LM.class.__index[n] end
    return f
  end
  for _, n in ipairs({"getUToken", "getSession", "getAccountID", "getCurrentUserId", "getUserId"}) do
    local f = pickL(n)
    if type(f) == "function" then
      local ok, r = pcall(function() return f(LM) end)
      if ok and r ~= nil and type(r) ~= "table" then add("fn."..n, r) end
    end
  end
end
local IHM = package.loaded and package.loaded["app.common.ihumansdk.IHumanManager"]
if type(IHM) == "table" then
  for k, v in pairs(IHM) do
    if type(k) == "string" and type(v) == "string" and (k:lower():find("utoken") or k:lower():find("session")) then add("ihm."..k, v) end
  end
end
local UD = g.UserDefaultMgr
if type(UD) == "table" then
  if UD.userId then add("ud.userId", UD.userId) end
  if UD.accountId then add("ud.accountId", UD.accountId) end
end
return table.concat(out, string.char(10))
"""


def encrypt_secret(text):
    d = tempfile.mkdtemp()
    tf = os.path.join(d, "sess.txt")
    with open(tf, "w", encoding="utf-8") as f:
        f.write(text)
    kf = os.path.join(d, "k.bin")
    subprocess.run(["openssl", "rand", "-out", kf, "32"], check=True)
    subprocess.run(["openssl", "enc", "-aes-256-cbc", "-pbkdf2", "-pass", "file:" + kf,
                    "-in", tf, "-out", "sess.enc"], check=True)
    subprocess.run(["openssl", "pkeyutl", "-encrypt", "-pubin", "-inkey", "tools/login_pub.pem",
                    "-in", kf, "-out", "k.rsa"], check=True)
    for n in ("sess.enc", "k.rsa"):
        p = os.path.join(d, n)
        if os.path.exists(p):
            os.replace(p, n)
    print("SECRET_ENC_OK", flush=True)


def chunk_sample():
    return CHUNK_HEAD + r"""
local g = {}
for k, v in pairs(_G) do g[k] = v end
local AM = g.AssetMgr
if type(AM) ~= "table" then P("SAMPLE:NOAM") return table.concat(out, "|") end
if type(AM.refreshAssetSummary) == "function" then
  pcall(function() return AM:refreshAssetSummary() end)
end
local ids = {"PY002", "PY006", "PY010", "PY030", "practice_01"}
local okloop, errloop = pcall(function()
  for _, id in ipairs(ids) do
    local ok, a = pcall(function() return AM:getAsset(id) end)
    if ok and type(a) == "table" then
      local ok3, st = pcall(function() return a:getState() end)
      if ok3 and st == 3 then
        P("SAMPLE."..id..".installed")
      else
        local ok2, r2 = pcall(function() return a:download() end)
        P("SAMPLE."..id.."="..tostring(ok2)..":"..type(r2))
      end
    else
      P("SAMPLE."..id..".GETFAIL")
    end
  end
end)
if not okloop then P("SAMPLE.LOOPERR:"..tostring(errloop)) end
return table.concat(out, "|")
"""


def fetch_otp(url, deadline_s):
    want = os.environ.get("LOGIN_NONCE", "").strip()
    t0 = time.time()
    while time.time() - t0 < deadline_s:
        try:
            req = urllib.request.Request(url + "?v=%d" % int(time.time()),
                                         headers={"Cache-Control": "no-cache",
                                                  "User-Agent": "curl/8"})
            with urllib.request.urlopen(req, timeout=15) as r:
                d = json.loads(r.read().decode("utf-8", "replace"))
            otp = str(d.get("otp") or "").strip()
            nonce = str(d.get("nonce") or "").strip()
            if want and nonce != want:
                time.sleep(5)
                continue
            if otp and otp.isdigit() and 4 <= len(otp) <= 8:
                print("OTP_GOT len=%d" % len(otp), flush=True)
                return otp
        except Exception:
            pass
        time.sleep(5)
    print("OTP_TIMEOUT", flush=True)
    return None


def main():
    phone = os.environ.get("LOGIN_PHONE", "").strip()
    otp_url = os.environ.get("OTP_URL", "").strip()
    addr = os.environ.get("FRIDA_DEVICE", "127.0.0.1:27042")
    if not phone or not otp_url:
        print("MISSING_ENV", flush=True)
        return 1
    dev = connect(addr)
    pid = spawn_app(dev)
    sess = dev.attach(pid)

    def on_detached(reason, crash=None):
        print("DETACHED", reason, flush=True)
    sess.on("detached", on_detached)

    # clear stale results
    subprocess.run(["sudo", "docker", "exec", "redroid", "/system/bin/sh", "-c",
                    "rm -f /data/local/tmp/otp.txt"], check=False,
                   stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    for t in ("probe", "send", "login", "state", "secret", "sample"):
        guest_rm("/data/user/0/com.ihuman.pinyin/files/out_%s.txt" % t)

    phases = {
        "probe": chunk_probe(),
        "send": chunk_send(phone),
        "login": chunk_login(phone, "__OTP__"),
        "state": chunk_state(),
        "secret": chunk_secret(),
        "sample": chunk_sample(),
    }

    # load bundles + RPC runner while suspended
    for name, path in (("HIDE", "tools/hide.js"), ("BRIDGE", "tools/loadfile.js")):
        try:
            src = open(path, encoding="utf-8").read()
            if name == "BRIDGE":
                src = src.replace("__PATH__", "/data/local/tmp/v66.js")
            sc = sess.create_script(src)
            sc.load()
            print(name + "_OK", flush=True)
        except Exception as e:
            print(name + "_FAIL", str(e)[:200], flush=True)
    try:
        rsrc = open("tools/luarpc.js", encoding="utf-8").read()
        rs = sess.create_script(rsrc)

        def on_msg(m, d):
            if m.get("type") == "send":
                p = m.get("payload") or {}
                print("RPC", json.dumps(p, ensure_ascii=False)[:200], flush=True)
        rs.on("message", on_msg)
        rs.load()
        print("RUNNER_OK", flush=True)
    except Exception as e:
        print("RUNNER_FAIL", str(e)[:300], flush=True)
        return 4

    dev.resume(pid)
    time.sleep(40)
    tapper()
    time.sleep(10)

    # ping liveness before burning SMS
    try:
        rs.post({"type": "cmd", "action": "ping"})
    except Exception as e:
        print("PING_FAIL", str(e)[:200], flush=True)
        return 5
    time.sleep(3)

    res = run_phase(rs, "probe", phases["probe"], timeout=90) or ""
    if "PROBE.LM=" not in res and "PROBE.AM=" not in res:
        print("PROBE_FAILED mechanism broken; no SMS sent", flush=True)
        return 5
    print("PROBE_OK", flush=True)

    res = run_phase(rs, "send", phases["send"], timeout=120) or ""
    if "SEND:true" not in res:
        print("SEND_FAILED", res[:200], flush=True)
        return 3
    print("SMS_SENT", flush=True)

    otp = fetch_otp(otp_url, deadline_s=600)
    if not otp:
        print("FLOW_ABORT no otp", flush=True)
        return 2
    guest_write("/data/local/tmp/otp.txt", otp)
    run_phase(rs, "login", phases["login"], timeout=120)
    print("LOGIN_DISPATCHED", flush=True)
    time.sleep(25)
    tapper()
    time.sleep(6)
    run_phase(rs, "state", phases["state"], timeout=90)
    sec = run_phase(rs, "secret", phases["secret"], timeout=90, quiet=True)
    if sec:
        encrypt_secret(sec)
    else:
        print("SECRET_EMPTY", flush=True)
    run_phase(rs, "sample", phases["sample"], timeout=150)
    print("SAMPLE_TRIGGERED; waiting 90s for auth+downloads", flush=True)
    time.sleep(90)
    try:
        sess.detach()
    except Exception:
        pass
    print("DONE", flush=True)
    return 0


if __name__ == "__main__":
    sys.exit(main())
