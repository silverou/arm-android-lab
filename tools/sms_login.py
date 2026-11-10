"""SMS login flow driver: send code, relay OTP via repo file, login, sample auth.

Env: FRIDA_DEVICE, LOGIN_PHONE, OTP_URL (raw file URL to poll), BUNDLE_SCRIPTS.
Writes phase results to stdout (no tokens/secrets printed).
"""
import json
import os
import subprocess
import sys
import tempfile
import time
import urllib.request

import frida


def sh(args, **kw):
    return subprocess.run(args, **kw)


def guest_write(path, data, mode="644"):
    tmp = tempfile.NamedTemporaryFile(delete=False, mode="w", encoding="utf-8")
    tmp.write(data)
    tmp.close()
    subprocess.run(["sudo", "docker", "cp", tmp.name, "redroid:%s" % path], check=False)
    subprocess.run(["sudo", "docker", "exec", "redroid", "/system/bin/sh", "-c",
                    "chmod %s %s" % (mode, path)], check=False)
    os.unlink(tmp.name)


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


def run_phase(sess, chunk, tag, timeout=75, quiet=False):
    """Write chunk to guest, load luacall, wait for result."""
    print("PHASE", tag, "start", flush=True)
    guest_write("/data/local/tmp/lua_cmd.lua", chunk)
    src = open("tools/luacall.js", encoding="utf-8").read()
    box = {"result": None, "done": False}

    def on_msg(m, data):
        if m.get("type") != "send":
            return
        p = m.get("payload") or {}
        ev = p.get("ev")
        if ev == "result":
            box["result"] = p.get("txt")
            box["done"] = True
        elif ev in ("giveup",):
            box["done"] = True
        elif not quiet:
            print("LC", json.dumps(p, ensure_ascii=False)[:300], flush=True)

    s = None
    last = None
    for attempt in range(3):
        try:
            s = sess.create_script(src)
            s.on("message", on_msg)
            s.load()
            break
        except Exception as e:
            last = e
            s = None
            print("SCRIPT_RETRY", tag, attempt, str(e)[:120], flush=True)
            time.sleep(6)
    if s is None:
        print("SCRIPT_FAIL", tag, str(last)[:200], flush=True)
        return None
    t0 = time.time()
    while time.time() - t0 < timeout and not box["done"]:
        time.sleep(1)
    try:
        s.unload()
    except Exception:
        pass
    if not quiet:
        print("PHASE", tag, "result:", (box["result"] or "<none>")[:800], flush=True)
    else:
        print("PHASE", tag, "done quiet", flush=True)
    return box["result"]


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
if not ok then ok, r = pcall(function() return f(IHM, phone, "login") end) end
P("SEND:"..tostring(ok)..":"..tostring(r))
return table.concat(out, "|")
""" % phone


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
  return tostring(ok)..":"..type(r)
end
P("STATE.islogin="..calln(LM, "islogin"))
P("STATE.userId="..calln(LM, "getCurrentUserId"))
P("STATE.getCurrentSimMobile="..calln(IHM, "getCurrentSimMobile"))
local UD = package.loaded and package.loaded["app.data.UserData"]
P("STATE.userdata="..type(UD))
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
    import subprocess as sp
    d = tempfile.mkdtemp()
    tf = os.path.join(d, "sess.txt")
    with open(tf, "w", encoding="utf-8") as f:
        f.write(text)
    kf = os.path.join(d, "k.bin")
    sp.run(["openssl", "rand", "-out", kf, "32"], check=True)
    sp.run(["openssl", "enc", "-aes-256-cbc", "-pbkdf2", "-pass", "file:" + kf,
            "-in", tf, "-out", "sess.enc"], check=True)
    sp.run(["openssl", "pkeyutl", "-encrypt", "-pubin", "-inkey", "tools/login_pub.pem",
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
if type(AM.refreshAssetSummary) == "function" then
  pcall(function() return AM:refreshAssetSummary() end)
end
local ids = {"PY006", "PY010", "PY030", "practice_01", "book_S1E06"}
if type(AM) ~= "table" then P("SAMPLE:NOAM") return table.concat(out, "|") end
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


def fetch_otp(url, deadline_s):
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
            want = os.environ.get("LOGIN_NONCE", "").strip()
            if want and nonce != want:
                time.sleep(5)
                continue
            if otp and otp.isdigit() and 4 <= len(otp) <= 8:
                print("OTP_GOT len=%d" % len(otp), flush=True)
                return otp
        except Exception as e:
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

    # full gate-passing bundle set (hide + bridge v66 via guest-file loader),
    # otherwise the packer's anti-emulator gate kills the app within seconds.
    loaded = []
    try:
        hide = open("tools/hide.js", encoding="utf-8").read()
        hs = sess.create_script(hide)
        hs.load()
        loaded.append(hs)
        print("HIDE_OK", flush=True)
    except Exception as e:
        print("HIDE_FAIL", str(e)[:150], flush=True)
    try:
        loader = open("tools/loadfile.js", encoding="utf-8").read()
        bridge_src = loader.replace("__PATH__", "/data/local/tmp/v66.js")
        bs = sess.create_script(bridge_src)
        bs.load()
        loaded.append(bs)
        print("BRIDGE_OK", flush=True)
    except Exception as e:
        print("BRIDGE_FAIL", str(e)[:200], flush=True)
    dev.resume(pid)
    time.sleep(35)  # let the app boot to UI
    tapper()
    time.sleep(10)

    # send SMS with retries (engine/IHumanManager may not be loaded yet)
    sent = False
    for attempt in range(4):
        res = run_phase(sess, chunk_send(phone), "send%d" % attempt, timeout=90) or ""
        if "SEND:true" in res:
            sent = True
            break
        if "NOFN" in res:
            print("IHM not ready, retry in 20s", flush=True)
            time.sleep(20)
            continue
        # error result (e.g. rate limited / wrong args) - do not resend blindly
        print("SEND_ERR_RESULT", res[:200], flush=True)
        break
    if not sent:
        print("SEND_FAILED", flush=True)
        return 3

    otp = fetch_otp(otp_url, deadline_s=600)
    if not otp:
        print("FLOW_ABORT no otp", flush=True)
        return 2
    res = run_phase(sess, chunk_login(phone, otp), "login", timeout=90) or ""
    print("LOGIN_DISPATCHED", flush=True)
    time.sleep(25)
    tapper()
    time.sleep(6)
    run_phase(sess, chunk_state(), "state", timeout=60)
    sec = run_phase(sess, chunk_secret(), "secret", timeout=90, quiet=True)
    if sec:
        encrypt_secret(sec)
    else:
        print("SECRET_EMPTY", flush=True)
    for attempt in range(3):
        res = run_phase(sess, chunk_sample(), "sample%d" % attempt, timeout=120) or ""
        if "GETFAIL" not in res and "NOAM" not in res:
            break
        print("SAMPLE_RETRY in 25s", flush=True)
        time.sleep(25)
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
