// Force-load every class recorded in our dex dumps, then dump the dex
// mappings from memory. The shell restores method bodies per class at
// class-load time; classes never loaded by the original session remain
// stubbed in our dumps.
import Java from "frida-java-bridge";

const LIST = "/data/local/tmp/classlist.txt";
const DIR = "/data/user/0/com.ihuman.pinyin/files/";

function readText(path) {
  const f = new File(path, "r");
  const data = f.readAll();
  f.close();
  if (typeof data === "string") return data;
  const u = new Uint8Array(data);
  const CH = 0x4000;
  let s = "";
  for (let i = 0; i < u.length; i += CH) {
    s += String.fromCharCode.apply(null, u.subarray(i, Math.min(i + CH, u.length)));
  }
  return s;
}

function writeBytes(path, bytes) {
  const f = new File(path, "wb");
  f.write(bytes);
  f.close();
}

function findLoader() {
  let loaders;
  try {
    loaders = Java.enumerateClassLoadersSync();
  } catch (e) {
    return null;
  }
  for (const l of loaders) {
    try {
      l.loadClass("org.cocos2dx.lua.AppActivity");
      return l;
    } catch (e) {}
  }
  return null;
}

function dumpDex(tag) {
  let ranges;
  try {
    ranges = Process.enumerateRanges("r--");
  } catch (e) {
    send({ ev: "range_err", e: String(e) });
    return;
  }
  let n = 0;
  for (const r of ranges) {
    if (r.size < 4096 || r.size > 64 * 1024 * 1024) continue;
    let sig = null;
    try {
      sig = r.base.readCString(4);
    } catch (e) {
      continue;
    }
    if (sig !== "dex\n") continue;
    n++;
    try {
      const size = Math.min(r.size, 32 * 1024 * 1024);
      const bytes = r.base.readByteArray(size);
      const name = "dexdump_" + tag + "_" + n + "_" + r.base.toString().replace("0x", "") + ".bin";
      writeBytes(DIR + name, bytes);
      send({ ev: "dexdump", file: name, base: r.base.toString(), size: size });
    } catch (e) {
      send({ ev: "dexdump_err", base: r.base.toString(), e: String(e) });
    }
  }
  send({ ev: "dexdump_done", tag: tag, found: n });
}

function main() {
  const re = /^[A-Za-z_$][\w$]*(\.[A-Za-z_$][\w$]*)*$/;
  let names = [];
  try {
    names = readText(LIST).split("\n").map(s => s.trim()).filter(s => s && re.test(s));
  } catch (e) {
    send({ ev: "list_err", e: String(e) });
    return;
  }
  send({ ev: "list_ok", count: names.length });

  let waited = 0;
  const timer = setInterval(() => {
    waited++;
    const loader = findLoader();
    if (!loader) {
      if (waited > 120) {
        clearInterval(timer);
        send({ ev: "loader_timeout" });
        dumpDex("late");
      }
      return;
    }
    clearInterval(timer);
    send({ ev: "loader_ok", waited });

    let ok = 0;
    let err = 0;
    const errs = [];
    for (let i = 0; i < names.length; i++) {
      try {
        loader.loadClass(names[i]);
        ok++;
      } catch (e) {
        err++;
        if (errs.length < 30) errs.push(names[i] + ": " + String(e).slice(0, 120));
      }
      if ((i + 1) % 2000 === 0) send({ ev: "load_progress", done: i + 1, ok: ok, err: err });
    }
    send({ ev: "load_done", ok: ok, err: err, errs: errs });
    setTimeout(() => dumpDex("full"), 5000);
  }, 1000);
}

Java.perform(main);
