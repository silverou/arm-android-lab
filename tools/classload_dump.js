// Force-load every class recorded in our dex dumps, then dump the dex
// mappings from memory. The shell restores method bodies per class at
// class-load time; classes never loaded by the original session remain
// stubbed in our dumps.
//
// File IO uses native fopen/fread/fwrite (proven loadfile.js pattern);
// the JS File API is not reliable across frida versions.
import Java from "frida-java-bridge";

const LIST = "/data/local/tmp/classlist.txt";
const DIR = "/data/user/0/com.ihuman.pinyin/files/";

const fopen = new NativeFunction(
  Module.getGlobalExportByName("fopen"), "pointer", ["pointer", "pointer"]);
const fwrite = new NativeFunction(
  Module.getGlobalExportByName("fwrite"), "size_t", ["pointer", "size_t", "size_t", "pointer"]);
const fclose = new NativeFunction(
  Module.getGlobalExportByName("fclose"), "int", ["pointer"]);
// read via syscalls exactly like the proven loadfile.js loader
const openF = new NativeFunction(
  Module.getGlobalExportByName("open"), "int", ["pointer", "int", "int"]);
const readF = new NativeFunction(
  Module.getGlobalExportByName("read"), "long", ["int", "pointer", "long"]);
const closeF = new NativeFunction(
  Module.getGlobalExportByName("close"), "int", ["int"]);

function readNative(path) {
  const p = Memory.allocUtf8String(path);
  const fd = openF(p, 0, 0);
  if (fd < 0) throw new Error("open failed: " + path + " code=" + fd);
  const parts = [];
  const buf = Memory.alloc(65536);
  let total = 0;
  for (;;) {
    const n = readF(fd, buf, 65536);
    if (n <= 0) break;
    if (n > 65536) throw new Error("bogus read size " + n);
    total += n;
    if (total > 8 * 1024 * 1024) throw new Error("classlist too large");
    parts.push(buf.readByteArray(n));
  }
  closeF(fd);
  const all = new Uint8Array(total);
  let off = 0;
  for (const p of parts) {
    const u = new Uint8Array(p);
    all.set(u, off);
    off += u.length;
  }
  let s = "";
  for (let i = 0; i < all.length; i += 8192) {
    s += String.fromCharCode.apply(null, all.subarray(i, Math.min(i + 8192, all.length)));
  }
  return s;
}

function writeNative(path, bytes) {
  const fp = fopen(Memory.allocUtf8String(path), Memory.allocUtf8String("wb"));
  if (fp.isNull()) return false;
  const buf = Memory.alloc(bytes.byteLength || bytes.length);
  buf.writeByteArray(bytes);
  fwrite(buf, 1, bytes.byteLength || bytes.length, fp);
  fclose(fp);
  return true;
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
      const bytes = new Uint8Array(r.base.readByteArray(size));
      const name = "dexdump_" + tag + "_" + n + "_" + r.base.toString().replace("0x", "") + ".bin";
      const ok = writeNative(DIR + name, bytes);
      send({ ev: "dexdump", file: name, base: r.base.toString(), size: size, ok: ok });
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
    names = readNative(LIST).split("\n").map(s => s.trim()).filter(s => s && re.test(s));
  } catch (e) {
    send({ ev: "list_err", e: String(e) });
    return;
  }
  send({ ev: "list_ok", count: names.length });

  let waited = 0;
  const timer = setInterval(() => {
    waited++;
    // let the app finish its own boot (shell init + Application + activity)
    // before we force-load classes; early loads race the packer init
    if (waited <= 15) {
      if (waited === 15) send({ ev: "boot_wait_done" });
      return;
    }
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
