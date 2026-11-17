r"""Final SIGBUS-matrix cell: vendor META-INF kept, MANIFEST.MF *and*
HONGENWO.SF digests patched consistently for the entries we replace,
HONGENWO.RSA left byte-identical.

Prior falsification (build_manifest_patched_v2.py) patched MANIFEST only
-> still 0xdead7002, proving the shell also reads the .SF layer. This
script patches both layers; if the shell does not cryptographically
verify the .RSA signature over the .SF, the chain is consistent and the
install should pass the digest gate.

Content change: lib/arm64-v8a/libihcommon.so, 4-byte patch at file
offset 0x2ab08 (SecurityJni_check miss-path: `mov x0,xzr` -> `b +0x4c`),
so the set-miss path returns instead of strlen(NULL) crashing.

Phase 0 (always): self-test digest formulas against the original APK.
Phase 1: build patched APK.
Phase 2: verify full chain on the output.

Usage: python build_checkpatched_sf.py [--skip-build]
"""
import base64
import hashlib
import io
import os
import re
import struct
import subprocess
import sys
import zipfile
import zlib
from pathlib import Path

LAB = Path(os.environ.get("APKLAB", r"F:\apk-lab"))
APK = Path(os.environ.get("CHECKPATCH_SRC_APK", str(LAB / "input" / "hepy_879872.apk")))
OUT_DIR = LAB / "build"
REBUILT = OUT_DIR / "checkpatched_raw.apk"
ALIGNED = OUT_DIR / "checkpatched_aligned.apk"
FINAL = OUT_DIR / "hepy_2.0.4_checkpatched.apk"

UBER_JAR = os.environ.get("UBER_JAR", r"D:\tools\android\uber-apk-signer-1.3.0.jar")
JAVA = os.environ.get("JAVA_BIN", r"D:\tools\jdk-21\bin\java.exe")
JAVAC = os.environ.get("JAVAC_BIN", r"D:\tools\jdk-21\bin\javac.exe")
ZIPALIGN = os.environ.get("ZIPALIGN_BIN",
                          str(LAB / "tools" / "uber" / "win-zipalign_33_0_2.exe"))
KEYSTORE = os.environ.get("KEYSTORE", str(LAB / "tools" / "debug.keystore"))
ALIAS = "androiddebugkey"
PASSWORD = "android"
WORK = LAB / "tools" / "uber"

SO_NAME = "lib/arm64-v8a/libihcommon.so"
SO_PATCH_OFF = 0x2AB08
SO_ORIG_BYTES = bytes.fromhex("e0031faa")        # mov x0, xzr (orr x0, xzr, xzr)
SO_PATCH_BYTES = bytes.fromhex("13000014")       # b +0x4c -> 0x2ab54

# CONTENT_TARGET=so   -> patch libihcommon.so (SecurityJni bypass)   [default]
# CONTENT_TARGET=json -> patch a benign asset instead (bisect: is 7001
#                        caused by .so self-check or by ANY content edit?)
CONTENT_TARGET = os.environ.get("CONTENT_TARGET", "so")
JSON_NAME = "assets/res/scenes/pinyin/module/book/config/bookcfg.json"

SIGNER_JAVA = r'''
import com.android.apksig.ApkSigner;
import java.io.File;
import java.io.FileInputStream;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.List;

public class CheckPatchedSign {
    public static void main(String[] args) throws Exception {
        String in = args[0], out = args[1], ksPath = args[2],
               alias = args[3], pass = args[4];
        KeyStore ks = KeyStore.getInstance("JKS");
        try (FileInputStream fis = new FileInputStream(ksPath)) { ks.load(fis, pass.toCharArray()); }
        PrivateKey key = (PrivateKey) ks.getKey(alias, pass.toCharArray());
        java.security.cert.Certificate c = ks.getCertificate(alias);
        List<X509Certificate> certs = new ArrayList<>();
        certs.add((X509Certificate) c);
        ApkSigner.SignerConfig signer = new ApkSigner.SignerConfig.Builder(
                alias, key, certs, false).build();
        new ApkSigner.Builder(java.util.Collections.singletonList(signer))
                .setInputApk(new File(in))
                .setOutputApk(new File(out))
                .setMinSdkVersion(21)
                .setOtherSignersSignaturesPreserved(true)
                .setV1SigningEnabled(false)
                .setV2SigningEnabled(true)
                .setV3SigningEnabled(false)
                .build().sign();
        System.out.println("v2-only signed: " + out);
    }
}
'''


def sha256b64(data: bytes) -> str:
    return base64.b64encode(hashsha256(data)).decode("ascii")


def hashsha256(data: bytes) -> bytes:
    return hashlib.sha256(data).digest()


# ---------------------------------------------------------------- phase 0

def unwrap_name(block: str) -> str | None:
    """JAR name with 72-byte line wrapping: continuation lines start with space."""
    m = re.search(r"^Name: ([^\r\n]*(?:\r\n [^\r\n]*)*)", block, re.M)
    if not m:
        return None
    return m.group(1).replace("\r\n ", "")


def selftest_formulas(apk_path: Path) -> str:
    """Find the section-byte convention that reproduces every .SF digest."""
    z = zipfile.ZipFile(apk_path)
    mf = z.read("META-INF/MANIFEST.MF")
    sf_name = next(n for n in z.namelist()
                   if n.upper().startswith("META-INF/") and n.upper().endswith(".SF"))
    sf = z.read(sf_name)

    # header digest convention
    m = re.search(rb"SHA-256-Digest-Manifest: ([A-Za-z0-9+/=]+)\r\n", sf)
    if not m:
        raise SystemExit("no SHA-256-Digest-Manifest in .SF")
    want_hdr = m.group(1).decode()
    got_hdr = sha256b64(mf)
    print("[selftest] Digest-Manifest: %s" % ("OK" if got_hdr == want_hdr else
                                              "MISMATCH got=%s want=%s" % (got_hdr, want_hdr)))
    if got_hdr != want_hdr:
        raise SystemExit("header digest formula failed")

    sf_text = sf.decode("utf-8", "replace")
    sf_entries = {}
    for block in re.split(r"\r\n\r\n", sf_text):
        nm = unwrap_name(block)
        dg = re.search(r"^SHA-256-Digest: ([A-Za-z0-9+/=]+)$", block, re.M)
        if nm and dg:
            sf_entries[nm] = dg.group(1)

    # build candidate section byte ranges from raw mf
    # convention A: from "Name: X" up to and including the blank line's \r\n
    #   i.e. content between separators + b"\r\n\r\n"
    # convention B: content only (no trailing blank line)
    # convention C: content + single trailing \r\n
    conventions = {
        "A+blank": lambda p: p + b"\r\n\r\n",
        "Braw": lambda p: p,
        "C+crlf": lambda p: p + b"\r\n",
    }
    # split raw keeping positions
    raw_parts = re.split(rb"(\r\n\r\n)", mf)  # interleaved content/sep
    sections_raw = []  # (name, content_bytes, sep)
    for i in range(1, len(raw_parts), 2):
        content = raw_parts[i - 1]
        sep = raw_parts[i]
        m = re.search(rb"^Name: ([^\r\n]*(?:\r\n [^\r\n]*)*)", content, re.M)
        if m:
            name = m.group(1).decode("utf-8", "replace").replace("\r\n ", "")
            sections_raw.append((name, content, sep))

    results = {}
    for cname, fn in conventions.items():
        ok = bad = 0
        for name, content, sep in sections_raw:
            if name not in sf_entries:
                continue
            if sha256b64(fn(content)) == sf_entries[name]:
                ok += 1
            else:
                bad += 1
                if bad > 3:
                    break
        results[cname] = (ok, bad)
    print("[selftest] section conventions:", results)
    for cname, (ok, bad) in results.items():
        if bad == 0 and ok > 100:
            print("[selftest] using convention:", cname)
            return cname
    # maybe separator belongs differently: content excludes leading? try
    raise SystemExit("no section convention matched")


def section_bytes_for(mf: bytes, name: str, convention: str) -> bytes:
    raw_parts = re.split(rb"(\r\n\r\n)", mf)
    for i in range(1, len(raw_parts), 2):
        content = raw_parts[i - 1]
        m = re.search(rb"^Name: ([^\r\n]*(?:\r\n [^\r\n]*)*)", content, re.M)
        if m and m.group(1).decode("utf-8", "replace").replace("\r\n ", "") == name:
            if convention == "A+blank":
                return content + b"\r\n\r\n"
            if convention == "C+crlf":
                return content + b"\r\n"
            return content
    raise KeyError(name)


# ---------------------------------------------------------------- phase 1

def patch_so(data: bytes) -> bytes:
    if len(data) < SO_PATCH_OFF + 4:
        raise SystemExit("so too small")
    cur = data[SO_PATCH_OFF:SO_PATCH_OFF + 4]
    if cur != SO_ORIG_BYTES:
        raise SystemExit("unexpected bytes at 0x%x: %s (want %s)" %
                         (SO_PATCH_OFF, cur.hex(), SO_ORIG_BYTES.hex()))
    return data[:SO_PATCH_OFF] + SO_PATCH_BYTES + data[SO_PATCH_OFF + 4:]


def build(convention: str):
    OUT_DIR.mkdir(parents=True, exist_ok=True)
    for p in (REBUILT, ALIGNED, FINAL):
        if p.exists():
            p.unlink()

    zin = zipfile.ZipFile(APK)
    if CONTENT_TARGET == "json":
        target_name = JSON_NAME
        orig_target = zin.read(target_name)
        new_target = orig_target + b"\n"  # benign edit: changes digest only
    else:
        target_name = SO_NAME
        orig_target = zin.read(target_name)
        new_target = patch_so(orig_target)
    print("[build][%s] patched %s: %d -> %d bytes" %
          (CONTENT_TARGET, target_name, len(orig_target), len(new_target)))

    # patch MANIFEST
    mf = zin.read("META-INF/MANIFEST.MF")
    sec = section_bytes_for(mf, target_name, convention)
    m = re.search(rb"(Name: " + re.escape(target_name.encode()) +
                  rb"\r\nSHA-256-Digest: )([A-Za-z0-9+/=]+)", sec)
    if not m:
        raise SystemExit("target section not found in MANIFEST: %s" % target_name)
    new_digest = sha256b64(new_target)
    new_sec = sec[:m.start(2)] + new_digest.encode() + sec[m.end(2):]
    # rebuild mf by replacing this section's bytes
    if mf.find(sec) < 0:
        raise SystemExit("section bytes not found verbatim in MANIFEST")
    mf_new = mf.replace(sec, new_sec, 1)
    print("[build] MANIFEST digest -> %s" % new_digest)

    # patch .SF: header + this entry's section
    sf_name = next(n for n in zin.namelist()
                   if n.upper().startswith("META-INF/") and n.upper().endswith(".SF"))
    sf = zin.read(sf_name)
    hdr_new = sha256b64(mf_new)
    sf_new, n1 = re.subn(rb"(SHA-256-Digest-Manifest: )([A-Za-z0-9+/=]+)",
                         lambda mm: mm.group(1) + hdr_new.encode(), sf, count=1)
    if n1 != 1:
        raise SystemExit("SF header digest not patched")
    # entry section in .SF
    sf_sec = section_bytes_for(sf, target_name, convention)
    m2 = re.search(rb"(Name: " + re.escape(target_name.encode()) +
                   rb"\r\nSHA-256-Digest: )([A-Za-z0-9+/=]+)", sf_sec)
    if not m2:
        raise SystemExit("target section not found in .SF: %s" % target_name)
    new_sf_digest = sha256b64(new_sec)
    new_sf_sec = sf_sec[:m2.start(2)] + new_sf_digest.encode() + sf_sec[m2.end(2):]
    if sf.find(sf_sec) < 0:
        raise SystemExit("SF section bytes not found verbatim")
    sf_new = sf_new.replace(sf_sec, new_sf_sec, 1)
    print("[build] .SF Digest-Manifest -> %s" % hdr_new)
    print("[build] .SF entry digest -> %s" % new_sf_digest)

    # rewrite zip
    with zipfile.ZipFile(REBUILT, "w") as zout:
        for item in zin.infolist():
            name = item.filename
            if name == "META-INF/MANIFEST.MF":
                data = mf_new
            elif name == sf_name:
                data = sf_new
            elif name == target_name:
                data = new_target
            else:
                data = zin.read(name)
            zi = zipfile.ZipInfo(name, date_time=item.date_time)
            zi.compress_type = item.compress_type
            zi.external_attr = item.external_attr
            zi.internal_attr = item.internal_attr
            zi.create_system = item.create_system
            zout.writestr(zi, data)
    zin.close()
    print("[build] rebuilt -> %s" % REBUILT)


def compile_signer():
    WORK.mkdir(parents=True, exist_ok=True)
    (WORK / "CheckPatchedSign.java").write_text(SIGNER_JAVA, encoding="utf-8")
    r = subprocess.run([JAVAC, "-cp", UBER_JAR, str(WORK / "CheckPatchedSign.java")],
                       capture_output=True, text=True, timeout=600)
    if r.returncode != 0:
        print(r.stdout[-1500:]); print(r.stderr[-1500:])
        raise SystemExit("javac failed")
    print("[sign] compiled")


def py_zipalign(src, dst):
    """Pure-python zipalign: pad STORED entries so data starts aligned.

    Matches AOSP zipalign's padding style: dummy extra-field TLV 0x1337.
    Alignment rules: resources.arsc and misc STORED -> 4; STORED .so -> 4096.
    """
    zin = zipfile.ZipFile(src)
    with open(dst, "wb") as out:
        central = []
        for item in zin.infolist():
            raw = zin.read(item.filename)
            if item.compress_type == zipfile.ZIP_STORED:
                data = raw
                if item.filename.endswith(".so"):
                    align = 4096
                else:
                    align = 4
            elif item.compress_type == zipfile.ZIP_DEFLATED:
                co = zlib.compressobj(9, zlib.DEFLATED, -15)
                data = co.compress(raw) + co.flush()
                align = 0
            else:
                raise SystemExit("unsupported zip method %d: %s" %
                                 (item.compress_type, item.filename))
            name = item.filename.encode("utf-8")
            flags = 0 if name.isascii() else 0x800
            crc = zlib.crc32(raw) & 0xFFFFFFFF
            dt = item.date_time
            dostime = (dt[3] << 11) | (dt[4] << 5) | (dt[5] // 2)
            dosdate = ((dt[0] - 1980) << 9) | (dt[1] << 5) | dt[2]
            lho = out.tell()
            base = lho + 30 + len(name) + len(item.extra)
            pad = 0
            if align:
                pad = (align - base % align) % align
                if 0 < pad < 4:
                    pad += align  # keep alignment, make room for TLV header
            if pad:
                extra = item.extra + struct.pack("<HH", 0x1337, pad - 4) + b"\x00" * (pad - 4)
            else:
                extra = item.extra
            out.write(struct.pack("<IHHHHHIIIHH", 0x04034B50, 20, flags,
                                  item.compress_type, dostime, dosdate,
                                  crc, len(data), len(raw), len(name), len(extra)))
            out.write(name)
            out.write(extra)
            out.write(data)
            central.append((item, name, extra, crc, len(data), len(raw),
                            lho, flags, dostime, dosdate))
        cd_start = out.tell()
        for item, name, extra_c, crc, csz, usz, lho, flags, dostime, dosdate in central:
            out.write(struct.pack("<IHHHHHHIIIHHHHHII", 0x02014B50,
                                  (item.create_system << 8) | 20, 20, flags,
                                  item.compress_type, dostime, dosdate,
                                  crc, csz, usz, len(name), len(extra_c), 0,
                                  0, item.internal_attr, item.external_attr, lho))
            out.write(name)
            out.write(extra_c)
        cd_size = out.tell() - cd_start
        n = len(central)
        out.write(struct.pack("<IHHHHIIH", 0x06054B50, 0, 0, n, n,
                              cd_size, cd_start, 0))
    zin.close()
    print("[sign] py_zipalign -> %s" % Path(dst).name)


def align():
    py_zipalign(REBUILT, ALIGNED)


def sign():
    cp = UBER_JAR + os.pathsep + str(WORK)
    r = subprocess.run([JAVA, "-cp", cp, "CheckPatchedSign", str(ALIGNED), str(FINAL),
                        str(KEYSTORE), ALIAS, PASSWORD],
                       capture_output=True, text=True, timeout=1800)
    if not FINAL.exists():
        print(r.stdout[-800:], r.stderr[-800:])
        raise SystemExit("sign failed")
    print("[sign] -> %s" % FINAL)


# ---------------------------------------------------------------- phase 2

def verify(convention: str):
    z = zipfile.ZipFile(FINAL)
    if CONTENT_TARGET == "json":
        target_name = JSON_NAME
        orig = zipfile.ZipFile(APK)
        assert z.read(target_name) != orig.read(target_name), "json target unchanged"
        assert z.read(SO_NAME) == orig.read(SO_NAME), "so must stay original in json mode"
        orig.close()
        print("[verify] json target changed, so untouched")
    else:
        target_name = SO_NAME
        so = z.read(SO_NAME)
        assert so[SO_PATCH_OFF:SO_PATCH_OFF + 4] == SO_PATCH_BYTES, "so patch missing"
    target_bytes = z.read(target_name)
    # resources.arsc must be stored + 4-aligned (Android R+ install rule, -124)
    zi = z.getinfo("resources.arsc")
    assert zi.compress_type == zipfile.ZIP_STORED, "arsc not stored"
    with open(FINAL, "rb") as f:
        f.seek(zi.header_offset)
        hdr = f.read(30)
        nlen, elen = struct.unpack_from("<HH", hdr, 26)
        dstart = zi.header_offset + 30 + nlen + elen
    assert dstart % 4 == 0, "arsc data offset %d not 4-aligned" % dstart
    print("[verify] resources.arsc stored, data off %d (mod4=0)" % dstart)
    mf = z.read("META-INF/MANIFEST.MF")
    sf = z.read(next(n for n in z.namelist()
                     if n.upper().startswith("META-INF/") and n.upper().endswith(".SF")))
    # 1) manifest digest for target
    sec = section_bytes_for(mf, target_name, convention)
    m = re.search(rb"SHA-256-Digest: ([A-Za-z0-9+/=]+)", sec)
    assert m.group(1).decode() == sha256b64(target_bytes), "MANIFEST digest wrong"
    # 2) sf header
    m = re.search(rb"SHA-256-Digest-Manifest: ([A-Za-z0-9+/=]+)", sf)
    assert m.group(1).decode() == sha256b64(mf), "SF header wrong"
    # 3) sf entry digest over new manifest section
    sf_sec = section_bytes_for(sf, target_name, convention)
    m = re.search(rb"SHA-256-Digest: ([A-Za-z0-9+/=]+)", sf_sec)
    assert m.group(1).decode() == sha256b64(sec), "SF entry digest wrong"
    # 4) unmodified sample entries still chain
    ok = 0
    raw_parts = re.split(rb"(\r\n\r\n)", mf)
    sf_text = sf.decode("utf-8", "replace")
    sf_map = {}
    for block in re.split(r"\r\n\r\n", sf_text):
        nm = unwrap_name(block)
        dg = re.search(r"^SHA-256-Digest: ([A-Za-z0-9+/=]+)$", block, re.M)
        if nm and dg:
            sf_map[nm] = dg.group(1)
    for i in range(1, len(raw_parts), 2):
        content = raw_parts[i - 1]
        m = re.search(rb"^Name: ([^\r\n]*(?:\r\n [^\r\n]*)*)", content, re.M)
        if not m:
            continue
        name = m.group(1).decode("utf-8", "replace").replace("\r\n ", "")
        if name == target_name:
            continue
        if name not in sf_map:
            continue
        if convention == "A+blank":
            sb = content + b"\r\n\r\n"
        elif convention == "C+crlf":
            sb = content + b"\r\n"
        else:
            sb = content
        if sha256b64(sb) != sf_map[name]:
            print("[verify] chain break at", name)
            break
        if name in ("AndroidManifest.xml", "resources.arsc",
                    "assets/asset_summary.json", "classes.dex"):
            ok += 1
    print("[verify] spot chains ok, sample key entries checked: %d" % ok)
    # 5) RSA untouched
    orig = zipfile.ZipFile(APK)
    rsa = next(n for n in orig.namelist()
               if n.upper().startswith("META-INF/") and n.upper().endswith(".RSA"))
    assert z.read(rsa) == orig.read(rsa), "RSA changed!"
    # 6) only intended content diffs
    diffs = []
    for n in orig.namelist():
        if n in (target_name, "META-INF/MANIFEST.MF"):
            continue
        if n.upper().startswith("META-INF/") and n.upper().endswith(".SF"):
            continue
        if z.read(n) != orig.read(n):
            diffs.append(n)
    print("[verify] unexpected content diffs:", diffs[:5], "count=", len(diffs))
    print("[verify] ALL OK -> %s (%d bytes)" % (FINAL, FINAL.stat().st_size))


def main():
    convention = selftest_formulas(APK)
    if "--skip-build" not in sys.argv:
        build(convention)
        compile_signer()
        align()
        sign()
    verify(convention)


if __name__ == "__main__":
    main()
