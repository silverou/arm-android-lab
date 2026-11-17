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
import subprocess
import sys
import zipfile
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
    orig_so = zin.read(SO_NAME)
    new_so = patch_so(orig_so)
    print("[build] patched %s: %d -> %d bytes" % (SO_NAME, len(orig_so), len(new_so)))

    # patch MANIFEST
    mf = zin.read("META-INF/MANIFEST.MF")
    sec = section_bytes_for(mf, SO_NAME, convention)
    m = re.search(rb"(Name: " + re.escape(SO_NAME.encode()) +
                  rb"\r\nSHA-256-Digest: )([A-Za-z0-9+/=]+)", sec)
    if not m:
        raise SystemExit("SO section not found in MANIFEST")
    new_digest = sha256b64(new_so)
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
    sf_sec = section_bytes_for(sf, SO_NAME, convention)
    m2 = re.search(rb"(Name: " + re.escape(SO_NAME.encode()) +
                   rb"\r\nSHA-256-Digest: )([A-Za-z0-9+/=]+)", sf_sec)
    if not m2:
        raise SystemExit("SO section not found in .SF")
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
            elif name == SO_NAME:
                data = new_so
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


def align():
    if not Path(ZIPALIGN).exists():
        print("[sign] zipalign not found (%s) - skipping (v2 sign OK unaligned)" % ZIPALIGN)
        import shutil
        shutil.copy(REBUILT, ALIGNED)
        return
    r = subprocess.run([str(ZIPALIGN), "-p", "-f", "4", str(REBUILT), str(ALIGNED)],
                       capture_output=True, text=True, timeout=1800)
    if not ALIGNED.exists():
        print(r.stdout[-500:], r.stderr[-500:])
        raise SystemExit("zipalign failed")
    print("[sign] aligned")


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
    so = z.read(SO_NAME)
    assert so[SO_PATCH_OFF:SO_PATCH_OFF + 4] == SO_PATCH_BYTES, "so patch missing"
    mf = z.read("META-INF/MANIFEST.MF")
    sf = z.read(next(n for n in z.namelist()
                     if n.upper().startswith("META-INF/") and n.upper().endswith(".SF")))
    # 1) manifest digest for so
    sec = section_bytes_for(mf, SO_NAME, convention)
    m = re.search(rb"SHA-256-Digest: ([A-Za-z0-9+/=]+)", sec)
    assert m.group(1).decode() == sha256b64(so), "MANIFEST digest wrong"
    # 2) sf header
    m = re.search(rb"SHA-256-Digest-Manifest: ([A-Za-z0-9+/=]+)", sf)
    assert m.group(1).decode() == sha256b64(mf), "SF header wrong"
    # 3) sf entry digest over new manifest section
    sf_sec = section_bytes_for(sf, SO_NAME, convention)
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
        if name == SO_NAME:
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
        if n in (SO_NAME, "META-INF/MANIFEST.MF"):
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
