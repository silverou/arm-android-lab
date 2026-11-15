# -*- coding: utf-8 -*-
"""Rewrite the ihuman SDK device id inside native-MMKV files (libmmkv.so).

MMKV record layout: varint(keyLen) key varint(valueSize) value...
String values are either plain-length or (len << 2) | type encoded; the
file ends with a 4-byte CRC32 of everything before it.  We accept both
length encodings, re-encode the length, and recompute the trailing CRC.
"""
import re
import sys
import zlib

TRUSTED = b"d92c80adf601092db56c8669f8b17e3562"
KEY = b"ih_sdk_save_deviceId_key"
HEX = re.compile(rb"^[0-9a-f]{16,64}$")


def varint_at(buf, off):
    v = 0
    shift = 0
    i = off
    while i < len(buf) and shift <= 35:
        b = buf[i]
        i += 1
        v |= (b & 0x7f) << shift
        if not b & 0x80:
            return v, i - off
        shift += 7
    return None, 0


def enc_varint(v):
    out = bytearray()
    while True:
        b = v & 0x7f
        v >>= 7
        if v:
            out.append(b | 0x80)
        else:
            out.append(b)
            return bytes(out)


def crc_mode(buf):
    if len(buf) < 8:
        return "none"
    calc = zlib.crc32(buf[:-4]) & 0xffffffff
    le = int.from_bytes(buf[-4:], "little")
    be = int.from_bytes(buf[-4:], "big")
    if calc == le:
        return "le"
    if calc == be:
        return "be"
    return "le?"  # unknown, assume little-endian


def find_value(buf):
    p = buf.find(KEY)
    while p >= 0:
        q = p + len(KEY)
        v, w = varint_at(buf, q)
        if v is not None:
            for shift in (0, 2):
                L = v >> shift
                if shift and v & 3:
                    continue
                if 16 <= L <= 64:
                    s = q + w
                    cand = buf[s:s + L]
                    if len(cand) == L and HEX.match(cand):
                        return q, w, s, L, cand, shift
        p = buf.find(KEY, p + 1)
    return None


def patch_file(path):
    try:
        buf = open(path, "rb").read()
    except FileNotFoundError:
        print("%s missing" % path)
        return None
    print("%s size=%d crc=%s head=%s" % (path, len(buf), crc_mode(buf),
                                         buf[:48].hex()))
    hit = find_value(buf)
    if not hit:
        print("%s nokv" % path)
        return None
    q, w, s, L, old, shift = hit
    if old == TRUSTED:
        print("%s already pinned oldid=%s" % (path, old.decode()))
        return old.decode()
    enc = enc_varint(len(TRUSTED) << shift)
    new = buf[:q] + enc + TRUSTED + buf[s + L:]
    if len(buf) >= 8:
        mode = crc_mode(buf)
        crc = zlib.crc32(new[:-4]) & 0xffffffff
        new = new[:-4] + crc.to_bytes(4, "little" if mode != "be" else "big")
        print("%s crc_recalc mode=%s crc=%08x" % (path, mode, crc))
    open(path, "wb").write(new)
    chk = find_value(open(path, "rb").read())
    ok = bool(chk) and chk[4] == TRUSTED
    print("%s patched oldid=%s shift=%d varint=%d->%d size=%d verify=%s"
          % (path, old.decode(), shift, w, len(enc), len(new),
             "ok" if ok else "FAIL"))
    return old.decode()


def main():
    old = None
    for path in sys.argv[1:]:
        r = patch_file(path)
        if r and not old:
            old = r
    print("OLDID=%s" % (old or ""))
    return 0


if __name__ == "__main__":
    sys.exit(main())
