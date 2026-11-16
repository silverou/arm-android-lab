# -*- coding: utf-8 -*-
"""Pin the ihuman SDK device id inside MMKV storage (libmmkv.so, v1.3 file format).

Main file: [u32 actualSize][pb stream], stream = [int32 filler][varint keyLen]
[key][varint valLen][value].  The companion ".crc" file holds a MMKVMetaInfo:
  u32 m_crcDigest   @0x00   = crc32(main[4 : 4+actualSize])
  u32 m_version     @0x04
  u32 m_sequence    @0x08
  u8  m_vector[16]  @0x0C
  u32 m_actualSize  @0x1C
  u32 lastActualSize@0x20
  u32 lastCRCDigest @0x24
Everything the id touches (value bytes, lengths, both CRCs) is rewritten here.
"""
import re
import sys
import zlib

TRUSTED = b"d92c80adf601092db56c8669f8b17e3562"
KEY = b"ih_sdk_save_deviceId_key"
HEXRUN = re.compile(rb"[0-9a-f]{16,64}")


def u32(buf, off):
    return int.from_bytes(buf[off:off + 4], "little")


def put_u32(buf, off, v):
    buf[off:off + 4] = int(v & 0xffffffff).to_bytes(4, "little")


def read_varint(buf, off):
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


def pin(main_path, meta_path):
    main = bytearray(open(main_path, "rb").read())
    actual = u32(main, 0)
    print("main size=%d actual=%d" % (len(main), actual))
    if not (8 <= actual <= len(main) - 4):
        print("BAD actualSize")
        return None
    data = bytes(main[4:4 + actual])
    ki = data.find(KEY)
    if ki < 0:
        print("key not found")
        return None
    p = ki + len(KEY)
    vlen, vw = read_varint(data, p)
    if vlen is None or vlen > 4096:
        print("bad valLen at %d" % p)
        return None
    vstart = p + vw
    value = data[vstart:vstart + vlen]
    hm = HEXRUN.search(value)
    if not hm:
        print("no hex id in value %r" % value[:48])
        return None
    old = hm.group(0)
    if old == TRUSTED:
        print("already pinned %s" % old.decode())
        return old.decode()
    nv = value[:hm.start()] + TRUSTED + value[hm.end():]
    new_data = bytearray(data[:p]) + enc_varint(len(nv)) + nv + data[vstart + vlen:]
    delta = len(new_data) - len(data)
    new_actual = actual + delta
    out = bytearray(main)
    out[0:4] = new_actual.to_bytes(4, "little")
    out[4:4 + len(new_data)] = new_data
    crc = zlib.crc32(bytes(out[4:4 + new_actual])) & 0xffffffff
    open(main_path, "wb").write(out)
    print("main OLDID=%s vlen=%d->%d actual=%d->%d crc=%08x"
          % (old.decode(), vlen, len(nv), actual, new_actual, crc))
    try:
        meta = bytearray(open(meta_path, "rb").read())
    except FileNotFoundError:
        print("meta missing %s" % meta_path)
        return old.decode()
    put_u32(meta, 0x00, crc)          # m_crcDigest
    put_u32(meta, 0x1C, new_actual)   # m_actualSize
    put_u32(meta, 0x20, new_actual)   # lastConfirmed.lastActualSize
    put_u32(meta, 0x24, crc)          # lastConfirmed.lastCRCDigest
    open(meta_path, "wb").write(meta)
    print("meta crc=%08x actual=%d" % (crc, new_actual))
    # verify round trip
    chk = bytearray(open(main_path, "rb").read())
    a2 = u32(chk, 0)
    d2 = bytes(chk[4:4 + a2])
    k2 = d2.find(KEY)
    vl2, vw2 = read_varint(d2, k2 + len(KEY))
    vs2 = k2 + len(KEY) + vw2
    ok = TRUSTED in d2[vs2:vs2 + vl2] and (zlib.crc32(d2) & 0xffffffff) == u32(open(meta_path, "rb").read(), 0)
    print("verify=%s" % ("ok" if ok else "FAIL"))
    return old.decode()


def main():
    if len(sys.argv) < 3:
        print("usage: pin_mmkv.py <main> <meta.crc>")
        return 2
    old = pin(sys.argv[1], sys.argv[2])
    print("OLDID=%s" % (old or ""))
    return 0 if old else 1


if __name__ == "__main__":
    sys.exit(main())
