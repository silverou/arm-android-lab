"""Strip frida-compile banners and the inline source map from a bundle.

frida-compile emits a UTF-8 header/footer banner (📦/✄) and an inline
source map; the guest-side loader eval()s the file as Latin-1 bytes, so any
non-ASCII outside comments breaks parsing.

Usage: strip_bundle.py <bundle.js>
"""
import re
import sys


def main():
    path = sys.argv[1]
    s = open(path, encoding="utf-8").read()
    i = s.find("var __defProp")
    if i >= 0:
        s = s[i:]
    s = re.split(r"\n✄", s)[0]
    s = re.sub(r"\n//# sourceMappingURL=.*$", "", s, flags=re.S)
    # frida-compile banner glyphs only (keep any non-ASCII inside strings)
    s = s.replace("\U0001F4E6", "").replace("✄", "")
    open(path, "w", encoding="utf-8").write(s)
    print("stripped %s -> %d bytes" % (path, len(s)))
    return 0


if __name__ == "__main__":
    sys.exit(main())
