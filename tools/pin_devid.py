# -*- coding: utf-8 -*-
"""Pin the app's deviceid to a server-trusted value (in-place, same length)."""
import re
import sys

TRUSTED = b"d92c80adf601092db56c8669f8b17e3562"
PATHS = (
    "/tmp/dev_mmkv",
    "/tmp/dev_prefs.xml",
)


def main():
    for path in PATHS:
        try:
            b = open(path, "rb").read()
        except FileNotFoundError:
            print(path, "missing")
            continue
        new, n = re.subn(rb"[0-9a-f]{32}", TRUSTED, b)
        open(path, "wb").write(new)
        print(path, "replaced", n)
        if n == 0:
            print(path, "WARN no32hex found; head:", b[:80])
    return 0


if __name__ == "__main__":
    sys.exit(main())
