#!/usr/bin/env python3
"""Repack an APK with byte patches applied.

usage: patch.py in.apk out.apk patches.json

patches.json is a list of:
  {"name": "...", "file": "lib/arm64-v8a/libil2cpp.so",
   "find": "AA BB ?? DD", "replace": "AA BB ?? 00"}
"??" in find = any byte; "??" in replace = keep the original byte.
Each pattern must match exactly once, otherwise the run fails.
"""
import json, re, shutil, sys, zipfile


def hexbytes(s):
    return [None if p == "??" else int(p, 16) for p in s.split()]


def apply_patch(data, spec):
    find, rep = hexbytes(spec["find"]), hexbytes(spec["replace"])
    if len(find) != len(rep):
        sys.exit(f"{spec['name']}: find/replace length differ")
    rx = re.compile(
        b"".join(b"." if b is None else re.escape(bytes([b])) for b in find), re.DOTALL
    )
    hits = list(rx.finditer(data))
    if len(hits) != 1:
        sys.exit(f"{spec['name']}: expected 1 match, found {len(hits)}")
    start = hits[0].start()
    buf = bytearray(data)
    for i, b in enumerate(rep):
        if b is not None:
            buf[start + i] = b
    print(f"patched {spec['name']} at offset {start:#x}")
    return bytes(buf)


def main(src, dst, patch_file):
    specs = json.load(open(patch_file))
    by_file = {}
    for s in specs:
        by_file.setdefault(s["file"], []).append(s)
    if not specs:
        print("WARNING: patches.json is empty, repacking without changes")
    seen = set()
    with zipfile.ZipFile(src) as zin, zipfile.ZipFile(dst, "w") as zout:
        for item in zin.infolist():
            name = item.filename
            if name.startswith("META-INF/") and name.endswith((".MF", ".SF", ".RSA", ".DSA", ".EC")):
                continue  # old signature, re-signed later
            zi = zipfile.ZipInfo(name, item.date_time)
            zi.compress_type = item.compress_type
            zi.external_attr = item.external_attr
            if name in by_file:
                data = zin.read(name)
                for s in by_file[name]:
                    data = apply_patch(data, s)
                zout.writestr(zi, data)
                seen.add(name)
            else:
                with zin.open(item) as a, zout.open(zi, "w") as b:
                    shutil.copyfileobj(a, b, 1 << 20)
    missing = set(by_file) - seen
    if missing:
        sys.exit(f"files not found in APK: {missing}")


if __name__ == "__main__":
    if len(sys.argv) != 4:
        sys.exit(__doc__)
    main(*sys.argv[1:])
