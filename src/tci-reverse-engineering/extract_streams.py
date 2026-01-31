#!/usr/bin/env python3
import io
import os
import struct
import sys
import zlib
import gzip

MAGICS = [
    (b"\x1F\x8B", "gzip"),
    (b"\x78\x9C", "zlib"),
    (b"\x78\xDA", "zlib"),
]

SIGNATURES = [
    b"TRIGGER COMPRESSED INSTRUMENT\x00",
    b"TRIGGER COMPRESSED INSTRUMENT 2\x00",
    b"TRIGGER COMPRESSED INSTRUMENT 2",
    b"TRIGGER COMPRESSED INSTRUMENT",
]


def find_magic(data, magic):
    start = 0
    while True:
        idx = data.find(magic, start)
        if idx == -1:
            break
        yield idx
        start = idx + 1


def try_gzip(data, offset):
    try:
        with gzip.GzipFile(fileobj=io.BytesIO(data[offset:])) as gz:
            out = gz.read()
        return out
    except Exception:
        return None


def try_zlib(data, offset):
    try:
        return zlib.decompress(data[offset:])
    except Exception:
        return None


def main():
    path = sys.argv[1]
    with open(path, 'rb') as f:
        data = f.read()

    out_dir = os.path.join(os.path.dirname(__file__), "output", "streams")
    os.makedirs(out_dir, exist_ok=True)

    stream_index = 0
    for magic, kind in MAGICS:
        for offset in find_magic(data, magic):
            if kind == "gzip":
                out = try_gzip(data, offset)
            else:
                out = try_zlib(data, offset)
            if not out:
                continue
            stream_index += 1
            out_path = os.path.join(out_dir, f"stream_{stream_index:02d}_{kind}_0x{offset:X}.bin")
            with open(out_path, "wb") as f:
                f.write(out)
            sig_hit = None
            for sig in SIGNATURES:
                if out.startswith(sig):
                    sig_hit = sig
                    break
            print(f"Extracted {kind} stream at 0x{offset:X} -> {out_path} (len={len(out)})")
            if sig_hit:
                print(f"  Starts with signature: {sig_hit}")


if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: extract_streams.py <path>")
        sys.exit(1)
    main()
