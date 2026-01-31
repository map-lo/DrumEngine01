#!/usr/bin/env python3
import sys

MAGICS = {
    b"\x28\xB5\x2F\xFD": "zstd",
    b"\x1F\x8B": "gzip",
    b"\x78\x9C": "zlib",
    b"\x78\xDA": "zlib",
    b"\x42\x5A\x68": "bzip2",
    b"\x50\x4B\x03\x04": "zip",
    b"\x89PNG": "png",
    b"RIFF": "riff",
}


def main():
    path = sys.argv[1]
    with open(path, 'rb') as f:
        data = f.read()

    hits = []
    for magic, name in MAGICS.items():
        idx = data.find(magic)
        if idx != -1:
            hits.append((idx, name, magic))

    hits.sort()
    for idx, name, magic in hits:
        print(f"{name} at 0x{idx:X} ({idx})")


if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: detect_magic.py <path>")
        sys.exit(1)
    main()
