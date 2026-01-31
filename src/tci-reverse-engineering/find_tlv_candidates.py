#!/usr/bin/env python3
import struct
import sys

KNOWN_TAGS = {4, 5, 7, 8, 9, 10, 11, 12, 13, 15, 18, 19, 20}


def read_u32le(data, offset):
    if offset + 4 > len(data):
        return None
    return struct.unpack_from('<I', data, offset)[0]


def main():
    path = sys.argv[1]
    with open(path, 'rb') as f:
        data = f.read()

    candidates = []
    for offset in range(0, len(data) - 16):
        tag = read_u32le(data, offset)
        size = read_u32le(data, offset + 4)
        if tag not in KNOWN_TAGS:
            continue
        if size is None or size < 0 or size > len(data) - offset - 8:
            continue
        # Check next 4 tags in sequence
        cursor = offset
        valid = 0
        for _ in range(6):
            t = read_u32le(data, cursor)
            s = read_u32le(data, cursor + 4)
            if t not in KNOWN_TAGS or s is None or s < 0 or cursor + 8 + s > len(data):
                break
            valid += 1
            cursor += 8 + s
        if valid >= 4:
            candidates.append((offset, valid))

    candidates.sort(key=lambda x: -x[1])
    for off, valid in candidates[:10]:
        print(f"candidate offset=0x{off:X} valid_tags={valid}")


if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: find_tlv_candidates.py <path>")
        sys.exit(1)
    main()
