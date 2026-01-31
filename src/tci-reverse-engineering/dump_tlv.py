#!/usr/bin/env python3
"""Dump TLV records from a TCI file starting at 0x40."""

import struct


def read_u32le(data, offset):
    if offset + 4 > len(data):
        return None
    return struct.unpack_from('<I', data, offset)[0]


def main():
    path = 'tci/sine_440hz.tci'
    with open(path, 'rb') as f:
        data = f.read()

    offset = 0x40
    print(f"Start offset: 0x{offset:04x}")
    for i in range(30):
        tag = read_u32le(data, offset)
        size = read_u32le(data, offset + 4)
        if tag is None or size is None:
            break
        print(f"{i:2d}: tag={tag} size={size} offset=0x{offset:04x}")
        offset += 8 + size


if __name__ == '__main__':
    main()
