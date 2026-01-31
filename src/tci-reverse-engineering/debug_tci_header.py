#!/usr/bin/env python3
import struct

SIGNATURE = b"TRIGGER COMPRESSED INSTRUMENT\x00"


def read_u32le(data, offset):
    if offset + 4 > len(data):
        return None
    return struct.unpack_from('<I', data, offset)[0]


def main():
    path = "/Users/marian/Downloads/SPINLIGHT SAMPLES/Trigger TCI/Vintage 70's Acrolite (Tight)/Vintage 70's Acrolite (Tight) - Close Mic.tci"
    with open(path, 'rb') as f:
        data = f.read()

    sig_index = data.find(SIGNATURE)
    print(f"Signature index: {sig_index}")
    if sig_index == -1:
        return

    scan_start = sig_index + len(SIGNATURE)
    header_offset = None
    for offset in range(scan_start, scan_start + 0x100):
        v = [read_u32le(data, offset + i * 4) for i in range(8)]
        if None in v:
            continue
        v1, v2, v3, v4, v5, v6, v7, v8 = v
        if v1 == 1 and v3 == 4 and v4 == 0x15 and v6 == 0 and v7 == 2:
            print("Found header at", offset, v)
            header_offset = offset
            break

    if header_offset is None:
        print("No matching header found in scan window")
        return

    tlv_start = header_offset + 32
    print("TLV start:", tlv_start)
    cursor = tlv_start
    for i in range(20):
        tag = read_u32le(data, cursor)
        size = read_u32le(data, cursor + 4)
        if tag is None or size is None:
            break
        print(f"Tag {i}: tag={tag} size={size}")
        if tag == 5 and size >= 9:
            channels = data[cursor + 8]
            bit_len = read_u32le(data, cursor + 9)
            sample_count = read_u32le(data, cursor + 13)
            payload_start = cursor + 17
            payload_len = size - 9
            payload = data[payload_start:payload_start + payload_len]
            first_byte = payload[0] if payload else None
            print(
                f"  Wave meta: channels={channels} bit_len={bit_len} "
                f"sample_count={sample_count} payload_len={payload_len} first_byte={first_byte}"
            )
            break
        cursor += 8 + size
        if cursor >= len(data):
            break


if __name__ == "__main__":
    main()
