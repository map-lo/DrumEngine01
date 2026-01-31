#!/usr/bin/env python3
import struct

SIGNATURE = b"TRIGGER COMPRESSED INSTRUMENT\x00"

def read_u32le(data, offset):
    if offset + 4 > len(data):
        return None
    return struct.unpack_from('<I', data, offset)[0]


def find_tlv_start(data):
    sig_index = data.find(SIGNATURE)
    if sig_index == -1:
        return None
    scan_start = sig_index + len(SIGNATURE)
    for offset in range(scan_start, scan_start + 0x100):
        v = [read_u32le(data, offset + i * 4) for i in range(8)]
        if None in v:
            continue
        v1, v2, v3, v4, v5, v6, v7, v8 = v
        if v1 == 1 and v3 == 4 and v4 == 0x15 and v6 == 0 and v7 == 2:
            return offset + 32
    return None


def main():
    path = "/Users/marian/Downloads/SPINLIGHT SAMPLES/Trigger TCI/Vintage 70's Acrolite (Tight)/Vintage 70's Acrolite (Tight) - Close Mic.tci"
    with open(path, 'rb') as f:
        data = f.read()

    tlv_start = find_tlv_start(data)
    if tlv_start is None:
        print("TLV start not found")
        return

    cursor = tlv_start
    payload = None
    bit_len = None
    sample_count = None

    while cursor + 8 <= len(data):
        tag = read_u32le(data, cursor)
        size = read_u32le(data, cursor + 4)
        if tag is None or size is None:
            break
        cursor += 8
        if tag == 5 and size >= 9:
            bit_len = read_u32le(data, cursor + 1)
            sample_count = read_u32le(data, cursor + 5)
            payload_len = size - 9
            payload_start = cursor + 9
            payload = data[payload_start:payload_start + payload_len]
            break
        cursor += size

    if payload is None:
        print("No wave payload found")
        return

    uVar9 = payload[0]
    bit_pos = 8
    block_count = 0
    max_uVar9 = uVar9
    min_uVar9 = uVar9
    big_count = 0
    total_samples = 0

    while total_samples < sample_count:
        if (bit_pos >> 3) + 4 > len(payload):
            break
        total_samples += 1
        block_count += 1
        bit_pos += uVar9
        if uVar9 > 32:
            big_count += 1
        if uVar9 > max_uVar9:
            max_uVar9 = uVar9
        if uVar9 < min_uVar9:
            min_uVar9 = uVar9

        if block_count >= 201:
            byte_index = bit_pos >> 3
            if byte_index + 2 > len(payload):
                break
            uVar9 = ((payload[byte_index + 1] << 16) | (payload[byte_index] << 24))
            uVar9 = ((uVar9 << (bit_pos & 7)) & 0xFFFFFFFF) >> 24
            bit_pos += 8
            block_count = 0

        if bit_pos >= bit_len:
            break

    print(f"bit_len={bit_len} sample_count={sample_count} payload_len={len(payload)}")
    print(f"decoded_samples={total_samples} bit_pos={bit_pos}")
    print(f"uVar9 min={min_uVar9} max={max_uVar9} >32_count={big_count}")


if __name__ == "__main__":
    main()
