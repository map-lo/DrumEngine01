#!/usr/bin/env python3
"""Scan for wave chunk headers in a TCI file."""

import struct


def u32le(data, offset):
    if offset + 4 > len(data):
        return None
    return struct.unpack_from('<I', data, offset)[0]


def main():
    path = 'tci/sine_440hz.tci'
    with open(path, 'rb') as f:
        data = f.read()

    candidates = []
    for offset in range(0, len(data) - 20):
        wave_id = u32le(data, offset)
        data_len = u32le(data, offset + 4)
        if data_len is None:
            continue
        if data_len < 16 or data_len > 10_000_000:
            continue
        channels = data[offset + 8]
        if channels not in (1, 2):
            continue
        bit_len = u32le(data, offset + 9)
        sample_count = u32le(data, offset + 13)
        if bit_len is None or sample_count is None:
            continue
        if sample_count == 0 or sample_count > 1_000_000:
            continue
        payload_len = data_len - 9
        if payload_len <= 0:
            continue
        if offset + 8 + data_len > len(data):
            continue
        # Check if bit_len is plausible relative to payload size
        if bit_len > payload_len * 8 + 32:
            continue

        candidates.append((offset, wave_id, data_len, channels, bit_len, sample_count))

    print(f"Found {len(candidates)} candidates")
    for c in candidates[:20]:
        print(f"offset=0x{c[0]:06x} wave_id={c[1]} len={c[2]} ch={c[3]} bit_len={c[4]} samples={c[5]}")


if __name__ == '__main__':
    main()
