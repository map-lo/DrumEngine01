#!/usr/bin/env python3
"""Analyze segment payloads for length-2 patterns (possible 16-bit values)."""

import struct
from collections import defaultdict, Counter

MARKERS = {0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80}


def read_tci(path):
    with open(path, 'rb') as f:
        data = f.read()
    if not data.startswith(b'TRIGGER COMPRESSED INSTRUMENT'):
        raise ValueError('Not a TCI file')
    return data


def analyze_segments(data, start_offset):
    segments = []
    i = start_offset
    while i < len(data):
        b = data[i]
        if b in MARKERS:
            control = b
            i += 1
            seg_start = i
            while i < len(data) and data[i] not in MARKERS:
                i += 1
            seg_data = data[seg_start:i]
            segments.append((control, seg_start, seg_data))
        else:
            i += 1
    return segments


def main():
    data = read_tci('tci/sine_440hz.tci')
    segments = analyze_segments(data, 0x80)

    stats = defaultdict(list)
    len2_counts = Counter()

    for c, _, seg in segments:
        if len(seg) == 2:
            val = struct.unpack('<h', seg)[0]
            stats[c].append(val)
            len2_counts[c] += 1

    print('Length-2 segment stats (as signed 16-bit):')
    for c in sorted(MARKERS):
        vals = stats.get(c, [])
        if not vals:
            print(f'  0x{c:02x}: none')
            continue
        print(
            f'  0x{c:02x}: count={len(vals):4d}, '
            f'min={min(vals):6d}, max={max(vals):6d}, avg={sum(vals)/len(vals):8.2f}'
        )

    # Also show most common length-2 values per control
    print('\nMost common length-2 values per control (top 5):')
    for c in sorted(MARKERS):
        vals = stats.get(c, [])
        if not vals:
            continue
        counter = Counter(vals)
        common = ', '.join(f'{v}({n})' for v, n in counter.most_common(5))
        print(f'  0x{c:02x}: {common}')


if __name__ == '__main__':
    main()
