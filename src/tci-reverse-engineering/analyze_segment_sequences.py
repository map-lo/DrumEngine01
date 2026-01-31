#!/usr/bin/env python3
"""Analyze sequences of segments to detect run-length or parameter patterns."""

import struct
from collections import Counter, defaultdict

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

    # Analyze pairs: (len2 segment) -> next segment length
    follow_lengths = defaultdict(Counter)
    follow_controls = defaultdict(Counter)

    for idx in range(len(segments) - 1):
        c, _, seg = segments[idx]
        c2, _, seg2 = segments[idx + 1]
        if len(seg) == 2:
            val = struct.unpack('<h', seg)[0]
            follow_lengths[c][len(seg2)] += 1
            follow_controls[c][c2] += 1

    print('Next segment length after length-2 segments (top 5):')
    for c in sorted(MARKERS):
        common = follow_lengths[c].most_common(5)
        if common:
            print(f'  0x{c:02x}: ' + ', '.join(f'{l}({n})' for l, n in common))

    print('\nNext segment control after length-2 segments (top 5):')
    for c in sorted(MARKERS):
        common = follow_controls[c].most_common(5)
        if common:
            print(f'  0x{c:02x}: ' + ', '.join(f'0x{k:02x}({n})' for k, n in common))

    # Analyze if length-2 value correlates with following length (sample count?)
    print('\nChecking if length-2 values match following length:')
    matches = 0
    total = 0
    for idx in range(len(segments) - 1):
        _, _, seg = segments[idx]
        _, _, seg2 = segments[idx + 1]
        if len(seg) == 2:
            val = struct.unpack('<H', seg)[0]  # unsigned
            total += 1
            if val == len(seg2):
                matches += 1
    print(f'  Matches: {matches}/{total}')


if __name__ == '__main__':
    main()
