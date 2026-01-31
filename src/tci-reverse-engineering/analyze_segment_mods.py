#!/usr/bin/env python3
"""Analyze segment length mod patterns per control byte."""

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
            seg_len = i - seg_start
            segments.append((control, seg_start, seg_len))
        else:
            i += 1
    return segments


def main():
    data = read_tci('tci/sine_440hz.tci')
    segments = analyze_segments(data, 0x80)

    mods = {1: defaultdict(int), 2: defaultdict(int), 3: defaultdict(int), 4: defaultdict(int)}
    for c, _, length in segments:
        mods[1][(c, length % 1)] += 1
        mods[2][(c, length % 2)] += 1
        mods[3][(c, length % 3)] += 1
        mods[4][(c, length % 4)] += 1

    for mod in [2, 3, 4]:
        print(f'\nLength mod {mod}:')
        for c in sorted(MARKERS):
            counts = [mods[mod][(c, r)] for r in range(mod)]
            print(f'  0x{c:02x}: ' + ' '.join(f'r{r}={counts[r]:4d}' for r in range(mod)))

    # Also check common small lengths per control
    print('\nMost common lengths per control:')
    by_control = defaultdict(Counter)
    for c, _, length in segments:
        by_control[c][length] += 1
    for c in sorted(MARKERS):
        common = by_control[c].most_common(5)
        print(f'  0x{c:02x}: ' + ', '.join(f'{l}({n})' for l, n in common))


if __name__ == '__main__':
    main()
