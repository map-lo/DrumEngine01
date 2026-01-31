#!/usr/bin/env python3
"""Analyze control-byte segments across a TCI file."""

import struct
from collections import Counter, defaultdict

MARKERS = {0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80}


def read_tci(path):
    with open(path, 'rb') as f:
        data = f.read()
    if not data.startswith(b'TRIGGER COMPRESSED INSTRUMENT'):
        raise ValueError('Not a TCI file')
    meta_size = struct.unpack('<I', data[32:36])[0]
    return data, meta_size


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
            segments.append((control, seg_start, len(seg_data), seg_data))
        else:
            i += 1
    return segments


def dump_summary(segments):
    count_by_control = Counter(c for c, _, _, _ in segments)
    len_by_control = defaultdict(list)
    for c, _, length, _ in segments:
        len_by_control[c].append(length)

    print('Control byte summary:')
    for c in sorted(count_by_control):
        lengths = len_by_control[c]
        print(
            f'  0x{c:02x}: count={count_by_control[c]:5d}, '
            f'len min={min(lengths):4d}, max={max(lengths):5d}, avg={sum(lengths)/len(lengths):7.2f}'
        )


def dump_first_segments(segments, limit=30):
    print('\nFirst segments:')
    for idx, (c, start, length, seg) in enumerate(segments[:limit]):
        preview = ' '.join(f'{b:02x}' for b in seg[:24])
        print(f'{idx:3d}. 0x{c:02x} @ 0x{start:06x} len={length:5d}  {preview}')


def dump_length_histogram(segments, control):
    lengths = [l for c, _, l, _ in segments if c == control]
    if not lengths:
        return
    buckets = Counter()
    for l in lengths:
        if l <= 4:
            buckets['<=4'] += 1
        elif l <= 16:
            buckets['5-16'] += 1
        elif l <= 64:
            buckets['17-64'] += 1
        elif l <= 256:
            buckets['65-256'] += 1
        elif l <= 1024:
            buckets['257-1024'] += 1
        else:
            buckets['>1024'] += 1
    print(f'\nLength histogram for 0x{control:02x}:')
    for k in ['<=4', '5-16', '17-64', '65-256', '257-1024', '>1024']:
        print(f'  {k:>8}: {buckets[k]}')


def main():
    path = 'tci/sine_440hz.tci'
    data, meta_size = read_tci(path)

    # Config starts at 0x60, compressed data at 0x80 for these test files
    compressed_start = 0x80

    print(f'File: {path}')
    print(f'Total size: {len(data)}')
    print(f'Metadata size: {meta_size}')
    print(f'Compressed start: 0x{compressed_start:04x}')

    segments = analyze_segments(data, compressed_start)

    print(f'\nTotal segments: {len(segments)}')
    dump_summary(segments)
    dump_first_segments(segments)

    for control in sorted(MARKERS):
        dump_length_histogram(segments, control)


if __name__ == '__main__':
    main()
