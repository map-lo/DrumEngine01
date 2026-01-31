#!/usr/bin/env python3
"""Analyze alignment and marker removal effects on compressed data."""

MARKERS = {0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80}


def main():
    path = 'tci/sine_440hz.tci'
    with open(path, 'rb') as f:
        data = f.read()

    compressed = data[0x80:]

    total = len(compressed)
    removed = [b for b in compressed if b in MARKERS]
    kept = [b for b in compressed if b not in MARKERS]

    print(f'Compressed size: {total}')
    print(f'Marker bytes count: {len(removed)}')
    print(f'Non-marker bytes: {len(kept)}')
    print()
    print('Non-marker length mod 3:', len(kept) % 3)
    print('Non-marker length mod 2:', len(kept) % 2)

    # Try removing markers only when they appear at positions that are NOT multiples of 3
    # to see if markers are aligned to sample boundaries.
    aligned_removed = 0
    aligned_kept = 0
    kept_bytes = []
    for i, b in enumerate(compressed):
        if b in MARKERS and (i % 3) != 0:
            aligned_removed += 1
        else:
            kept_bytes.append(b)
            if b in MARKERS:
                aligned_kept += 1

    print('\nHeuristic: remove marker bytes only when not on 3-byte boundary')
    print(f'Removed: {aligned_removed}, kept marker bytes on boundary: {aligned_kept}')
    print('Remaining length:', len(kept_bytes))
    print('Remaining length mod 3:', len(kept_bytes) % 3)


if __name__ == '__main__':
    main()
