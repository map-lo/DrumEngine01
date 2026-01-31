#!/usr/bin/env python3
"""
Analyze the bit patterns in compressed TCI data to understand the encoding.
"""

import struct

def analyze_patterns(filename, sample_name):
    print(f"\n{'='*80}")
    print(f"{sample_name.upper()} - BIT PATTERN ANALYSIS")
    print('='*80)
    
    with open(filename, 'rb') as f:
        tci_data = f.read()
    
    # Skip TCI header (128 bytes) and compression header (12 bytes)
    compressed = tci_data[128 + 12:]
    
    print(f"Compressed data size: {len(compressed)} bytes")
    
    # Count byte frequency
    freq = {}
    for byte in compressed:
        freq[byte] = freq.get(byte, 0) + 1
    
    # Show top 20 most common bytes
    print("\nTop 20 most common bytes:")
    for byte, count in sorted(freq.items(), key=lambda x: x[1], reverse=True)[:20]:
        pct = count / len(compressed) * 100
        binary = f"{byte:08b}"
        print(f"  0x{byte:02x} ({byte:3d}) [{binary}]: {count:5d} times ({pct:5.2f}%)")
    
    # Look for run-length patterns
    print("\nLooking for byte pair patterns (possible RLE):")
    pairs = {}
    for i in range(len(compressed) - 1):
        pair = (compressed[i], compressed[i+1])
        pairs[pair] = pairs.get(pair, 0) + 1
    
    # Show top 10 pairs
    for pair, count in sorted(pairs.items(), key=lambda x: x[1], reverse=True)[:10]:
        if count > 5:  # Only show if occurs more than 5 times
            print(f"  [{pair[0]:02x}, {pair[1]:02x}]: {count} times")
    
    # Look for sequences
    print("\nLooking for common 4-byte sequences:")
    sequences = {}
    for i in range(len(compressed) - 3):
        seq = compressed[i:i+4]
        sequences[seq] = sequences.get(seq, 0) + 1
    
    for seq, count in sorted(sequences.items(), key=lambda x: x[1], reverse=True)[:10]:
        if count > 3:
            print(f"  {seq.hex()}: {count} times")
    
    # Analyze entropy of sections
    print("\nEntropy analysis by section (1KB blocks):")
    block_size = 1024
    for i in range(0, min(len(compressed), 10240), block_size):
        block = compressed[i:i+block_size]
        unique = len(set(block))
        print(f"  Bytes {i:5d}-{i+len(block):5d}: {unique:3d} unique bytes ({unique/256*100:.1f}%)")

def main():
    analyze_patterns('tci/silence.tci', 'silence')
    analyze_patterns('tci/impulse.tci', 'impulse')
    analyze_patterns('tci/sine_440hz.tci', 'sine_440hz')

if __name__ == '__main__':
    main()
