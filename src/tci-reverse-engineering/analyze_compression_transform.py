#!/usr/bin/env python3
"""
Analyze the actual transformation between compressed TCI and uncompressed WAV data.
Try to reverse engineer the compression algorithm by examining patterns.
"""

import struct
import sys

def load_wav_data(wav_file):
    """Extract raw audio data from WAV file."""
    with open(wav_file, 'rb') as f:
        wav_data = f.read()
    
    # Find data chunk
    pos = 12
    while pos < len(wav_data):
        chunk_id = wav_data[pos:pos+4]
        chunk_size = struct.unpack('<I', wav_data[pos+4:pos+8])[0]
        if chunk_id == b'data':
            return wav_data[pos+8:pos+8+chunk_size]
        pos += 8 + chunk_size
    
    return None

def analyze_compression_header(compressed):
    """Analyze the 12-byte compression header."""
    print("Compression Header Analysis:")
    print(f"  Bytes 0-3:  0x{compressed[0:4].hex()} = {struct.unpack('<I', compressed[0:4])[0]:,}")
    print(f"  Bytes 4-7:  0x{compressed[4:8].hex()} = {struct.unpack('<I', compressed[4:8])[0]:,}")
    print(f"  Bytes 8-11: 0x{compressed[8:12].hex()} = {struct.unpack('<I', compressed[8:12])[0]:,}")
    
    # Try different interpretations
    b0_3 = struct.unpack('<I', compressed[0:4])[0]
    b4_7 = struct.unpack('<I', compressed[4:8])[0]
    b8_11 = struct.unpack('<I', compressed[8:12])[0]
    
    print(f"\n  Interpretations:")
    print(f"    Bytes 0-3: {b0_3} (0x{b0_3:08x})")
    print(f"    Bytes 4-7: {b4_7} (0x{b4_7:08x}) - CONSTANT across all files")
    print(f"    Bytes 8-11: {b8_11} (0x{b8_11:08x})")
    
    return b0_3, b4_7, b8_11

def compare_bytes(original, compressed_data, sample_name):
    """Compare original and compressed data to find patterns."""
    print(f"\n{'='*80}")
    print(f"{sample_name.upper()} - TRANSFORMATION ANALYSIS")
    print('='*80)
    
    # Skip 12-byte compression header
    compressed = compressed_data[12:]
    
    print(f"Original size: {len(original):,} bytes")
    print(f"Compressed size: {len(compressed):,} bytes")
    print(f"Ratio: {len(compressed)/len(original)*100:.1f}%")
    
    # Analyze compression header
    b0_3, b4_7, b8_11 = analyze_compression_header(compressed_data[:12])
    
    # Show first 100 bytes side by side
    print(f"\nFirst 100 bytes comparison:")
    print(f"  Original:     {original[:100].hex()}")
    print(f"  Compressed:   {compressed[:100].hex()}")
    
    # Try to find patterns
    print(f"\nLooking for patterns:")
    
    # Check if compressed data appears in original (might be stored raw in blocks)
    if compressed[:50] in original:
        pos = original.find(compressed[:50])
        print(f"  ✓ First 50 compressed bytes found at original position {pos}")
    else:
        print(f"  ✗ First 50 compressed bytes NOT found in original (transformed)")
    
    # Check for XOR patterns
    print(f"\nTrying XOR with various keys:")
    for xor_key in [0x00, 0xFF, 0x80, 0x55, 0xAA]:
        xored = bytes([b ^ xor_key for b in compressed[:50]])
        if xored in original or original[:50] == xored:
            print(f"  ✓ XOR with 0x{xor_key:02x} matches!")
    
    # Check for byte swapping (big/little endian)
    print(f"\nChecking byte order:")
    # Convert first 4 bytes of original
    orig_16bit = struct.unpack('<50h', original[:100])  # Little-endian 16-bit samples
    orig_16bit_swapped = struct.unpack('>50h', original[:100])  # Big-endian
    print(f"  Original (LE): {orig_16bit[:10]}")
    print(f"  Original (BE): {orig_16bit_swapped[:10]}")
    
    # Try to interpret compressed as 16-bit samples
    if len(compressed) >= 100:
        try:
            comp_16bit = struct.unpack('<50h', compressed[:100])
            print(f"  Compressed (LE): {comp_16bit[:10]}")
        except:
            pass
    
    # Check if data is delta-encoded
    print(f"\nChecking for delta encoding:")
    if len(compressed) >= 4:
        # Assume first sample is stored, then deltas
        deltas = struct.unpack('<h', compressed[:2])[0]
        print(f"  First compressed value: {deltas}")
        print(f"  First original value: {struct.unpack('<h', original[:2])[0]}")
        
        # Try reconstructing with delta
        reconstructed = [deltas]
        for i in range(2, min(100, len(compressed)), 2):
            delta = struct.unpack('<h', compressed[i:i+2])[0]
            reconstructed.append(reconstructed[-1] + delta)
        
        original_samples = [struct.unpack('<h', original[i:i+2])[0] for i in range(0, 100, 2)]
        
        matches = sum(1 for i in range(min(len(reconstructed), len(original_samples))) 
                     if reconstructed[i] == original_samples[i])
        print(f"  Delta reconstruction: {matches}/{min(len(reconstructed), len(original_samples))} matches")
    
    # Check for bit-plane separation
    print(f"\nBit-plane analysis:")
    # Count how many bytes have only one bit set
    single_bit_count = sum(1 for b in compressed[:1000] 
                          if b in [0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80])
    print(f"  Single-bit marker bytes in first 1KB: {single_bit_count} ({single_bit_count/10:.1f}%)")

def main():
    test_files = [
        ('tci/silence.tci', 'tci/silence.wav', 'silence'),
        ('tci/impulse.tci', 'tci/impulse.wav', 'impulse'),
        ('tci/sine_440hz.tci', 'tci/sine_440hz.wav', 'sine_440hz'),
    ]
    
    for tci_file, wav_file, name in test_files:
        # Load files
        with open(tci_file, 'rb') as f:
            tci_data = f.read()
        
        compressed = tci_data[128:]  # Skip TCI header
        original = load_wav_data(wav_file)
        
        compare_bytes(original, compressed, name)

if __name__ == '__main__':
    main()
