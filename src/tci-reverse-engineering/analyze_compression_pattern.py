#!/usr/bin/env python3
"""
Analyze the TCI compression pattern by comparing compressed data with expected output.
"""

import struct
import sys

def analyze_sine_pattern():
    """Analyze the sine wave compression to understand the algorithm."""
    
    # Read the sine TCI
    with open('tci/sine_440hz.tci', 'rb') as f:
        data = f.read()
    
    # Skip header (32 bytes)
    header = data[:32]
    print(f"Header: {header[:30]}")
    
    # Read metadata size
    meta_size = struct.unpack('<I', data[32:36])[0]
    print(f"Metadata size at offset 32: {meta_size}")
    
    # Find where audio data actually starts
    # Look for the repeating pattern
    print("\n=== Searching for audio data start ===")
    
    # The sine wave should have increasing values
    # Let's look at different offsets
    offsets_to_check = [0x60, 0x80, 0x90, 0x50, 0x70]
    
    for offset in offsets_to_check:
        print(f"\nOffset 0x{offset:04x}:")
        chunk = data[offset:offset+48]
        
        # Show hex
        for i in range(0, min(len(chunk), 48), 16):
            hex_str = ' '.join(f'{b:02x}' for b in chunk[i:i+16])
            print(f"  {i:04x}: {hex_str}")
        
        # Try to interpret as 24-bit samples
        print("  As 24-bit LE samples:")
        samples = []
        for i in range(0, min(len(chunk), 48), 3):
            if i+3 <= len(chunk):
                # Little-endian 24-bit
                val = chunk[i] | (chunk[i+1] << 8) | (chunk[i+2] << 16)
                if val & 0x800000:  # Sign extend
                    val -= 0x1000000
                samples.append(val)
        print(f"    First 10 samples: {samples[:10]}")
        
        # Check for repeating patterns (stereo)
        pairs = []
        for i in range(0, len(samples)-1, 2):
            if i+1 < len(samples):
                pairs.append((samples[i], samples[i+1]))
        print(f"    As stereo pairs (L,R): {pairs[:5]}")
    
    # Now let's look for marker bytes
    print("\n=== Searching for marker bytes (0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80) ===")
    marker_bytes = {0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80}
    
    for i, byte in enumerate(data[0x60:0x200]):
        if byte in marker_bytes:
            abs_offset = 0x60 + i
            # Show context
            context_start = max(0, i-4)
            context_end = min(len(data)-0x60, i+12)
            context = data[0x60+context_start:0x60+context_end]
            hex_str = ' '.join(f'{b:02x}' for b in context)
            print(f"  Marker 0x{byte:02x} at offset 0x{abs_offset:04x}: {hex_str}")

def compare_files():
    """Compare silence, impulse, and sine to find patterns."""
    
    print("\n=== COMPARING THREE TEST FILES ===\n")
    
    files = ['silence.tci', 'impulse.tci', 'sine_440hz.tci']
    
    for filename in files:
        with open(f'tci/{filename}', 'rb') as f:
            data = f.read()
        
        print(f"{filename}:")
        print(f"  Total size: {len(data)} bytes")
        
        # Check metadata size
        if len(data) >= 36:
            meta_size = struct.unpack('<I', data[32:36])[0]
            print(f"  Metadata size: {meta_size}")
        
        # Show first different offset
        offset = 0x60
        chunk = data[offset:offset+32]
        hex_str = ' '.join(f'{b:02x}' for b in chunk[:32])
        print(f"  Data at 0x{offset:04x}: {hex_str}")
        
        # Count marker bytes
        marker_bytes = {0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80}
        marker_count = sum(1 for b in data if b in marker_bytes)
        print(f"  Marker byte count: {marker_count}")
        print()

def extract_control_bytes():
    """Extract and analyze control byte sequences."""
    
    print("\n=== ANALYZING CONTROL BYTE PATTERNS ===\n")
    
    with open('tci/sine_440hz.tci', 'rb') as f:
        data = f.read()
    
    # Start from where we see actual data
    start = 0x60
    compressed = data[start:start+500]
    
    print("Looking for patterns in compressed data:")
    print("Hypothesis: Marker bytes indicate following data structure\n")
    
    marker_bytes = {0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80}
    
    i = 0
    chunks = []
    while i < len(compressed):
        byte = compressed[i]
        
        if byte in marker_bytes:
            # This is a control byte
            # Collect following data until next marker
            chunk_start = i
            i += 1
            data_bytes = []
            
            while i < len(compressed) and compressed[i] not in marker_bytes:
                data_bytes.append(compressed[i])
                i += 1
            
            chunks.append({
                'control': byte,
                'offset': start + chunk_start,
                'data': bytes(data_bytes),
                'length': len(data_bytes)
            })
        else:
            i += 1
    
    print(f"Found {len(chunks)} control byte sequences:\n")
    for idx, chunk in enumerate(chunks[:15]):  # Show first 15
        hex_data = ' '.join(f'{b:02x}' for b in chunk['data'][:16])
        print(f"  {idx:2d}. Control=0x{chunk['control']:02x} at 0x{chunk['offset']:04x}, "
              f"{chunk['length']:3d} bytes: {hex_data}{'...' if chunk['length'] > 16 else ''}")

if __name__ == '__main__':
    analyze_sine_pattern()
    compare_files()
    extract_control_bytes()
