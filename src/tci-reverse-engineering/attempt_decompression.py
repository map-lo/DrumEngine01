#!/usr/bin/env python3
"""
Attempt to decode TCI compression format based on test file patterns.
"""

import struct
import sys

def decode_compression_header(compressed_data):
    """Try to decode the compression header."""
    
    print("Compression header analysis:")
    print(f"  Bytes 0-3:  0x{compressed_data[0:4].hex()} = {struct.unpack('<I', compressed_data[0:4])[0]}")
    print(f"  Bytes 4-7:  0x{compressed_data[4:8].hex()} = {struct.unpack('<I', compressed_data[4:8])[0]}")
    print(f"  Bytes 8-11: 0x{compressed_data[8:12].hex()} = {struct.unpack('<I', compressed_data[8:12])[0]}")
    
    # The constant 0x01580800 appears in all files at bytes 4-8
    # Let's decode it
    val = struct.unpack('<I', compressed_data[4:8])[0]
    print(f"\n  0x01580800 decoded:")
    print(f"    As big-endian: 0x{struct.unpack('>I', compressed_data[4:8])[0]:08x}")
    print(f"    Byte 4: 0x{compressed_data[4]:02x} = {compressed_data[4]}")
    print(f"    Byte 5: 0x{compressed_data[5]:02x} = {compressed_data[5]}")
    print(f"    Byte 6: 0x{compressed_data[6]:02x} = {compressed_data[6]}")
    print(f"    Byte 7: 0x{compressed_data[7]:02x} = {compressed_data[7]}")
    
    # Check if it's related to sample count
    # 192000 bytes = 96000 samples (stereo 16-bit) = 0x017700
    # 88200 (1 sec at 44.1kHz) = 0x015888
    print(f"\n  Potential meanings:")
    print(f"    Sample count theory: 0x01580800 >> 8 = 0x015808 = {0x015808}")
    print(f"    That's 88072 - close to 88200 (1 sec @ 44.1kHz stereo)")
    
    # Byte 8-11 seems to vary
    byte8_11 = struct.unpack('<I', compressed_data[8:12])[0]
    print(f"\n  Bytes 8-11 = {byte8_11}:")
    print(f"    In silence:  0x00010000 = {0x00010000}")
    print(f"    In impulse:  0x6ed270 = {0x6ed270}")
    print(f"    In sine:     0x18 = {0x18}")

def try_decompress_silence(compressed_data, expected_size=192000):
    """Attempt to decompress silence data using observed patterns."""
    
    print(f"\n{'='*80}")
    print("Attempting silence decompression...")
    print('='*80)
    
    # Skip header (looks like first 12 bytes might be header)
    header_size = 12
    data = compressed_data[header_size:]
    
    print(f"Header size: {header_size} bytes")
    print(f"Compressed data: {len(data)} bytes")
    print(f"Expected output: {expected_size} bytes")
    
    # Silence data shows a bit-plane pattern
    # 0x80, 0x40, 0x20, 0x10, 0x08, 0x04, 0x02, 0x01 pattern
    # This suggests each byte encodes a run of zeros with a single bit position
    
    # Let's try to decode it
    output = bytearray()
    i = 0
    
    while i < len(data) and len(output) < expected_size:
        byte = data[i]
        
        if byte == 0x00:
            # Run of zeros
            # Check next byte for count?
            if i + 1 < len(data):
                count = data[i + 1]
                if count > 0:
                    output.extend([0] * count)
                    i += 2
                    continue
        
        # For bit patterns like 0x80, 0x40, etc.
        # These might indicate position or count
        if byte in [0x80, 0x40, 0x20, 0x10, 0x08, 0x04, 0x02, 0x01]:
            # Might be bit-plane encoding
            # Or might indicate position of non-zero bit
            pass
        
        # For now, just copy the byte
        output.append(byte)
        i += 1
    
    print(f"Decoded {len(output)} bytes")
    print(f"First 100 bytes: {output[:100].hex()}")
    print(f"Success rate: {len(output)/expected_size*100:.1f}%")
    
    return bytes(output)

def main():
    # Analyze silence (simplest case)
    print("="*80)
    print("SILENCE.TCI ANALYSIS")
    print("="*80)
    
    with open('tci/silence.tci', 'rb') as f:
        tci_data = f.read()
    
    compressed = tci_data[128:]  # Skip TCI header
    
    decode_compression_header(compressed)
    
    # Try decompression
    decompressed = try_decompress_silence(compressed)
    
    # Compare with original
    with open('tci/silence.wav', 'rb') as f:
        wav_data = f.read()
    
    # Find WAV data chunk
    pos = 12
    while pos < len(wav_data):
        chunk_id = wav_data[pos:pos+4]
        chunk_size = struct.unpack('<I', wav_data[pos+4:pos+8])[0]
        if chunk_id == b'data':
            original = wav_data[pos+8:pos+8+chunk_size]
            break
        pos += 8 + chunk_size
    
    print(f"\n{'='*80}")
    print("COMPARISON:")
    print('='*80)
    print(f"Original WAV: {len(original)} bytes, first 20: {original[:20].hex()}")
    print(f"Decompressed: {len(decompressed)} bytes, first 20: {decompressed[:20].hex()}")
    print(f"Match: {original[:len(decompressed)] == decompressed}")

if __name__ == '__main__':
    main()
