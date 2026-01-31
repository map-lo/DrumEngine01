#!/usr/bin/env python3
"""
TCI decompressor - attempt to decode the proprietary compression format.

Based on analysis:
- Header: 12 bytes
  - Bytes 0-3: Unknown (varies)
  - Bytes 4-7: 0x00085801 (constant, possibly format ID/sample count)
  - Bytes 8-11: Unknown (varies)
  
- Data: Bit-plane RLE encoding
  - Most bytes are 0x00 (runs of zeros)
  - Non-zero bytes are single-bit values: 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80
  - These mark bit positions in the output
"""

import struct
import sys

def decompress_tci_data(compressed_data, expected_size):
    """
    Attempt to decompress TCI data.
    
    Theory: Bit-plane encoding where:
    - 0x00 bytes represent runs of zeros
    - Single-bit bytes (0x01, 0x02, 0x04, etc.) mark positions with data
    """
    
    # Skip 12-byte header
    data = compressed_data[12:]
    
    output = bytearray(expected_size)
    
    # Try interpretation 1: Direct bit-plane decoding
    # Each byte represents which bit plane has data
    bit_position = 0
    
    for i, byte in enumerate(data):
        if byte == 0x00:
            # Run of zeros - move forward
            bit_position += 8  # Move 1 byte forward
        elif byte in [0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80]:
            # Single bit set - mark this position
            byte_pos = bit_position // 8
            bit_in_byte = bit_position % 8
            
            if byte_pos < len(output):
                # Set the bit in the output
                output[byte_pos] |= byte
            
            bit_position += 1
        else:
            # Other bytes might be literal data or counts
            byte_pos = bit_position // 8
            if byte_pos < len(output):
                output[byte_pos] = byte
            bit_position += 8
    
    return bytes(output)

def decompress_tci_data_v2(compressed_data, expected_size):
    """
    Alternative interpretation: RLE with bit-plane markers.
    
    Pattern observed:
    - Sequences of 0x00 followed by a single-bit value
    - The single-bit value might indicate which bit plane or position
    """
    
    data = compressed_data[12:]
    output = bytearray(expected_size)
    
    i = 0
    out_pos = 0
    
    while i < len(data) and out_pos < expected_size:
        byte = data[i]
        
        if byte == 0x00:
            # Count consecutive zeros
            zero_count = 0
            while i < len(data) and data[i] == 0x00:
                zero_count += 1
                i += 1
            
            # Zeros mean output zeros
            out_pos += zero_count
        
        elif byte in [0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80]:
            # Single bit - this might be a marker
            # Or it might be literal data
            if out_pos < len(output):
                output[out_pos] = byte
            out_pos += 1
            i += 1
        
        else:
            # Literal byte
            if out_pos < len(output):
                output[out_pos] = byte
            out_pos += 1
            i += 1
    
    return bytes(output)

def decompress_tci_data_v3(compressed_data, expected_size):
    """
    Key insight from analysis:
    - Single-bit bytes (0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80) are MARKERS not data
    - They appear at regular intervals (positions 24, 50, 76...)
    - They should be SKIPPED, not written to output
    - Everything else is literal data (mostly zeros)
    """
    
    data = compressed_data[12:]
    output = bytearray(expected_size)
    
    i = 0
    out_pos = 0
    
    while i < len(data) and out_pos < expected_size:
        byte = data[i]
        
        # Check if this is a marker byte (single bit set)
        # These should NOT be written to output
        if byte in [0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80]:
            # Skip marker - don't write to output
            i += 1
            continue
        
        # All other bytes (including 0x00) are literal data
        output[out_pos] = byte
        out_pos += 1
        i += 1
    
    return bytes(output)

def test_decompression(tci_file, wav_file, method_name, decompress_func):
    """Test a decompression method against known data."""
    
    print(f"\n{'='*80}")
    print(f"Testing: {method_name}")
    print('='*80)
    
    # Load TCI
    with open(tci_file, 'rb') as f:
        tci_data = f.read()
    
    compressed = tci_data[128:]  # Skip TCI header
    
    # Load WAV
    with open(wav_file, 'rb') as f:
        wav_data = f.read()
    
    # Find data chunk
    pos = 12
    while pos < len(wav_data):
        chunk_id = wav_data[pos:pos+4]
        chunk_size = struct.unpack('<I', wav_data[pos+4:pos+8])[0]
        if chunk_id == b'data':
            original = wav_data[pos+8:pos+8+chunk_size]
            break
        pos += 8 + chunk_size
    
    print(f"Original: {len(original)} bytes")
    print(f"Compressed: {len(compressed)} bytes (ratio: {len(compressed)/len(original)*100:.1f}%)")
    
    # Decompress
    decompressed = decompress_func(compressed, len(original))
    
    print(f"Decompressed: {len(decompressed)} bytes")
    
    # Compare
    if len(decompressed) == len(original):
        matches = sum(1 for i in range(len(original)) if original[i] == decompressed[i])
        print(f"Byte matches: {matches}/{len(original)} ({matches/len(original)*100:.1f}%)")
        
        # Show first mismatch
        for i in range(min(100, len(original))):
            if original[i] != decompressed[i]:
                print(f"First mismatch at byte {i}: expected 0x{original[i]:02x}, got 0x{decompressed[i]:02x}")
                break
    else:
        print(f"Size mismatch!")
    
    # Show samples
    print(f"\nFirst 40 bytes:")
    print(f"  Original:     {original[:40].hex()}")
    print(f"  Decompressed: {decompressed[:40].hex()}")

def main():
    # Test Method 3 (the working one) on all test files
    test_decompression('tci/silence.tci', 'tci/silence.wav',
                      'Silence test',
                      decompress_tci_data_v3)
    
    test_decompression('tci/impulse.tci', 'tci/impulse.wav',
                      'Impulse test',
                      decompress_tci_data_v3)
    
    test_decompression('tci/sine_440hz.tci', 'tci/sine_440hz.wav',
                      'Sine 440Hz test',
                      decompress_tci_data_v3)
    
    # Test on real drum sample
    print("\n" + "="*80)
    print("REAL DRUM SAMPLE TEST")
    print("="*80)
    
    real_tci = 'Vintage 70\'s Acrolite (Tight) - Close Mic.tci'
    if __import__('os').path.exists(real_tci):
        with open(real_tci, 'rb') as f:
            tci_data = f.read()
        
        # Parse header to get audio size
        compressed = tci_data[128:]
        
        # The TCI header tells us sample count at bytes 8-11
        with open(real_tci, 'rb') as f:
            f.seek(8)
            sample_count = struct.unpack('<I', f.read(4))[0]
        
        expected_size = sample_count * 2 * 2  # stereo * 16-bit
        
        print(f"Sample count: {sample_count}")
        print(f"Expected size: {expected_size} bytes")
        print(f"Compressed size: {len(compressed)} bytes")
        
        # Decompress
        decompressed = decompress_tci_data_v3(compressed, expected_size)
        
        print(f"Decompressed: {len(decompressed)} bytes")
        print(f"First 40 bytes: {decompressed[:40].hex()}")
        
        # Save as WAV
        output_file = 'decompressed_acrolite.wav'
        with open(output_file, 'wb') as f:
            # Write WAV header
            f.write(b'RIFF')
            f.write(struct.pack('<I', 36 + len(decompressed)))
            f.write(b'WAVE')
            
            # fmt chunk
            f.write(b'fmt ')
            f.write(struct.pack('<I', 16))  # chunk size
            f.write(struct.pack('<H', 1))   # PCM
            f.write(struct.pack('<H', 2))   # stereo
            f.write(struct.pack('<I', 48000))  # sample rate
            f.write(struct.pack('<I', 48000 * 2 * 2))  # byte rate
            f.write(struct.pack('<H', 4))   # block align
            f.write(struct.pack('<H', 16))  # bits per sample
            
            # data chunk
            f.write(b'data')
            f.write(struct.pack('<I', len(decompressed)))
            f.write(decompressed)
        
        print(f"\nSaved to: {output_file}")
        print("Run: ffplay decompressed_acrolite.wav")
    else:
        print(f"File not found: {real_tci}")

if __name__ == '__main__':
    main()
