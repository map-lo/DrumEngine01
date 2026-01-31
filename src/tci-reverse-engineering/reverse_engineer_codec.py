#!/usr/bin/env python3
"""
Reverse engineer TCI compression by analyzing test files with known inputs.
"""

import struct
import sys

def analyze_compression_pattern(tci_path, wav_path):
    """Compare TCI compressed data against original WAV to find compression pattern."""
    
    # Read TCI
    with open(tci_path, 'rb') as f:
        tci_data = f.read()
    
    # Skip 128-byte header
    compressed = tci_data[128:]
    
    # Read WAV
    with open(wav_path, 'rb') as f:
        wav_data = f.read()
    
    # Parse WAV header (skip to data chunk)
    # Standard WAV: RIFF header (12 bytes) + fmt chunk + data chunk
    wav_pos = 12
    while wav_pos < len(wav_data):
        chunk_id = wav_data[wav_pos:wav_pos+4]
        chunk_size = struct.unpack('<I', wav_data[wav_pos+4:wav_pos+8])[0]
        
        if chunk_id == b'data':
            audio_data = wav_data[wav_pos+8:wav_pos+8+chunk_size]
            break
        
        wav_pos += 8 + chunk_size
    else:
        print(f"ERROR: No data chunk found in {wav_path}")
        return
    
    print(f"\n{'='*80}")
    print(f"Analyzing: {tci_path}")
    print(f"{'='*80}")
    print(f"WAV audio data: {len(audio_data)} bytes")
    print(f"TCI compressed: {len(compressed)} bytes")
    print(f"Compression ratio: {len(compressed)/len(audio_data)*100:.1f}%")
    
    # Analyze compressed data structure
    print(f"\nCompressed data first 100 bytes:")
    for i in range(0, min(100, len(compressed)), 16):
        hex_str = ' '.join(f'{b:02x}' for b in compressed[i:i+16])
        print(f"  {i:04x}: {hex_str}")
    
    # Look for patterns
    print(f"\nSearching for patterns...")
    
    # Check if it starts with a size field
    potential_size = struct.unpack('<I', compressed[0:4])[0]
    print(f"  First 4 bytes as uint32: {potential_size} (0x{potential_size:08x})")
    
    potential_size2 = struct.unpack('<I', compressed[4:8])[0]
    print(f"  Bytes 4-8 as uint32: {potential_size2} (0x{potential_size2:08x})")
    
    # Check for repeating patterns (useful for silence/constant data)
    if len(set(compressed[:20])) < 5:
        print(f"  ⚠ Low entropy in first 20 bytes - may be header/metadata")
    
    # Try to find audio data start
    # Silence test: look for the bit-shifting pattern we observed
    if 'silence' in tci_path:
        print(f"\n  SILENCE pattern analysis:")
        print(f"  Looking for bit-plane encoding (0x80, 0x40, 0x20, 0x10 pattern)...")
        
        for i in range(len(compressed) - 4):
            if (compressed[i] & 0x80) and (compressed[i+4] & 0x40):
                print(f"    Found potential bit-plane at offset {i}: {compressed[i:i+20].hex()}")
                break
    
    # Sine wave test: high entropy, should be harder to compress
    if 'sine' in tci_path:
        print(f"\n  SINE WAVE pattern analysis:")
        print(f"  High entropy data - codec may store nearly raw or use different encoding")
        
        # Check if there's a transformation applied
        # Calculate some basic stats
        byte_counts = {}
        for b in compressed[12:]:  # Skip potential header
            byte_counts[b] = byte_counts.get(b, 0) + 1
        
        print(f"    Unique bytes: {len(byte_counts)}/256")
        print(f"    Most common bytes: {sorted(byte_counts.items(), key=lambda x: x[1], reverse=True)[:5]}")

def main():
    test_files = [
        ('tci/silence.tci', 'tci/silence.wav'),
        ('tci/impulse.tci', 'tci/impulse.wav'),
        ('tci/sine_440hz.tci', 'tci/sine_440hz.wav'),
    ]
    
    for tci, wav in test_files:
        try:
            analyze_compression_pattern(tci, wav)
        except Exception as e:
            print(f"ERROR analyzing {tci}: {e}")
    
    print(f"\n{'='*80}")
    print("HYPOTHESIS:")
    print("="*80)
    print("""
Based on test file analysis:

1. HEADER STRUCTURE (128 bytes):
   - Bytes 0-2: "TRI" signature
   - Bytes 3+: Sample rate, counts, velocity layers, metadata

2. COMPRESSED AUDIO DATA:
   - Likely starts with size/metadata fields (first ~12 bytes)
   - For SILENCE: Uses bit-plane or RLE encoding
     * Highly efficient for sparse data (94% compression)
     * Pattern: bit-shifting sequences visible
   
   - For PREDICTABLE PATTERNS (sine waves): 
     * EXPANDS the data (38% larger than original)
     * Suggests codec is optimized for complex/noisy audio
     * May store frequency domain or use prediction that fails on pure tones
   
   - For COMPLEX AUDIO (drums):
     * Should compress ~2:1 ratio
     * Optimized for transients and noise

3. NEXT STEPS:
   - Examine first 12-20 bytes of compressed data for size/control fields
   - Identify where actual audio encoding starts
   - Test decompression by implementing bit-plane or RLE decoder for silence
   - Use that to bootstrap understanding of full codec
""")

if __name__ == '__main__':
    main()
