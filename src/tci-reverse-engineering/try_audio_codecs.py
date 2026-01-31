#!/usr/bin/env python3
"""
Try to decode TCI compressed data using audio codecs.
Based on discovery that header bytes leak into compressed data stream.
"""

import subprocess
import struct
import tempfile
import os

def try_flac_decode(tci_file, output_wav):
    """Try to decode as FLAC audio."""
    with open(tci_file, 'rb') as f:
        tci_data = f.read()
    
    # Skip TCI header (128 bytes) and compression header (12 bytes)
    compressed = tci_data[128+12:]
    
    print(f"Trying FLAC decode on {len(compressed)} bytes...")
    
    # Write to temp file and try flac decoder
    with tempfile.NamedTemporaryFile(suffix='.flac', delete=False) as tmp:
        tmp.write(compressed)
        tmp_name = tmp.name
    
    try:
        # Try flac decoder
        result = subprocess.run(
            ['flac', '-d', tmp_name, '-o', output_wav],
            capture_output=True,
            text=True
        )
        if result.returncode == 0:
            print(f"✓ FLAC decode succeeded!")
            return True
        else:
            print(f"✗ FLAC decode failed: {result.stderr[:200]}")
    except Exception as e:
        print(f"✗ FLAC decode error: {e}")
    finally:
        os.unlink(tmp_name)
    
    return False

def try_with_flac_header(tci_file, output_wav):
    """Try adding a FLAC header and decoding."""
    with open(tci_file, 'rb') as f:
        tci_data = f.read()
    
    compressed = tci_data[128+12:]
    
    print(f"\nTrying with FLAC header prepended...")
    
    # Create minimal FLAC header
    #  "fLaC" + STREAMINFO block
    flac_header = bytearray(b'fLaC')
    
    # STREAMINFO metadata block (type 0, last=1, length=34)
    flac_header.append(0x80)  # Last metadata block, type 0 (STREAMINFO)
    flac_header.extend(struct.pack('>I', 34)[1:])  # Length = 34 bytes (3 bytes)
    
    # STREAMINFO (34 bytes)
    flac_header.extend(struct.pack('>H', 4096))  # min block size
    flac_header.extend(struct.pack('>H', 4096))  # max block size
    flac_header.extend(struct.pack('>I', 0)[1:])  # min frame size (unknown = 0, 3 bytes)
    flac_header.extend(struct.pack('>I', 0)[1:])  # max frame size (unknown = 0, 3 bytes)
    
    # Sample rate (20 bits), channels (3 bits), bits per sample (5 bits)
    # 44100 Hz, 2 channels (1), 16 bits (15)
    sample_rate = 44100
    channels = 1  # 0-based: 0=1ch, 1=2ch
    bits_per_sample = 15  # 0-based: 15=16bits
    
    # Pack into 8 bytes
    val = (sample_rate << 44) | (channels << 41) | (bits_per_sample << 36) | 192000  # total samples
    flac_header.extend(struct.pack('>Q', val))
    
    # MD5 (16 bytes, can be zeros)
    flac_header.extend(bytes(16))
    
    # Combine with compressed data
    flac_data = flac_header + compressed
    
    with tempfile.NamedTemporaryFile(suffix='.flac', delete=False) as tmp:
        tmp.write(flac_data)
        tmp_name = tmp.name
    
    try:
        result = subprocess.run(
            ['flac', '-d', tmp_name, '-o', output_wav, '--force'],
            capture_output=True,
            text=True
        )
        if result.returncode == 0:
            print(f"✓ FLAC with header succeeded!")
            return True
        else:
            print(f"✗ FLAC with header failed: {result.stderr[:200]}")
    except Exception as e:
        print(f"✗ Error: {e}")
    finally:
        os.unlink(tmp_name)
    
    return False

def main():
    test_files = [
        'tci/impulse.tci',
        'tci/sine_440hz.tci',
    ]
    
    for tci_file in test_files:
        print(f"\n{'='*80}")
        print(f"Testing: {tci_file}")
        print('='*80)
        
        output = f"{tci_file.replace('.tci', '_decoded.wav')}"
        
        # Try raw FLAC
        if try_flac_decode(tci_file, output):
            print(f"Saved to: {output}")
            continue
        
        # Try with FLAC header
        if try_with_flac_header(tci_file, output):
            print(f"Saved to: {output}")
            continue
        
        print(f"All methods failed for {tci_file}")

if __name__ == '__main__':
    main()
