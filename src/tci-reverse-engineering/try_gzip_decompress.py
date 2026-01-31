#!/usr/bin/env python3
"""
Try GZIP decompression on TCI data based on strings found in binary.
The binary contains: GZIPCompressorOutputStream and GZIPDecompressorInputStream
"""

import gzip
import zlib
import struct

def try_gzip_decompress(tci_file, wav_file, sample_name):
    """Try GZIP decompression on TCI compressed data."""
    
    print(f"\n{'='*80}")
    print(f"{sample_name.upper()} - GZIP DECOMPRESSION TEST")
    print('='*80)
    
    with open(tci_file, 'rb') as f:
        tci_data = f.read()
    
    # Skip TCI header (128 bytes)
    compressed = tci_data[128:]
    
    print(f"Compressed data: {len(compressed):,} bytes")
    print(f"First 20 bytes: {compressed[:20].hex()}")
    
    # Try different starting points
    for skip in [0, 12, 16, 20, 32]:
        print(f"\n  Trying skip={skip} bytes...")
        data = compressed[skip:]
        
        # Try raw gzip
        try:
            decompressed = gzip.decompress(data)
            print(f"    ✓ GZIP succeeded! Decompressed: {len(decompressed):,} bytes")
            
            # Save it
            output = tci_file.replace('.tci', '_gzip_decompressed.raw')
            with open(output, 'wb') as f:
                f.write(decompressed)
            print(f"    Saved to: {output}")
            return True
        except Exception as e:
            print(f"    ✗ GZIP failed: {str(e)[:60]}")
        
        # Try raw zlib (DEFLATE)
        try:
            decompressed = zlib.decompress(data)
            print(f"    ✓ ZLIB succeeded! Decompressed: {len(decompressed):,} bytes")
            
            output = tci_file.replace('.tci', '_zlib_decompressed.raw')
            with open(output, 'wb') as f:
                f.write(decompressed)
            print(f"    Saved to: {output}")
            return True
        except Exception as e:
            print(f"    ✗ ZLIB failed: {str(e)[:60]}")
        
        # Try zlib with different wbits
        for wbits in [-15, 15, -8, 8, 16+15]:
            try:
                decompressed = zlib.decompress(data, wbits)
                print(f"    ✓ ZLIB wbits={wbits} succeeded! Decompressed: {len(decompressed):,} bytes")
                
                output = tci_file.replace('.tci', f'_zlib_wb{wbits}_decompressed.raw')
                with open(output, 'wb') as f:
                    f.write(decompressed)
                print(f"    Saved to: {output}")
                return True
            except:
                pass
    
    return False

def main():
    test_files = [
        ('tci/silence.tci', 'tci/silence.wav', 'silence'),
        ('tci/impulse.tci', 'tci/impulse.wav', 'impulse'),
        ('tci/sine_440hz.tci', 'tci/sine_440hz.wav', 'sine_440hz'),
    ]
    
    for tci_file, wav_file, name in test_files:
        try_gzip_decompress(tci_file, wav_file, name)

if __name__ == '__main__':
    main()
