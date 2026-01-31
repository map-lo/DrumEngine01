#!/usr/bin/env python3
"""
TCI Audio Extractor
Attempts to extract compressed audio data from .tci files
"""

import struct
import zlib
import gzip
import bz2
try:
    import lzma
    HAS_LZMA = True
except ImportError:
    HAS_LZMA = False
from pathlib import Path
import sys

class TCIAudioExtractor:
    def __init__(self, tci_path):
        self.tci_path = Path(tci_path)
        self.data = self.tci_path.read_bytes()
        
    def read_uint32(self, offset):
        return struct.unpack_from('<I', self.data, offset)[0]
    
    def read_string(self, offset, length):
        return self.data[offset:offset+length].decode('utf-8', errors='ignore').rstrip('\x00')
    
    def parse_header(self):
        """Parse TCI header"""
        header = {
            'signature': self.read_string(0, 32),
            'sample_rate': self.read_uint32(0x68),
            'total_samples': self.read_uint32(0x74),
            'velocity_layers': self.read_uint32(0x78),
        }
        return header
    
    def try_decompress_zlib(self, data):
        """Try zlib decompression"""
        try:
            return zlib.decompress(data)
        except:
            # Try with different wbits values
            for wbits in [15, -15, 16+15, -16-15]:
                try:
                    return zlib.decompress(data, wbits)
                except:
                    pass
        return None
    
    def try_decompress_gzip(self, data):
        """Try gzip decompression"""
        try:
            return gzip.decompress(data)
        except:
            return None
    
    def try_decompress_bz2(self, data):
        """Try bz2 decompression"""
        try:
            return bz2.decompress(data)
        except:
            return None
    
    def try_decompress_lzma(self, data):
        """Try LZMA decompression"""
        if not HAS_LZMA:
            return None
        try:
            return lzma.decompress(data)
        except:
            return None
    
    def find_wav_signatures(self):
        """Look for any RIFF/WAVE signatures in the data"""
        positions = []
        pos = 0
        while True:
            pos = self.data.find(b'RIFF', pos)
            if pos == -1:
                break
            if pos + 12 <= len(self.data):
                wave_sig = self.data[pos+8:pos+12]
                if wave_sig == b'WAVE':
                    size = struct.unpack_from('<I', self.data, pos+4)[0]
                    positions.append({'offset': pos, 'size': size})
            pos += 1
        return positions
    
    def analyze_compression(self):
        """Analyze the compressed data section"""
        print("=" * 80)
        print("TCI Audio Data Analysis")
        print("=" * 80)
        print(f"File: {self.tci_path.name}")
        print(f"Size: {len(self.data):,} bytes")
        print()
        
        header = self.parse_header()
        print("Header Information:")
        print(f"  Signature: {header['signature']}")
        print(f"  Sample Rate: {header['sample_rate']} Hz")
        print(f"  Total Samples: {header['total_samples']}")
        print(f"  Velocity Layers: {header['velocity_layers']}")
        print()
        
        # Check for WAV signatures
        print("Searching for embedded WAV files...")
        wav_sigs = self.find_wav_signatures()
        if wav_sigs:
            print(f"✓ Found {len(wav_sigs)} RIFF/WAVE signature(s):")
            for idx, sig in enumerate(wav_sigs):
                print(f"  {idx+1}. Offset: 0x{sig['offset']:X}, Size: {sig['size']:,} bytes")
            return wav_sigs
        else:
            print("✗ No RIFF/WAVE signatures found - audio is compressed")
        print()
        
        # Try to decompress the data section
        data_start = 0x80  # After 128-byte header
        compressed_data = self.data[data_start:]
        
        print(f"Compressed data section: {len(compressed_data):,} bytes")
        print(f"Starting at offset: 0x{data_start:X}")
        print()
        
        # Show first bytes
        print("First 64 bytes of compressed data:")
        print(compressed_data[:64].hex())
        print()
        
        # Try different decompression methods
        print("Attempting decompression methods:")
        print("-" * 80)
        
        methods = [
            ("zlib", self.try_decompress_zlib),
            ("gzip", self.try_decompress_gzip),
            ("bz2", self.try_decompress_bz2),
            ("LZMA/XZ", self.try_decompress_lzma),
        ]
        
        for name, method in methods:
            print(f"Trying {name}...", end=" ")
            result = method(compressed_data)
            if result:
                print(f"✓ SUCCESS! Decompressed to {len(result):,} bytes")
                # Check if decompressed data contains WAV
                if b'RIFF' in result and b'WAVE' in result:
                    print(f"  ✓ Contains RIFF/WAVE signature!")
                return result
            else:
                print("✗ Failed")
        
        print()
        print("⚠️  All standard decompression methods failed")
        print()
        
        # Analyze data patterns
        print("Data Pattern Analysis:")
        print("-" * 80)
        
        # Check entropy (random vs structured)
        byte_counts = [0] * 256
        for byte in compressed_data[:10000]:  # Sample first 10KB
            byte_counts[byte] += 1
        
        non_zero = sum(1 for c in byte_counts if c > 0)
        print(f"Unique byte values (first 10KB): {non_zero}/256")
        
        if non_zero > 200:
            print("  → High entropy - likely compressed or encrypted")
        else:
            print("  → Low entropy - may be raw audio or specific compression")
        
        # Look for repeating patterns
        sample_data = compressed_data[:1000]
        print(f"\nSample data (first 32 bytes): {sample_data[:32].hex()}")
        
        return None
    
    def extract_embedded_wavs(self, output_dir):
        """Extract any embedded WAV files"""
        wav_sigs = self.find_wav_signatures()
        
        if not wav_sigs:
            print("No embedded WAV files found")
            return []
        
        output_path = Path(output_dir)
        output_path.mkdir(parents=True, exist_ok=True)
        
        extracted = []
        for idx, sig in enumerate(wav_sigs):
            offset = sig['offset']
            size = sig['size'] + 8  # Include RIFF header
            
            wav_data = self.data[offset:offset + size]
            output_file = output_path / f"extracted_{idx:02d}.wav"
            
            with open(output_file, 'wb') as f:
                f.write(wav_data)
            
            print(f"✓ Extracted: {output_file} ({len(wav_data):,} bytes)")
            extracted.append(output_file)
        
        return extracted
    
    def try_raw_audio_extraction(self, output_dir):
        """
        Try to extract audio as raw PCM (experimental)
        This assumes the data might be uncompressed PCM audio
        """
        print("\nAttempting raw PCM extraction (experimental)...")
        print("-" * 80)
        
        header = self.parse_header()
        data_start = 0x80
        audio_data = self.data[data_start:]
        
        # Try different bit depths and channel configurations
        configs = [
            ("16-bit mono", 2, 1),
            ("16-bit stereo", 2, 2),
            ("24-bit mono", 3, 1),
            ("24-bit stereo", 3, 2),
        ]
        
        output_path = Path(output_dir)
        output_path.mkdir(parents=True, exist_ok=True)
        
        for config_name, bytes_per_sample, channels in configs:
            print(f"Trying {config_name}...", end=" ")
            
            # Create a simple WAV header
            sample_rate = header['sample_rate']
            num_samples = len(audio_data) // (bytes_per_sample * channels)
            
            if num_samples < 100:  # Too small
                print("✗ Too small")
                continue
            
            # Create WAV file
            output_file = output_path / f"raw_{config_name.replace(' ', '_')}.wav"
            
            try:
                with open(output_file, 'wb') as f:
                    # Write WAV header
                    data_size = len(audio_data)
                    
                    # RIFF header
                    f.write(b'RIFF')
                    f.write(struct.pack('<I', 36 + data_size))
                    f.write(b'WAVE')
                    
                    # fmt chunk
                    f.write(b'fmt ')
                    f.write(struct.pack('<I', 16))  # Chunk size
                    f.write(struct.pack('<H', 1))   # PCM format
                    f.write(struct.pack('<H', channels))
                    f.write(struct.pack('<I', sample_rate))
                    f.write(struct.pack('<I', sample_rate * channels * bytes_per_sample))  # Byte rate
                    f.write(struct.pack('<H', channels * bytes_per_sample))  # Block align
                    f.write(struct.pack('<H', bytes_per_sample * 8))  # Bits per sample
                    
                    # data chunk
                    f.write(b'data')
                    f.write(struct.pack('<I', data_size))
                    f.write(audio_data)
                
                print(f"✓ Created {output_file} ({num_samples} samples)")
                
            except Exception as e:
                print(f"✗ Error: {e}")

def main():
    import argparse
    
    parser = argparse.ArgumentParser(description='Extract audio from TCI files')
    parser.add_argument('tci_file', help='Path to .tci file')
    parser.add_argument('--output-dir', '-o', default='extracted_audio',
                       help='Output directory for extracted files')
    parser.add_argument('--analyze-only', action='store_true',
                       help='Only analyze, do not extract')
    parser.add_argument('--try-raw', action='store_true',
                       help='Attempt raw PCM extraction (experimental)')
    
    args = parser.parse_args()
    
    if not Path(args.tci_file).exists():
        print(f"Error: File not found: {args.tci_file}")
        sys.exit(1)
    
    extractor = TCIAudioExtractor(args.tci_file)
    
    # Analyze the file
    result = extractor.analyze_compression()
    
    if not args.analyze_only:
        print("\n" + "=" * 80)
        print("Extraction Attempt")
        print("=" * 80)
        
        # Try to extract embedded WAVs
        extracted = extractor.extract_embedded_wavs(args.output_dir)
        
        if extracted:
            print(f"\n✓ Successfully extracted {len(extracted)} WAV file(s)")
        else:
            print("\n⚠️  No embedded WAV files found")
            
            if args.try_raw:
                extractor.try_raw_audio_extraction(args.output_dir)
                print("\n⚠️  Raw extraction attempted - files may not be playable")
            else:
                print("\nTip: Use --try-raw to attempt raw PCM extraction (experimental)")
    
    print("\n" + "=" * 80)
    print("Conclusion:")
    print("=" * 80)
    
    if result:
        print("✓ Audio data can be extracted using standard methods")
    else:
        print("✗ Audio uses proprietary compression")
        print("\nThe TCI file uses Slate Digital's proprietary compression.")
        print("To use these samples, you need the original WAV files that")
        print("came with Slate Trigger 2.")
        print("\nUse the recursive_tci_converter.py tool with the WAV files:")
        print(f"  python3 recursive_tci_converter.py <tci_dir> --wav-search <wav_dir>")

if __name__ == "__main__":
    main()
