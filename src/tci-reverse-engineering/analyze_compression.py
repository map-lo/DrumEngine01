#!/usr/bin/env python3
"""
TCI Compression Reverse Engineering Toolkit
Advanced analysis tools to help identify the compression algorithm
"""

import struct
import sys
from pathlib import Path
from collections import Counter
import math

class TCICompressionAnalyzer:
    def __init__(self, tci_path, wav_path=None):
        self.tci_path = Path(tci_path)
        self.tci_data = self.tci_path.read_bytes()
        self.wav_path = Path(wav_path) if wav_path else None
        self.wav_data = self.wav_path.read_bytes() if wav_path else None
        
    def read_uint32(self, data, offset):
        return struct.unpack_from('<I', data, offset)[0]
    
    def parse_wav_header(self):
        """Parse WAV file header if available"""
        if not self.wav_data:
            return None
        
        # Parse WAV
        riff = self.wav_data[0:4]
        size = self.read_uint32(self.wav_data, 4)
        wave = self.wav_data[8:12]
        
        # Find fmt chunk
        pos = 12
        while pos < len(self.wav_data) - 8:
            chunk_id = self.wav_data[pos:pos+4]
            chunk_size = self.read_uint32(self.wav_data, pos+4)
            
            if chunk_id == b'fmt ':
                fmt_data = self.wav_data[pos+8:pos+8+chunk_size]
                audio_format = struct.unpack_from('<H', fmt_data, 0)[0]
                num_channels = struct.unpack_from('<H', fmt_data, 2)[0]
                sample_rate = struct.unpack_from('<I', fmt_data, 4)[0]
                byte_rate = struct.unpack_from('<I', fmt_data, 8)[0]
                block_align = struct.unpack_from('<H', fmt_data, 12)[0]
                bits_per_sample = struct.unpack_from('<H', fmt_data, 14)[0]
                
                return {
                    'format': audio_format,
                    'channels': num_channels,
                    'sample_rate': sample_rate,
                    'byte_rate': byte_rate,
                    'block_align': block_align,
                    'bits_per_sample': bits_per_sample
                }
            
            pos += 8 + chunk_size
        
        return None
    
    def find_wav_data_chunk(self):
        """Find the 'data' chunk in WAV file"""
        if not self.wav_data:
            return None
        
        pos = 12
        while pos < len(self.wav_data) - 8:
            chunk_id = self.wav_data[pos:pos+4]
            chunk_size = self.read_uint32(self.wav_data, pos+4)
            
            if chunk_id == b'data':
                return {
                    'offset': pos + 8,
                    'size': chunk_size,
                    'data': self.wav_data[pos+8:pos+8+chunk_size]
                }
            
            pos += 8 + chunk_size
        
        return None
    
    def calculate_entropy(self, data):
        """Calculate Shannon entropy of data"""
        if not data:
            return 0
        
        counts = Counter(data)
        entropy = 0
        length = len(data)
        
        for count in counts.values():
            probability = count / length
            entropy -= probability * math.log2(probability)
        
        return entropy
    
    def analyze_byte_patterns(self, data, window_size=1024):
        """Analyze byte patterns in data"""
        patterns = {
            'repeating_bytes': 0,
            'null_bytes': 0,
            'high_entropy_sections': 0,
            'byte_distribution': Counter()
        }
        
        # Count patterns
        for i in range(min(len(data), 10000)):
            byte = data[i]
            patterns['byte_distribution'][byte] += 1
            
            if byte == 0:
                patterns['null_bytes'] += 1
            
            if i > 0 and data[i] == data[i-1]:
                patterns['repeating_bytes'] += 1
        
        # Analyze entropy in windows
        for i in range(0, min(len(data), 100000), window_size):
            window = data[i:i+window_size]
            entropy = self.calculate_entropy(window)
            if entropy > 7.5:  # High entropy
                patterns['high_entropy_sections'] += 1
        
        return patterns
    
    def look_for_codec_signatures(self):
        """Look for known audio codec signatures"""
        signatures = {
            'FLAC': [b'fLaC'],
            'Ogg Vorbis': [b'OggS', b'vorbis'],
            'Opus': [b'OpusHead', b'OpusTags'],
            'MP3': [b'\xff\xfb', b'\xff\xf3', b'\xff\xf2', b'ID3'],
            'AAC': [b'\xff\xf1', b'\xff\xf9'],
            'WMA': [b'\x30\x26\xb2\x75'],
            'Speex': [b'Speex'],
            'GSM': [b'\xd0'],
            'ADPCM markers': [b'\x02\x00\x00\x00', b'\x11\x00\x00\x00'],
        }
        
        found = []
        data_section = self.tci_data[0x80:]
        
        for codec_name, sigs in signatures.items():
            for sig in sigs:
                if sig in data_section:
                    pos = data_section.find(sig)
                    found.append({
                        'codec': codec_name,
                        'signature': sig.hex(),
                        'offset': 0x80 + pos
                    })
        
        return found
    
    def analyze_compression_ratio(self):
        """Analyze compression ratio if WAV is available"""
        if not self.wav_data:
            return None
        
        tci_compressed_size = len(self.tci_data) - 0x80  # Minus header
        wav_data_chunk = self.find_wav_data_chunk()
        
        if not wav_data_chunk:
            return None
        
        wav_data_size = wav_data_chunk['size']
        ratio = wav_data_size / tci_compressed_size
        
        return {
            'compressed_size': tci_compressed_size,
            'uncompressed_size': wav_data_size,
            'ratio': ratio,
            'compression_percent': (1 - tci_compressed_size/wav_data_size) * 100
        }
    
    def search_for_frame_boundaries(self):
        """
        Try to identify frame boundaries in compressed data
        Many codecs split audio into frames
        """
        data = self.tci_data[0x80:]
        
        # Look for repeating patterns at regular intervals
        potential_frame_sizes = [64, 128, 256, 512, 1024, 2048, 4096]
        
        candidates = []
        
        for frame_size in potential_frame_sizes:
            # Check if there are similar byte patterns at these intervals
            matches = 0
            for i in range(0, min(len(data) - frame_size*2, 50000), frame_size):
                # Check first few bytes of each potential frame
                if i + frame_size < len(data):
                    pattern1 = data[i:i+4]
                    pattern2 = data[i+frame_size:i+frame_size+4]
                    
                    # Count similar leading bytes (frame headers?)
                    similarity = sum(1 for a, b in zip(pattern1, pattern2) if a == b)
                    if similarity >= 2:
                        matches += 1
            
            if matches > 5:
                candidates.append({
                    'frame_size': frame_size,
                    'matches': matches,
                    'confidence': matches / (50000 // frame_size)
                })
        
        return sorted(candidates, key=lambda x: x['confidence'], reverse=True)
    
    def compare_with_wav(self):
        """Compare TCI data with WAV data to find patterns"""
        if not self.wav_data:
            print("No WAV file provided for comparison")
            return None
        
        print("=" * 80)
        print("Comparing TCI with WAV")
        print("=" * 80)
        
        wav_info = self.parse_wav_header()
        if wav_info:
            print(f"WAV Info:")
            print(f"  Sample Rate: {wav_info['sample_rate']} Hz")
            print(f"  Channels: {wav_info['channels']}")
            print(f"  Bits per Sample: {wav_info['bits_per_sample']}")
            print(f"  Format: {wav_info['format']} (1=PCM)")
        
        wav_data_chunk = self.find_wav_data_chunk()
        if wav_data_chunk:
            print(f"\nWAV Data:")
            print(f"  Offset: 0x{wav_data_chunk['offset']:X}")
            print(f"  Size: {wav_data_chunk['size']:,} bytes")
            print(f"  Duration: {wav_data_chunk['size'] / wav_info['byte_rate']:.2f} seconds")
        
        print(f"\nTCI Data:")
        tci_data_size = len(self.tci_data) - 0x80
        print(f"  Size: {tci_data_size:,} bytes")
        
        ratio_info = self.analyze_compression_ratio()
        if ratio_info:
            print(f"\nCompression Analysis:")
            print(f"  Uncompressed: {ratio_info['uncompressed_size']:,} bytes")
            print(f"  Compressed: {ratio_info['compressed_size']:,} bytes")
            print(f"  Ratio: {ratio_info['ratio']:.2f}:1")
            print(f"  Compression: {ratio_info['compression_percent']:.1f}%")
            
            # Estimate compression type based on ratio
            if ratio_info['ratio'] < 2:
                print(f"  → Likely lossless or high-quality lossy compression")
            elif ratio_info['ratio'] < 5:
                print(f"  → Likely moderate lossy compression")
            else:
                print(f"  → Likely aggressive lossy compression")
        
        # Entropy comparison
        tci_entropy = self.calculate_entropy(self.tci_data[0x80:10000])
        wav_entropy = self.calculate_entropy(wav_data_chunk['data'][:10000])
        
        print(f"\nEntropy Analysis (first 10KB):")
        print(f"  TCI entropy: {tci_entropy:.3f} bits/byte")
        print(f"  WAV entropy: {wav_entropy:.3f} bits/byte")
        print(f"  → TCI is {'more' if tci_entropy > wav_entropy else 'less'} random than WAV")
        
        return ratio_info
    
    def full_analysis(self):
        """Perform full analysis"""
        print("=" * 80)
        print("TCI Compression Analysis")
        print("=" * 80)
        print(f"File: {self.tci_path.name}")
        print(f"Size: {len(self.tci_data):,} bytes")
        print()
        
        # Header analysis
        print("TCI Header:")
        signature = self.tci_data[0:32].decode('utf-8', errors='ignore').rstrip('\x00')
        print(f"  Signature: {signature}")
        sample_rate = self.read_uint32(self.tci_data, 0x68)
        total_samples = self.read_uint32(self.tci_data, 0x74)
        velocity_layers = self.read_uint32(self.tci_data, 0x78)
        print(f"  Sample Rate: {sample_rate} Hz")
        print(f"  Total Samples: {total_samples}")
        print(f"  Velocity Layers: {velocity_layers}")
        print()
        
        # Look for codec signatures
        print("Searching for codec signatures...")
        signatures = self.look_for_codec_signatures()
        if signatures:
            print(f"✓ Found {len(signatures)} potential codec signature(s):")
            for sig in signatures:
                print(f"  - {sig['codec']}: {sig['signature']} at offset 0x{sig['offset']:X}")
        else:
            print("✗ No known codec signatures found")
        print()
        
        # Entropy analysis
        data_section = self.tci_data[0x80:]
        entropy = self.calculate_entropy(data_section[:10000])
        print(f"Entropy Analysis (first 10KB):")
        print(f"  Shannon Entropy: {entropy:.3f} bits/byte")
        print(f"  Max Entropy: 8.000 bits/byte")
        print(f"  → {(entropy/8)*100:.1f}% of maximum randomness")
        if entropy > 7.8:
            print(f"  → Very high entropy - likely encrypted or compressed")
        elif entropy > 7.0:
            print(f"  → High entropy - likely compressed")
        else:
            print(f"  → Lower entropy - may be uncompressed or lightly compressed")
        print()
        
        # Byte pattern analysis
        print("Byte Pattern Analysis...")
        patterns = self.analyze_byte_patterns(data_section)
        print(f"  Unique bytes: {len(patterns['byte_distribution'])}/256")
        print(f"  Null bytes: {patterns['null_bytes']}")
        print(f"  Repeating bytes: {patterns['repeating_bytes']}")
        print(f"  High entropy sections: {patterns['high_entropy_sections']}")
        print()
        
        # Frame boundary search
        print("Searching for frame boundaries...")
        frames = self.search_for_frame_boundaries()
        if frames:
            print(f"Potential frame structures found:")
            for frame in frames[:3]:  # Top 3
                print(f"  - Frame size: {frame['frame_size']} bytes, "
                      f"matches: {frame['matches']}, "
                      f"confidence: {frame['confidence']:.2%}")
        else:
            print("  No clear frame boundaries detected")
        print()
        
        # WAV comparison if available
        if self.wav_data:
            self.compare_with_wav()
        
        # First 128 bytes of compressed data
        print("\nFirst 128 bytes of compressed data:")
        for i in range(0, min(128, len(data_section)), 16):
            hex_str = ' '.join(f'{b:02x}' for b in data_section[i:i+16])
            ascii_str = ''.join(chr(b) if 32 <= b < 127 else '.' for b in data_section[i:i+16])
            print(f"  {0x80+i:04x}: {hex_str:<48} {ascii_str}")

def main():
    import argparse
    
    parser = argparse.ArgumentParser(
        description='Advanced TCI compression analysis',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Analyze TCI file alone
  python3 analyze_compression.py file.tci
  
  # Compare TCI with corresponding WAV file
  python3 analyze_compression.py file.tci --wav "Hard 1.wav"
  
  # Analyze multiple samples
  python3 analyze_compression.py file.tci --wav-dir /path/to/wavs
        """
    )
    
    parser.add_argument('tci_file', help='TCI file to analyze')
    parser.add_argument('--wav', help='Corresponding WAV file for comparison')
    parser.add_argument('--wav-dir', help='Directory containing WAV files (will try to find match)')
    
    args = parser.parse_args()
    
    if not Path(args.tci_file).exists():
        print(f"Error: File not found: {args.tci_file}")
        sys.exit(1)
    
    # Find WAV file if directory provided
    wav_file = args.wav
    if args.wav_dir and not wav_file:
        wav_dir = Path(args.wav_dir)
        if wav_dir.exists():
            wav_files = list(wav_dir.glob("*.wav"))
            if wav_files:
                wav_file = str(wav_files[0])  # Use first one
                print(f"Using WAV file: {wav_file}\n")
    
    analyzer = TCICompressionAnalyzer(args.tci_file, wav_file)
    analyzer.full_analysis()
    
    print("\n" + "=" * 80)
    print("Next Steps for Reverse Engineering:")
    print("=" * 80)
    print("""
1. DYNAMIC ANALYSIS (Recommended):
   - Use a debugger (lldb on macOS) to attach to Slate Trigger 2
   - Set breakpoints on file I/O functions (open, read, fread)
   - Load a TCI file in the app
   - Track where decompressed audio ends up in memory
   - Find the decompression function
   
2. STATIC ANALYSIS:
   - Disassemble Slate Trigger 2 binary with Ghidra or IDA Pro
   - Look for string references to ".tci" or "TRIGGER COMPRESSED"
   - Find the file loading code
   - Analyze the decompression routine
   
3. MEMORY DUMPING:
   - Load samples in Slate Trigger 2
   - Dump process memory while samples are loaded
   - Search for PCM audio data in memory dumps
   - Work backwards to find transformation
   
4. COMPARISON ANALYSIS:
   - If you have both TCI and WAV files, use this tool:
     python3 analyze_compression.py file.tci --wav file.wav
   - Look for patterns in the compression ratio
   - Analyze multiple samples to find commonalities
   
5. COMMUNITY RESEARCH:
   - Search for existing TCI decoders
   - Check audio developer forums
   - Look for patents by Slate Digital
    """)

if __name__ == "__main__":
    main()
