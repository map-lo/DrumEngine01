#!/usr/bin/env python3
"""
Deep TCI Structure Analysis
Reverse engineer the exact data layout to find audio samples
"""

import struct
import sys
from pathlib import Path

class DeepTCIAnalyzer:
    def __init__(self, tci_path):
        self.tci_path = Path(tci_path)
        self.data = self.tci_path.read_bytes()
        
    def read_uint32(self, offset):
        return struct.unpack_from('<I', self.data, offset)[0]
    
    def read_int32(self, offset):
        return struct.unpack_from('<i', self.data, offset)[0]
    
    def read_uint16(self, offset):
        return struct.unpack_from('<H', self.data, offset)[0]
    
    def parse_full_header(self):
        """Parse every value in the header"""
        print("=" * 80)
        print("COMPLETE HEADER ANALYSIS")
        print("=" * 80)
        
        # Parse everything from 0x00 to 0x80
        for offset in range(0, 0x80, 4):
            value32 = self.read_uint32(offset)
            value_hex = f"0x{value32:08X}"
            
            # Try to interpret as string
            bytes_at_offset = self.data[offset:offset+4]
            ascii_repr = ''.join(chr(b) if 32 <= b < 127 else '.' for b in bytes_at_offset)
            
            # Mark interesting values
            interesting = ""
            if value32 == 48000:
                interesting = " <- SAMPLE RATE"
            elif value32 == 30:
                interesting = " <- TOTAL SAMPLES?"
            elif value32 in [5, 6]:
                interesting = " <- VELOCITY LAYERS / ROUND ROBINS?"
            elif value32 > 1000000:
                interesting = " <- POSSIBLY SIZE/OFFSET"
            
            print(f"0x{offset:02X}: {value32:10d} {value_hex:12s} [{ascii_repr}]{interesting}")
        
        print()
    
    def search_for_sample_table(self):
        """Look for a table of offsets/sizes for individual samples"""
        print("=" * 80)
        print("SEARCHING FOR SAMPLE TABLE")
        print("=" * 80)
        
        # After header, look for repeating patterns of size values
        # Each sample might have: offset (4 bytes) + size (4 bytes) = 8 bytes per entry
        # For 30 samples, that's 240 bytes of table
        
        start_offset = 0x80
        end_offset = 0x500  # Search first ~1KB after header
        
        print(f"\nLooking for patterns between 0x{start_offset:X} and 0x{end_offset:X}...")
        print()
        
        # Look for sequences of reasonable values
        for table_start in range(start_offset, end_offset, 4):
            # Try reading 30 pairs of values
            potential_table = []
            valid_count = 0
            
            for i in range(30):
                offset_in_table = table_start + (i * 8)
                if offset_in_table + 8 > len(self.data):
                    break
                
                val1 = self.read_uint32(offset_in_table)
                val2 = self.read_uint32(offset_in_table + 4)
                
                # Check if these look like offset/size pairs
                # Offsets should be > 0x80 and < file size
                # Sizes should be reasonable (10KB - 1MB per sample)
                if (val1 > 0x80 and val1 < len(self.data) and 
                    val2 > 10000 and val2 < 1000000):
                    valid_count += 1
                    potential_table.append((val1, val2))
            
            if valid_count >= 20:  # At least 20 valid-looking entries
                print(f"✓ Found potential sample table at 0x{table_start:X}")
                print(f"  Valid entries: {valid_count}/30")
                print(f"\nFirst 10 entries (offset, size):")
                for idx, (offset, size) in enumerate(potential_table[:10]):
                    print(f"  Sample {idx+1:2d}: offset=0x{offset:08X}, size={size:8d} bytes")
                print()
                return table_start, potential_table
        
        print("✗ No clear sample table found")
        print()
        return None, None
    
    def analyze_data_after_header(self):
        """Analyze the structure right after the header"""
        print("=" * 80)
        print("DATA AFTER HEADER (0x80 onwards)")
        print("=" * 80)
        
        # Show hex dump of first 512 bytes after header
        start = 0x80
        for i in range(0, 512, 16):
            offset = start + i
            hex_bytes = ' '.join(f'{b:02x}' for b in self.data[offset:offset+16])
            ascii_repr = ''.join(chr(b) if 32 <= b < 127 else '.' for b in self.data[offset:offset+16])
            
            # Try to interpret as uint32 values
            if i % 16 == 0:
                val1 = self.read_uint32(offset) if offset + 4 <= len(self.data) else 0
                val2 = self.read_uint32(offset + 4) if offset + 8 <= len(self.data) else 0
                val3 = self.read_uint32(offset + 8) if offset + 12 <= len(self.data) else 0
                val4 = self.read_uint32(offset + 12) if offset + 16 <= len(self.data) else 0
                
                print(f"0x{offset:04X}: {hex_bytes:48s} {ascii_repr:16s}")
                print(f"        uint32: {val1:10d} {val2:10d} {val3:10d} {val4:10d}")
            else:
                print(f"0x{offset:04X}: {hex_bytes:48s} {ascii_repr:16s}")
        
        print()
    
    def look_for_chunk_markers(self):
        """Search for chunk markers (4-char identifiers)"""
        print("=" * 80)
        print("SEARCHING FOR CHUNK MARKERS")
        print("=" * 80)
        
        # Common chunk markers in audio files
        markers = [b'DATA', b'SMPL', b'data', b'smpl', b'INFO', b'info', 
                   b'WAVE', b'wave', b'fmt ', b'FMT ', b'JUNK', b'junk']
        
        found_any = False
        for marker in markers:
            pos = 0
            while True:
                pos = self.data.find(marker, pos)
                if pos == -1:
                    break
                
                # Read size after marker (common pattern)
                if pos + 8 <= len(self.data):
                    size = self.read_uint32(pos + 4)
                    print(f"✓ Found '{marker.decode('ascii', errors='ignore')}' at 0x{pos:X}, size={size}")
                    found_any = True
                
                pos += 1
        
        if not found_any:
            print("✗ No standard chunk markers found")
        print()
    
    def calculate_per_sample_size(self):
        """Calculate expected size per sample"""
        total_samples = self.read_uint32(0x74)
        data_section_size = len(self.data) - 0x80
        
        if total_samples > 0:
            avg_size_per_sample = data_section_size / total_samples
            
            print("=" * 80)
            print("SIZE CALCULATIONS")
            print("=" * 80)
            print(f"Total file size: {len(self.data):,} bytes")
            print(f"Header size: 128 bytes (0x80)")
            print(f"Data section: {data_section_size:,} bytes")
            print(f"Total samples: {total_samples}")
            print(f"Average per sample: {avg_size_per_sample:,.0f} bytes (~{avg_size_per_sample/1024:.0f} KB)")
            print()
            
            return avg_size_per_sample
        return 0
    
    def try_split_by_fixed_size(self, sample_size):
        """Try splitting data into fixed-size chunks"""
        print("=" * 80)
        print(f"ATTEMPTING FIXED-SIZE SPLIT ({sample_size:.0f} bytes per sample)")
        print("=" * 80)
        
        start_offset = 0x80
        total_samples = self.read_uint32(0x74)
        
        for i in range(min(5, total_samples)):  # Test first 5 samples
            sample_start = int(start_offset + (i * sample_size))
            sample_data = self.data[sample_start:sample_start + int(sample_size)]
            
            # Check for signatures
            has_riff = b'RIFF' in sample_data[:100]
            has_wave = b'WAVE' in sample_data[:100]
            has_mp3 = sample_data[0:2] in [b'\xff\xfb', b'\xff\xf3', b'\xff\xf2']
            has_aac = sample_data[0:2] in [b'\xff\xf1', b'\xff\xf9']
            
            print(f"Sample {i+1}: offset=0x{sample_start:X}")
            print(f"  First 16 bytes: {sample_data[:16].hex()}")
            print(f"  Signatures: RIFF={has_riff}, WAVE={has_wave}, MP3={has_mp3}, AAC={has_aac}")
        
        print()
    
    def deep_pattern_search(self):
        """Look for repeating patterns that might indicate sample boundaries"""
        print("=" * 80)
        print("PATTERN ANALYSIS")
        print("=" * 80)
        
        # Look for bytes that repeat at regular intervals
        data_section = self.data[0x80:]
        
        # Test different interval sizes
        test_intervals = [
            328000,  # ~328KB (our estimated size)
            327680,  # 320KB
            331776,  # 324KB
            655360,  # 640KB (2x)
        ]
        
        for interval in test_intervals:
            if interval > len(data_section):
                continue
            
            matches = 0
            for i in range(0, min(len(data_section) - interval * 3, 500000), interval):
                # Check if first 4 bytes at each interval are similar
                pattern1 = data_section[i:i+4]
                pattern2 = data_section[i+interval:i+interval+4]
                
                if pattern1 == pattern2 or sum(a == b for a, b in zip(pattern1, pattern2)) >= 3:
                    matches += 1
            
            if matches > 3:
                print(f"Interval {interval:,} bytes: {matches} potential boundaries")
        
        print()
    
    def full_analysis(self):
        """Run all analysis methods"""
        self.parse_full_header()
        self.calculate_per_sample_size()
        self.analyze_data_after_header()
        
        # Try to find sample table
        table_offset, sample_table = self.search_for_sample_table()
        
        if sample_table:
            print("\n✓✓✓ SAMPLE TABLE FOUND! ✓✓✓")
            print("=" * 80)
            print("You can now extract samples using these offsets and sizes!")
            print()
            return sample_table
        
        # Other analyses
        self.look_for_chunk_markers()
        self.deep_pattern_search()
        
        # Try fixed-size split
        avg_size = self.calculate_per_sample_size()
        if avg_size > 0:
            self.try_split_by_fixed_size(avg_size)
        
        return None

def main():
    import argparse
    
    parser = argparse.ArgumentParser(description='Deep TCI structure analysis')
    parser.add_argument('tci_file', help='TCI file to analyze')
    
    args = parser.parse_args()
    
    if not Path(args.tci_file).exists():
        print(f"Error: File not found: {args.tci_file}")
        sys.exit(1)
    
    analyzer = DeepTCIAnalyzer(args.tci_file)
    sample_table = analyzer.full_analysis()
    
    if sample_table:
        print("\n" + "=" * 80)
        print("NEXT STEP: Extract samples using found table")
        print("=" * 80)
        print("\nRun: python3 extract_using_table.py <tci_file> <output_dir>")
    else:
        print("\n" + "=" * 80)
        print("NEXT STEPS")
        print("=" * 80)
        print("1. Try the debugger: ./debug_slate_trigger.sh")
        print("2. Or examine the hex dump above for patterns")
        print("3. Or use Ghidra for static analysis")

if __name__ == "__main__":
    main()
