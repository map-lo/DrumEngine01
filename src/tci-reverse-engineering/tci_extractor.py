#!/usr/bin/env python3
"""
TCI File Structure Analyzer and Extractor
Based on reverse engineering of Slate Trigger 2 .tci format
"""

import struct
import json
from pathlib import Path
import sys

class TCIFile:
    def __init__(self, filepath):
        self.filepath = Path(filepath)
        self.data = self.filepath.read_bytes()
        self.header = {}
        self.samples = []
        
    def read_uint32(self, offset):
        return struct.unpack_from('<I', self.data, offset)[0]
    
    def read_int32(self, offset):
        return struct.unpack_from('<i', self.data, offset)[0]
    
    def read_float(self, offset):
        return struct.unpack_from('<f', self.data, offset)[0]
    
    def read_string(self, offset, length):
        return self.data[offset:offset+length].decode('utf-8', errors='ignore').rstrip('\x00')
    
    def parse_header(self):
        """Parse the TCI file header"""
        # Header signature
        self.header['signature'] = self.read_string(0, 32)
        
        # Main configuration (based on hex dump analysis)
        self.header['unknown_1'] = self.read_uint32(0x40)  # Always 1?
        self.header['unknown_2'] = self.read_uint32(0x44)  # 4
        self.header['unknown_3'] = self.read_uint32(0x48)  # 4
        self.header['name_length'] = self.read_uint32(0x4C)  # 21
        self.header['unknown_4'] = self.read_uint32(0x50)  # 4
        
        self.header['unknown_5'] = self.read_uint32(0x60)  # 20
        self.header['unknown_6'] = self.read_uint32(0x64)  # 4
        self.header['sample_rate'] = self.read_uint32(0x68)  # 48000
        
        # Critical values at 0x70
        self.header['unknown_count_1'] = self.read_uint32(0x70)  # 4
        self.header['total_samples'] = self.read_uint32(0x74)  # 30
        self.header['velocity_layers'] = self.read_uint32(0x78)  # 5
        
        # Calculate round robins
        if self.header['total_samples'] > 0 and self.header['velocity_layers'] > 0:
            self.header['round_robins'] = self.header['total_samples'] // self.header['velocity_layers']
        else:
            self.header['round_robins'] = 0
        
        return self.header
    
    def analyze_structure(self):
        """Analyze the overall file structure"""
        print("TCI File Analysis")
        print("=" * 80)
        print(f"File: {self.filepath.name}")
        print(f"Size: {len(self.data):,} bytes ({len(self.data) / 1024 / 1024:.2f} MB)")
        print()
        
        header = self.parse_header()
        print("Header Information:")
        print(f"  Signature: {header['signature']}")
        print(f"  Sample Rate: {header['sample_rate']} Hz")
        print(f"  Total Samples: {header['total_samples']}")
        print(f"  Velocity Layers: {header['velocity_layers']}")
        print(f"  Round Robins: {header['round_robins']}")
        print()
        
        # Map the structure based on screenshot
        velocity_layer_names = ['Hard', 'Hard_Med', 'Med', 'Med_Soft', 'Soft']
        
        print("Expected Sample Mapping:")
        print("-" * 80)
        sample_index = 0
        for vel_idx, vel_name in enumerate(velocity_layer_names):
            print(f"\nVelocity Layer {vel_idx + 1}: {vel_name}")
            for rr in range(1, self.header['round_robins'] + 1):
                sample_index += 1
                print(f"  Sample {sample_index:2d}: {vel_name} {rr}.wav")
        
        # Look for data sections
        print("\n" + "=" * 80)
        print("Data Section Analysis:")
        print("-" * 80)
        
        # Audio data likely starts after header
        # Based on the screenshot showing PWR (power) values, there's metadata per sample
        header_size = 0x80  # 128 bytes seems reasonable
        
        print(f"Estimated header size: {header_size} bytes (0x{header_size:X})")
        print(f"Data section size: {len(self.data) - header_size:,} bytes")
        
        # The data appears to be interleaved stereo samples (16-bit or 24-bit)
        data_section_size = len(self.data) - header_size
        bytes_per_sample = 2  # 16-bit
        total_audio_samples = data_section_size // bytes_per_sample
        
        print(f"\nAssuming 16-bit audio:")
        print(f"  Total audio samples: {total_audio_samples:,}")
        print(f"  Samples per file: {total_audio_samples // self.header['total_samples']:,}")
        print(f"  Duration per file: {(total_audio_samples // self.header['total_samples']) / self.header['sample_rate']:.2f} seconds")
        
        return header
    
    def create_mapping_json(self, output_path, wav_folder):
        """Create a JSON mapping file for the plugin"""
        header = self.parse_header()
        
        velocity_layer_names = ['Hard', 'Hard_Med', 'Med', 'Med_Soft', 'Soft']
        
        # Calculate velocity ranges (0-127 MIDI velocity)
        velocity_ranges = []
        vel_per_layer = 128 // header['velocity_layers']
        for i in range(header['velocity_layers']):
            min_vel = i * vel_per_layer
            max_vel = (i + 1) * vel_per_layer - 1 if i < header['velocity_layers'] - 1 else 127
            velocity_ranges.append((min_vel, max_vel))
        
        # Build the mapping
        mapping = {
            "name": "Vintage 70's Acrolite (Tight) - Close Mic",
            "source": "Slate Trigger 2",
            "sampleRate": header['sample_rate'],
            "articulations": [
                {
                    "name": "Articulation 1",
                    "midiNote": 60,  # Middle C
                    "velocityLayers": []
                }
            ]
        }
        
        # Add velocity layers
        for vel_idx, vel_name in enumerate(velocity_layer_names):
            vel_layer = {
                "name": vel_name,
                "velocityRange": {
                    "min": velocity_ranges[vel_idx][0],
                    "max": velocity_ranges[vel_idx][1]
                },
                "roundRobins": []
            }
            
            # Add round robins
            for rr in range(1, header['round_robins'] + 1):
                filename = f"{vel_name} {rr}.wav"
                vel_layer["roundRobins"].append({
                    "index": rr - 1,
                    "file": str(Path(wav_folder) / filename)
                })
            
            mapping["articulations"][0]["velocityLayers"].append(vel_layer)
        
        # Write JSON
        output_file = Path(output_path)
        output_file.parent.mkdir(parents=True, exist_ok=True)
        
        with open(output_file, 'w') as f:
            json.dump(mapping, f, indent=2)
        
        print(f"\nMapping JSON created: {output_file}")
        return mapping

def main():
    import argparse
    
    parser = argparse.ArgumentParser(description='Analyze and extract TCI file structure')
    parser.add_argument('tci_file', help='Path to .tci file')
    parser.add_argument('--json', help='Output JSON mapping file', default='mapping.json')
    parser.add_argument('--wav-folder', help='Path to WAV files folder', 
                       default='/Users/marian/Downloads/SPINLIGHT SAMPLES/WAV Files/VIntage 70\'s Acrolite (Tight)/Close Mic')
    
    args = parser.parse_args()
    
    if not Path(args.tci_file).exists():
        print(f"Error: File not found: {args.tci_file}")
        sys.exit(1)
    
    tci = TCIFile(args.tci_file)
    tci.analyze_structure()
    
    print("\n" + "=" * 80)
    print("Creating JSON Mapping...")
    print("=" * 80)
    mapping = tci.create_mapping_json(args.json, args.wav_folder)
    
    print("\n✓ Analysis complete!")
    print(f"\nYou can now use the JSON file with your plugin:")
    print(f"  {Path(args.json).absolute()}")

if __name__ == "__main__":
    main()
