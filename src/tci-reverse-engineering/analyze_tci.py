#!/usr/bin/env python3
"""
TCI (Trigger Compressed Instrument) File Format Reverse Engineering Tool
Extracts WAV files and metadata from Slate Trigger 2 .tci files
"""

import struct
import os
import sys
from pathlib import Path

def read_uint32(f):
    """Read a 32-bit unsigned integer (little-endian)"""
    return struct.unpack('<I', f.read(4))[0]

def read_int32(f):
    """Read a 32-bit signed integer (little-endian)"""
    return struct.unpack('<i', f.read(4))[0]

def read_string(f, length):
    """Read a fixed-length string"""
    return f.read(length).decode('utf-8', errors='ignore').rstrip('\x00')

def analyze_tci_file(filepath):
    """Analyze the TCI file structure"""
    print(f"Analyzing: {filepath}")
    print("=" * 80)
    
    with open(filepath, 'rb') as f:
        # Read header
        header = f.read(32)
        header_str = header.decode('utf-8', errors='ignore').rstrip('\x00')
        print(f"Header: {header_str}")
        print(f"Header bytes: {header.hex()}")
        
        # Skip padding
        f.seek(64)
        
        # Read configuration values
        print(f"\nPosition 0x40 (64):")
        val1 = read_uint32(f)  # 0x40
        val2 = read_uint32(f)  # 0x44
        val3 = read_uint32(f)  # 0x48
        val4 = read_uint32(f)  # 0x4C (21 = 0x15)
        val5 = read_uint32(f)  # 0x50
        print(f"  Value at 0x40: {val1}")
        print(f"  Value at 0x44: {val2}")
        print(f"  Value at 0x48: {val3}")
        print(f"  Value at 0x4C: {val4} (possibly string length or count)")
        print(f"  Value at 0x50: {val5}")
        
        f.seek(96)
        print(f"\nPosition 0x60 (96):")
        val6 = read_uint32(f)  # 0x60 (20 = 0x14)
        val7 = read_uint32(f)  # 0x64
        size_val = read_uint32(f)  # 0x68 (48000 = 0xBB80 = sample rate?)
        print(f"  Value at 0x60: {val6}")
        print(f"  Value at 0x64: {val7}")
        print(f"  Value at 0x68: {size_val} (0x{size_val:X}) - possibly sample rate: {size_val}Hz")
        
        f.seek(112)
        print(f"\nPosition 0x70 (112):")
        num_waves = read_uint32(f)  # 0x70 (30 = 0x1E)
        velocity_layers = read_uint32(f)  # 0x74 (5)
        data_size = read_uint32(f)  # 0x78 (large number - compressed data size?)
        print(f"  Value at 0x70: {num_waves} (number of waves: 30)")
        print(f"  Value at 0x74: {velocity_layers} (velocity layers: 5)")
        print(f"  Value at 0x78: {data_size} (0x{data_size:X}) - possibly compressed data size")
        
        # Look for WAV signatures
        print(f"\nSearching for WAV file signatures...")
        f.seek(0)
        content = f.read()
        
        # Search for RIFF headers
        pos = 0
        wav_files = []
        while True:
            pos = content.find(b'RIFF', pos)
            if pos == -1:
                break
            
            # Check if it's followed by file size and WAVE signature
            if pos + 12 <= len(content):
                riff_size = struct.unpack('<I', content[pos+4:pos+8])[0]
                wave_sig = content[pos+8:pos+12]
                if wave_sig == b'WAVE':
                    wav_files.append({
                        'offset': pos,
                        'size': riff_size + 8,  # RIFF chunk size + 8 bytes for 'RIFF' and size
                    })
                    print(f"  Found WAV at offset 0x{pos:X} ({pos}), size: {riff_size + 8} bytes")
            pos += 4
        
        print(f"\nTotal WAV files found: {len(wav_files)}")
        
        # Analyze structure before first WAV
        if wav_files:
            first_wav_offset = wav_files[0]['offset']
            print(f"\nData before first WAV (0 to 0x{first_wav_offset:X}):")
            print(f"  Header size: {first_wav_offset} bytes")
            
            # Try to extract metadata from header
            f.seek(0)
            header_data = f.read(first_wav_offset)
            
            # Look for patterns
            print(f"\n  Looking for metadata patterns...")
            # The format likely has: articulation name, velocity info, RR info, power values
            
        return {
            'num_waves': num_waves,
            'velocity_layers': velocity_layers,
            'wav_files': wav_files,
        }

def extract_wav_files(filepath, output_dir):
    """Extract all WAV files from the TCI file"""
    output_path = Path(output_dir)
    output_path.mkdir(exist_ok=True, parents=True)
    
    with open(filepath, 'rb') as f:
        content = f.read()
    
    # Find all WAV files
    pos = 0
    wav_index = 0
    
    while True:
        pos = content.find(b'RIFF', pos)
        if pos == -1:
            break
        
        # Check if it's a valid WAVE file
        if pos + 12 <= len(content):
            riff_size = struct.unpack('<I', content[pos+4:pos+8])[0]
            wave_sig = content[pos+8:pos+12]
            
            if wave_sig == b'WAVE':
                # Extract the WAV file
                wav_data = content[pos:pos + riff_size + 8]
                output_file = output_path / f"extracted_{wav_index:02d}.wav"
                
                with open(output_file, 'wb') as out:
                    out.write(wav_data)
                
                print(f"Extracted: {output_file} ({len(wav_data)} bytes)")
                wav_index += 1
        
        pos += 4
    
    print(f"\nTotal files extracted: {wav_index}")
    return wav_index

if __name__ == "__main__":
    tci_file = "Vintage 70's Acrolite (Tight) - Close Mic.tci"
    
    if not os.path.exists(tci_file):
        print(f"Error: File not found: {tci_file}")
        sys.exit(1)
    
    # Analyze the file
    info = analyze_tci_file(tci_file)
    
    # Extract WAV files
    print("\n" + "=" * 80)
    print("Extracting WAV files...")
    print("=" * 80)
    extract_wav_files(tci_file, "extracted_wavs")
