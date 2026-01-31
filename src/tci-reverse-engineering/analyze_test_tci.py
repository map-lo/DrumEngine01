#!/usr/bin/env python3
"""
Analyze test TCI files with known inputs
"""
import struct
import sys
from pathlib import Path

def analyze_tci(tci_file, wav_file):
    """Compare TCI with original WAV"""
    print("=" * 80)
    print(f"Analyzing: {Path(tci_file).name}")
    print("=" * 80)
    
    # Read files
    with open(tci_file, 'rb') as f:
        tci_data = f.read()
    
    with open(wav_file, 'rb') as f:
        wav_data = f.read()
    
    # Parse TCI header
    signature = tci_data[:32].rstrip(b'\x00').decode('ascii', errors='ignore')
    
    # Read header values at known offsets
    sample_rate = struct.unpack('<I', tci_data[0x68:0x6C])[0]
    total_samples = struct.unpack('<I', tci_data[0x74:0x78])[0]
    velocity_layers = struct.unpack('<I', tci_data[0x78:0x7C])[0]
    
    print(f"Signature: {signature}")
    print(f"Sample Rate: {sample_rate} Hz")
    print(f"Total Samples: {total_samples}")
    print(f"Velocity Layers: {velocity_layers}")
    print()
    
    # File sizes
    tci_size = len(tci_data)
    wav_size = len(wav_data)
    wav_audio_size = wav_size - 44  # Subtract WAV header
    
    print(f"WAV size: {wav_size:,} bytes ({wav_size/1024:.1f} KB)")
    print(f"WAV audio data: {wav_audio_size:,} bytes")
    print(f"TCI size: {tci_size:,} bytes ({tci_size/1024:.1f} KB)")
    print(f"TCI header: 128 bytes")
    print(f"TCI data: {tci_size - 128:,} bytes ({(tci_size-128)/1024:.1f} KB)")
    print()
    
    ratio = (tci_size - 128) / wav_audio_size
    if ratio < 1:
        print(f"Compression ratio: {ratio:.3f} ({(1-ratio)*100:.1f}% reduction)")
    else:
        print(f"Compression ratio: {ratio:.3f} ({(ratio-1)*100:.1f}% EXPANSION)")
    print()
    
    # Analyze data section
    data = tci_data[128:]
    
    # Calculate entropy
    from collections import Counter
    import math
    byte_counts = Counter(data)
    total = len(data)
    entropy = -sum((count/total) * math.log2(count/total) for count in byte_counts.values() if count > 0)
    
    print(f"Data section entropy: {entropy:.3f} bits/byte (max 8.0)")
    print(f"Unique byte values: {len(byte_counts)} / 256")
    print()
    
    # Look for patterns
    print("First 128 bytes of data section:")
    for i in range(0, min(128, len(data)), 16):
        hex_str = ' '.join(f'{b:02x}' for b in data[i:i+16])
        ascii_str = ''.join(chr(b) if 32 <= b < 127 else '.' for b in data[i:i+16])
        print(f"  {i+128:04x}: {hex_str:<48} {ascii_str}")
    print()

if __name__ == "__main__":
    tci_dir = Path("/Users/marian/Development/JUCE-Plugins/DrumEngine01/src/tci-reverse-engineering/tci")
    wav_dir = Path("/tmp/tci_test_wavs")
    
    tests = [
        ("silence.tci", "silence.wav"),
        ("impulse.tci", "impulse.wav"),
        ("sine_440hz.tci", "sine_440hz.wav"),
        ("sine_1000hz.tci", "sine_1000hz.wav"),
        ("dc_offset.tci", "dc_offset.wav"),
    ]
    
    for tci_name, wav_name in tests:
        tci_path = tci_dir / tci_name
        wav_path = tci_dir / wav_name  # User put them alongside
        
        if not wav_path.exists():
            wav_path = wav_dir / wav_name
        
        if tci_path.exists() and wav_path.exists():
            analyze_tci(str(tci_path), str(wav_path))
        else:
            print(f"⚠️  Missing: {tci_name} or {wav_name}")
        
        print()
