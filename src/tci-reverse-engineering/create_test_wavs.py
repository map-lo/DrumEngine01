#!/usr/bin/env python3
"""
Generate test WAV files for TCI reverse engineering
"""
import wave
import struct
import math

def create_sine_wave(filename, frequency=440, duration=1, sample_rate=48000, channels=2):
    """Create a pure sine wave WAV file"""
    num_samples = int(sample_rate * duration)
    
    with wave.open(filename, 'w') as wav:
        wav.setnchannels(channels)
        wav.setsampwidth(2)  # 16-bit
        wav.setframerate(sample_rate)
        
        for i in range(num_samples):
            # Generate sine wave
            value = int(32767 * 0.8 * math.sin(2 * math.pi * frequency * i / sample_rate))
            
            # Write to all channels
            for _ in range(channels):
                wav.writeframes(struct.pack('<h', value))
    
    print(f"✓ Created: {filename}")
    print(f"  {duration}s, {frequency}Hz sine, {sample_rate}Hz, {channels}ch")

def create_silence(filename, duration=1, sample_rate=48000, channels=2):
    """Create a silent WAV file"""
    num_samples = int(sample_rate * duration)
    
    with wave.open(filename, 'w') as wav:
        wav.setnchannels(channels)
        wav.setsampwidth(2)
        wav.setframerate(sample_rate)
        
        silence = struct.pack('<h', 0)
        for i in range(num_samples * channels):
            wav.writeframes(silence)
    
    print(f"✓ Created: {filename}")
    print(f"  {duration}s silence, {sample_rate}Hz, {channels}ch")

def create_impulse(filename, duration=1, sample_rate=48000, channels=2):
    """Create an impulse (single spike then silence)"""
    num_samples = int(sample_rate * duration)
    
    with wave.open(filename, 'w') as wav:
        wav.setnchannels(channels)
        wav.setsampwidth(2)
        wav.setframerate(sample_rate)
        
        for i in range(num_samples):
            # First sample is max, rest are zero
            value = 32767 if i == 0 else 0
            
            for _ in range(channels):
                wav.writeframes(struct.pack('<h', value))
    
    print(f"✓ Created: {filename}")
    print(f"  {duration}s impulse, {sample_rate}Hz, {channels}ch")

def create_dc_offset(filename, value=16383, duration=1, sample_rate=48000, channels=2):
    """Create constant DC offset"""
    num_samples = int(sample_rate * duration)
    
    with wave.open(filename, 'w') as wav:
        wav.setnchannels(channels)
        wav.setsampwidth(2)
        wav.setframerate(sample_rate)
        
        data = struct.pack('<h', value)
        for i in range(num_samples * channels):
            wav.writeframes(data)
    
    print(f"✓ Created: {filename}")
    print(f"  {duration}s DC offset ({value}), {sample_rate}Hz, {channels}ch")

if __name__ == "__main__":
    import os
    
    # Create test directory
    test_dir = "/tmp/tci_test_wavs"
    os.makedirs(test_dir, exist_ok=True)
    
    print("=" * 60)
    print("Creating Test WAV Files")
    print("=" * 60)
    print()
    
    # Create test files
    create_sine_wave(f"{test_dir}/sine_440hz.wav", frequency=440)
    create_sine_wave(f"{test_dir}/sine_1000hz.wav", frequency=1000)
    create_silence(f"{test_dir}/silence.wav")
    create_impulse(f"{test_dir}/impulse.wav")
    create_dc_offset(f"{test_dir}/dc_offset.wav")
    
    print()
    print("=" * 60)
    print("✓ Test files created in:", test_dir)
    print("=" * 60)
    print()
    print("Next steps:")
    print("1. Open Trigger Instrument Editor")
    print("2. Import these WAV files (one at a time)")
    print("3. Save as test1.tci, test2.tci, etc.")
    print("4. We'll analyze the compression by comparing input WAV to output TCI")
    print()
    print("Start with: sine_440hz.wav (most predictable)")
