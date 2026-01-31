#!/usr/bin/env python3
"""
Improved TCI decoder based on control byte analysis.

Hypothesis: The marker bytes (0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80) 
are NOT data to skip - they are CONTROL BYTES that indicate:
- How to interpret following bytes
- Possibly bit flags for different encoding modes
- Run-length or delta encoding parameters
"""

import struct
import sys
import wave

def decode_tci_v2(input_file, output_file):
    """
    Version 2 decoder: Treat marker bytes as control codes.
    """
    
    with open(input_file, 'rb') as f:
        data = f.read()
    
    # Parse header
    header = data[:32]
    if not header.startswith(b'TRIGGER COMPRESSED INSTRUMENT'):
        print(f"Error: Not a valid TCI file")
        return False
    
    print(f"Input: {input_file}")
    print(f"File size: {len(data)} bytes")
    
    # Find metadata
    meta_size = struct.unpack('<I', data[32:36])[0]
    print(f"Metadata size: {meta_size}")
    
    # Find audio config (at offset 0x60)
    offset = 0x60
    config = struct.unpack('<IIIIIIII', data[offset:offset+32])
    print(f"Config at 0x60: {config}")
    
    # Guess: [?, ?, sample_rate, ?, channels?, ?, ?, samples?]
    sample_rate = config[2]  # 44100 (0xac44)
    num_channels = config[4]  # Usually 1 or 2
    
    print(f"Sample rate: {sample_rate} Hz")
    print(f"Channels (guess): {num_channels}")
    
    # Start of compressed audio data
    compressed_start = 0x80
    compressed = data[compressed_start:]
    
    print(f"Compressed data starts at: 0x{compressed_start:04x}")
    print(f"Compressed size: {len(compressed)} bytes")
    
    # Decode with control byte interpretation
    samples = decode_with_control_bytes(compressed)
    
    print(f"Decoded {len(samples)} samples")
    
    if len(samples) > 0:
        # Save as WAV
        save_wav(output_file, samples, sample_rate, num_channels if num_channels <= 2 else 2)
        print(f"Output: {output_file}")
        return True
    
    return False

def decode_with_control_bytes(compressed):
    """
    Decode treating marker bytes as control codes.
    
    Updated theory based on analysis:
    - 0x01 = Raw 24-bit samples follow
    - 0x02 = Raw 24-bit samples follow  
    - 0x04 = Raw 24-bit samples follow
    - 0x08 = Raw 24-bit samples follow
    - 0x10 = Raw 24-bit samples follow
    - 0x20 = Raw 24-bit samples follow
    - 0x40 = Raw 24-bit samples follow
    - 0x80 = Raw 24-bit samples follow
    
    All control bytes seem to indicate "read following bytes as 24-bit samples"
    The control byte itself might indicate quantization level or bit depth.
    """
    
    marker_bytes = {0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80}
    samples = []
    
    i = 0
    while i < len(compressed):
        byte = compressed[i]
        
        if byte in marker_bytes:
            # Control byte - ALL types indicate 24-bit samples follow
            control = byte
            i += 1
            
            # Read 24-bit samples until next control byte
            while i + 2 < len(compressed) and compressed[i] not in marker_bytes:
                # Read 24-bit little-endian sample
                sample = compressed[i] | (compressed[i+1] << 8) | (compressed[i+2] << 16)
                if sample & 0x800000:  # Sign extend
                    sample -= 0x1000000
                samples.append(sample)
                i += 3
            
            # Handle remaining bytes before next control
            while i < len(compressed) and compressed[i] not in marker_bytes:
                # Skip incomplete samples
                i += 1
        else:
            # Not a control byte - shouldn't happen if format is clean
            # Skip it
            i += 1
    
    return samples

def save_wav(filename, samples, sample_rate, num_channels):
    """Save decoded samples as WAV file."""
    
    # Convert to 16-bit for WAV
    samples_16 = [max(-32768, min(32767, s >> 8)) for s in samples]
    
    with wave.open(filename, 'wb') as wav:
        wav.setnchannels(num_channels)
        wav.setsampwidth(2)  # 16-bit
        wav.setframerate(sample_rate)
        
        # Pack as 16-bit samples
        data = struct.pack('<' + 'h' * len(samples_16), *samples_16)
        wav.writeframes(data)

def main():
    test_files = [
        ('tci/silence.tci', 'output/silence_v2.wav'),
        ('tci/impulse.tci', 'output/impulse_v2.wav'),
        ('tci/sine_440hz.tci', 'output/sine_440hz_v2.wav'),
    ]
    
    for input_file, output_file in test_files:
        print("=" * 70)
        decode_tci_v2(input_file, output_file)
        print()

if __name__ == '__main__':
    main()
