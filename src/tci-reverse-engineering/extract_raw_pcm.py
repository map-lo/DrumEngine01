#!/usr/bin/env python3
"""
Find and extract raw PCM audio from Pro Tools memory
"""
import subprocess
import struct
import sys
from pathlib import Path

def get_pro_tools_pid():
    result = subprocess.run(['pgrep', 'Pro Tools'], capture_output=True, text=True)
    if result.stdout.strip():
        return result.stdout.strip()
    return None

def get_large_heap_regions(pid):
    """Get large heap allocations that might contain audio"""
    result = subprocess.run(
        ['sudo', 'vmmap', pid],
        capture_output=True,
        text=True
    )
    
    regions = []
    for line in result.stdout.split('\n'):
        if 'MALLOC' in line and ('M' in line or 'K' in line):
            parts = line.split()
            if len(parts) >= 2:
                addr_range = parts[1]
                if '-' in addr_range:
                    start, end = addr_range.split('-')
                    # Calculate size
                    try:
                        size = int(end, 16) - int(start, 16)
                        # Look for regions larger than 500KB (likely to contain audio)
                        if size > 500000:
                            regions.append((start, end, size))
                    except:
                        pass
    
    return sorted(regions, key=lambda x: x[2], reverse=True)[:10]  # Top 10 largest

def dump_memory_region(pid, start, end, output_file, max_size=10*1024*1024):
    """Dump a memory region to file (limit to max_size bytes)"""
    start_addr = int(start, 16)
    end_addr = int(end, 16)
    size = end_addr - start_addr
    
    # Limit to max_size
    if size > max_size:
        end_addr = start_addr + max_size
        end = format(end_addr, 'x')
    
    script = f"""
process attach -p {pid}
memory read --outfile {output_file} --binary 0x{start} 0x{end}
detach
quit
"""
    
    with open('/tmp/dump.lldb', 'w') as f:
        f.write(script)
    
    result = subprocess.run(
        ['sudo', 'lldb', '-s', '/tmp/dump.lldb'],
        capture_output=True,
        timeout=60
    )
    
    return Path(output_file).exists()

def analyze_for_audio(data, sample_rate=48000):
    """Check if data contains PCM audio patterns"""
    if len(data) < 10000:
        return False
    
    # Check for 16-bit PCM patterns
    # Audio should have varying values, not all zeros or constant
    sample_16 = struct.unpack(f'<{len(data)//2}h', data[:len(data)//2*2])
    
    # Calculate basic stats
    non_zero = sum(1 for s in sample_16[:1000] if s != 0)
    variance = len(set(sample_16[:1000]))
    
    # Audio should have:
    # - At least 50% non-zero samples
    # - High variance (many different values)
    if non_zero > 500 and variance > 100:
        return True
    
    return False

def find_sample_boundaries(data):
    """Try to find where samples start in the raw data"""
    # Look for patterns that might indicate sample starts
    # - Sudden amplitude changes
    # - Periods of silence followed by sound
    boundaries = []
    
    # Convert to 16-bit samples
    if len(data) < 4:
        return []
    
    samples = struct.unpack(f'<{len(data)//2}h', data[:len(data)//2*2])
    
    # Expected sample size: 48000 Hz * 2.31s * 2 channels * 2 bytes = ~443,520 bytes
    expected_size = 48000 * 2.31 * 2 * 2
    
    # Search for boundaries every ~440KB
    step = int(expected_size / 2)  # Convert to samples
    
    for i in range(0, len(samples) - step, step):
        boundaries.append(i * 2)  # Convert back to bytes
    
    return boundaries

def main():
    print("=" * 80)
    print("Raw PCM Audio Extraction from Memory")
    print("=" * 80)
    print()
    
    pid = get_pro_tools_pid()
    if not pid:
        print("❌ Pro Tools not running")
        sys.exit(1)
    
    print(f"✓ Found Pro Tools (PID: {pid})")
    print()
    
    print("Finding large memory regions...")
    regions = get_large_heap_regions(pid)
    
    if not regions:
        print("❌ No suitable memory regions found")
        sys.exit(1)
    
    print(f"Found {len(regions)} large regions:")
    for i, (start, end, size) in enumerate(regions[:5], 1):
        print(f"  {i}. 0x{start}-0x{end} ({size/1024/1024:.1f} MB)")
    
    print()
    print("Dumping and analyzing memory regions...")
    
    for i, (start, end, size) in enumerate(regions, 1):
        print(f"\nRegion {i}: {size/1024/1024:.1f} MB")
        dump_file = f'/tmp/memory_region_{i}.bin'
        
        print(f"  Dumping to {dump_file}...")
        if not dump_memory_region(pid, start, end, dump_file):
            print("  ✗ Failed to dump")
            continue
        
        # Analyze the data
        with open(dump_file, 'rb') as f:
            data = f.read()
        
        print(f"  Dumped {len(data)} bytes")
        
        if analyze_for_audio(data):
            print("  ✓ Contains likely audio data!")
            
            # Try to extract individual samples
            boundaries = find_sample_boundaries(data)
            print(f"  Found {len(boundaries)} potential sample boundaries")
            
            # Extract first few samples as WAV files
            for j, boundary in enumerate(boundaries[:5], 1):
                # Assume stereo 16-bit 48kHz
                # ~2.31 seconds = 221,760 samples = 443,520 bytes per sample
                sample_size = 443520
                
                if boundary + sample_size <= len(data):
                    wav_file = f'/tmp/extracted_sample_{i}_{j}.wav'
                    
                    # Create WAV file
                    import wave
                    with wave.open(wav_file, 'wb') as wav:
                        wav.setnchannels(2)  # Stereo
                        wav.setsampwidth(2)  # 16-bit
                        wav.setframerate(48000)
                        wav.writeframes(data[boundary:boundary+sample_size])
                    
                    print(f"    → {wav_file}")
    
    print()
    print("=" * 80)
    print("Done! Check /tmp/extracted_sample_*.wav")
    print("Play with: afplay /tmp/extracted_sample_1_1.wav")
    print("=" * 80)

if __name__ == "__main__":
    main()
