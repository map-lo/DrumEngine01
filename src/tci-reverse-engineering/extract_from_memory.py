#!/usr/bin/env python3
"""
Memory-based TCI Audio Extraction
This script helps you extract decompressed audio from Slate Trigger 2's memory
"""

import subprocess
import sys
from pathlib import Path
import time

def check_prerequisites():
    """Check if we have what we need"""
    print("Checking prerequisites...")
    
    # Check for Slate Trigger 2
    slate_paths = [
        "/Applications/Slate Digital/Trigger 2.app/Contents/MacOS/Trigger 2",
        Path.home() / "Library/Audio/Plug-Ins/VST3/Slate Digital Trigger 2.vst3/Contents/MacOS/Slate Digital Trigger 2",
        Path.home() / "Library/Audio/Plug-Ins/Components/Slate Digital Trigger 2.component/Contents/MacOS/Slate Digital Trigger 2"
    ]
    
    slate_found = None
    for path in slate_paths:
        if Path(path).exists():
            slate_found = path
            break
    
    if not slate_found:
        print("❌ Slate Trigger 2 not found!")
        print("\nYou need Slate Trigger 2 installed to proceed.")
        print("If you don't have it, you CANNOT decompress TCI files.")
        print("\nAlternative: Use the original WAV files instead!")
        return False
    
    print(f"✓ Found Slate Trigger 2: {slate_found}")
    
    # Check for lldb
    try:
        subprocess.run(['lldb', '--version'], capture_output=True, check=True)
        print("✓ LLDB debugger available")
    except:
        print("❌ LLDB not found!")
        print("Install: xcode-select --install")
        return False
    
    return True

def is_slate_running():
    """Check if Slate Trigger 2 is running"""
    try:
        result = subprocess.run(
            ['pgrep', '-i', 'trigger'],
            capture_output=True,
            text=True
        )
        return result.returncode == 0
    except:
        return False

def get_slate_pid():
    """Get Slate Trigger 2 process ID"""
    try:
        result = subprocess.run(
            ['pgrep', '-i', 'trigger'],
            capture_output=True,
            text=True
        )
        if result.stdout.strip():
            return int(result.stdout.strip().split()[0])
    except:
        pass
    return None

def dump_memory_regions(pid):
    """Dump memory regions that might contain audio"""
    print(f"\nDumping memory regions for PID {pid}...")
    
    try:
        # Use vmmap to see memory layout
        result = subprocess.run(
            ['vmmap', str(pid)],
            capture_output=True,
            text=True,
            timeout=10
        )
        
        # Save to file
        vmmap_file = '/tmp/slate_memory_map.txt'
        Path(vmmap_file).write_text(result.stdout)
        print(f"✓ Memory map saved to: {vmmap_file}")
        
        # Look for large heap regions (likely to contain audio data)
        lines = result.stdout.split('\n')
        large_regions = []
        
        for line in lines:
            if 'MALLOC' in line or 'HEAP' in line or '__DATA' in line:
                parts = line.split()
                if len(parts) >= 3:
                    try:
                        size_str = parts[1]
                        if 'M' in size_str:
                            size_mb = float(size_str.replace('M', ''))
                            if size_mb > 10:  # Regions larger than 10MB
                                large_regions.append(line)
                    except:
                        pass
        
        if large_regions:
            print("\nLarge memory regions (likely contain audio):")
            for region in large_regions[:10]:
                print(f"  {region}")
        
        return True
    except Exception as e:
        print(f"Error: {e}")
        return False

def search_for_wav_in_memory(pid):
    """Search process memory for RIFF/WAVE signatures"""
    print(f"\nSearching for WAV data in memory (PID {pid})...")
    
    # Create LLDB commands
    commands = """
process attach -p {pid}
memory find -s "RIFF" 0x0 0xFFFFFFFFFFFFFFFF
memory find -s "WAVE" 0x0 0xFFFFFFFFFFFFFFFF
quit
""".format(pid=pid)
    
    cmd_file = '/tmp/lldb_search.txt'
    Path(cmd_file).write_text(commands)
    
    try:
        result = subprocess.run(
            ['sudo', 'lldb', '-s', cmd_file],
            capture_output=True,
            text=True,
            timeout=30
        )
        
        output = result.stdout + result.stderr
        
        # Parse for addresses
        riff_addresses = []
        for line in output.split('\n'):
            if 'data found at location' in line.lower() or '0x' in line:
                riff_addresses.append(line)
        
        if riff_addresses:
            print("✓ Found potential WAV data:")
            for addr in riff_addresses[:10]:
                print(f"  {addr}")
            return riff_addresses
        else:
            print("❌ No RIFF/WAVE signatures found in memory")
            print("  This means audio hasn't been decompressed yet,")
            print("  or it's in a different format in memory")
    
    except Exception as e:
        print(f"Error: {e}")
    
    return []

def main():
    print("=" * 80)
    print("TCI Audio Extraction via Memory Dump")
    print("=" * 80)
    print()
    
    # Check prerequisites
    if not check_prerequisites():
        print("\n❌ Cannot proceed. Prerequisites missing.")
        sys.exit(1)
    
    print("\n" + "=" * 80)
    print("STEP 1: Start Slate Trigger 2")
    print("=" * 80)
    
    if not is_slate_running():
        print("\n⚠️  Slate Trigger 2 is NOT running!")
        print("\nPlease:")
        print("  1. Open Slate Trigger 2 (standalone or in DAW)")
        print("  2. Load a TCI file / instrument")
        print("  3. Run this script again")
        print("\nStart now:")
        print('  open "/Applications/Slate Digital/Trigger 2.app"')
        sys.exit(1)
    
    pid = get_slate_pid()
    print(f"✓ Slate Trigger 2 is running (PID: {pid})")
    
    print("\n" + "=" * 80)
    print("STEP 2: Make sure a TCI file is LOADED")
    print("=" * 80)
    print("\nIn Slate Trigger 2:")
    print("  1. Load your TCI instrument")
    print("  2. Make sure samples are loaded (maybe trigger a sound)")
    print("  3. Come back here")
    print("\nPress Enter when ready...")
    input()
    
    print("\n" + "=" * 80)
    print("STEP 3: Dump memory layout")
    print("=" * 80)
    
    dump_memory_regions(pid)
    
    print("\n" + "=" * 80)
    print("STEP 4: Search for decompressed audio in memory")
    print("=" * 80)
    print("\n⚠️  This requires sudo (you may be asked for password)")
    
    addresses = search_for_wav_in_memory(pid)
    
    if addresses:
        print("\n" + "=" * 80)
        print("✓✓✓ SUCCESS! Found audio data in memory")
        print("=" * 80)
        print("\nNext steps:")
        print("1. Use LLDB to dump that memory region:")
        print(f"   sudo lldb -p {pid}")
        print("   memory read --outfile /tmp/sample.wav --binary <address> <address+700000>")
        print("   quit")
        print("\n2. Check the extracted file:")
        print("   file /tmp/sample.wav")
        print("   afplay /tmp/sample.wav")
    else:
        print("\n" + "=" * 80)
        print("⚠️  No decompressed audio found in memory")
        print("=" * 80)
        print("\nThis could mean:")
        print("  1. Audio is still compressed in memory (not loaded yet)")
        print("  2. Audio is in PCM format without WAV headers")
        print("  3. Need to trigger a sound to load it")
        print("\nTry:")
        print("  1. Play a sound in Slate Trigger 2")
        print("  2. Run this script again")
        print("\nOR use the interactive debugger:")
        print("  ./debug_slate_trigger.sh")

if __name__ == "__main__":
    main()
