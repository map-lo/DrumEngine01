#!/usr/bin/env python3
"""
Try to identify the compression by brute-force checking known audio codecs
"""

import sys
import subprocess
from pathlib import Path
import tempfile

def try_extract_with_ffmpeg(tci_path):
    """Try to let ffmpeg auto-detect the format"""
    print("=" * 80)
    print("ATTEMPTING FFMPEG AUTO-DETECTION")
    print("=" * 80)
    
    # Skip the header and try ffmpeg
    data = Path(tci_path).read_bytes()
    
    # Try different starting offsets
    test_offsets = [0x80, 0, 0x100, 0x200]
    
    for offset in test_offsets:
        print(f"\nTrying offset 0x{offset:X}...")
        
        with tempfile.NamedTemporaryFile(delete=False, suffix='.bin') as tmp:
            tmp.write(data[offset:])
            tmp_path = tmp.name
        
        try:
            # Try ffmpeg probe
            result = subprocess.run(
                ['ffprobe', '-v', 'error', '-show_format', '-show_streams', tmp_path],
                capture_output=True,
                text=True,
                timeout=5
            )
            
            if result.returncode == 0 and result.stdout:
                print(f"✓ FFprobe found something at offset 0x{offset:X}!")
                print(result.stdout)
                
                # Try to convert
                output = f'/tmp/test_extract_{offset:X}.wav'
                conv_result = subprocess.run(
                    ['ffmpeg', '-y', '-i', tmp_path, '-acodec', 'pcm_s24le', output],
                    capture_output=True,
                    text=True,
                    timeout=10
                )
                
                if conv_result.returncode == 0:
                    print(f"✓✓✓ Successfully extracted to {output}!")
                    return True
            else:
                print(f"  No valid format detected")
        
        except (subprocess.TimeoutExpired, Exception) as e:
            print(f"  Error: {e}")
        finally:
            Path(tmp_path).unlink(missing_ok=True)
    
    return False

def check_with_file_command(tci_path):
    """Use the 'file' command to identify format"""
    print("\n" + "=" * 80)
    print("USING 'file' COMMAND FOR IDENTIFICATION")
    print("=" * 80)
    
    data = Path(tci_path).read_bytes()
    
    with tempfile.NamedTemporaryFile(delete=False, suffix='.bin') as tmp:
        tmp.write(data[0x80:])  # Skip header
        tmp_path = tmp.name
    
    try:
        result = subprocess.run(
            ['file', '-b', tmp_path],
            capture_output=True,
            text=True
        )
        
        print(f"File type: {result.stdout.strip()}")
        
        if 'data' not in result.stdout.lower():
            print("✓ Might have identified the format!")
            return result.stdout
    
    except Exception as e:
        print(f"Error: {e}")
    finally:
        Path(tmp_path).unlink(missing_ok=True)
    
    return None

def main():
    import argparse
    
    parser = argparse.ArgumentParser(description='Try to extract audio using standard tools')
    parser.add_argument('tci_file', help='TCI file to process')
    
    args = parser.parse_args()
    
    if not Path(args.tci_file).exists():
        print(f"Error: File not found: {args.tci_file}")
        sys.exit(1)
    
    # Try file command
    check_with_file_command(args.tci_file)
    
    # Try ffmpeg
    success = try_extract_with_ffmpeg(args.tci_file)
    
    if not success:
        print("\n" + "=" * 80)
        print("CONCLUSION")
        print("=" * 80)
        print("Standard tools cannot identify/extract the format.")
        print("\nThis means the compression is either:")
        print("1. A proprietary codec")
        print("2. Standard codec with non-standard framing")
        print("3. Encrypted or obfuscated")
        print("\nNext step: Use the debugger to watch Slate Trigger 2 decompress it")
        print("  ./debug_slate_trigger.sh")

if __name__ == "__main__":
    main()
