#!/usr/bin/env python3
"""
Alternative Path C: Monitor file system and memory allocations
Since we can't dump memory directly, let's monitor what happens when you play audio
"""

import subprocess
import sys
import time
from pathlib import Path

print("=" * 80)
print("Alternative Memory Monitoring Approach")
print("=" * 80)
print()

print("APPROACH 1: Find mapped files")
print("-" * 80)
print("Looking for any files mapped into memory...")
print()

# Get all files mapped by the process
result = subprocess.run(
    ['sudo', 'lsof', '-p', '19787'],
    capture_output=True,
    text=True
)

files = []
for line in result.stdout.split('\n'):
    if '.tci' in line.lower() or '.wav' in line.lower() or 'trigger' in line.lower():
        files.append(line)

if files:
    print("Found relevant files:")
    for f in files:
        print(f"  {f}")
else:
    print("No obvious audio files mapped")

print()
print("=" * 80)
print("APPROACH 2: Check temp directories")
print("-" * 80)
print()

temp_dirs = [
    '/private/var/folders',
    '/tmp',
    Path.home() / 'Library/Caches',
    '/Library/Caches'
]

print("Checking for recently created audio files...")
for temp_dir in temp_dirs:
    if Path(temp_dir).exists():
        try:
            result = subprocess.run(
                ['find', str(temp_dir), '-name', '*.wav', '-o', '-name', '*.aiff', 
                 '-mmin', '-10', '-type', 'f'],
                capture_output=True,
                text=True,
                timeout=5
            )
            if result.stdout.strip():
                print(f"\nFound in {temp_dir}:")
                print(result.stdout)
        except:
            pass

print()
print("=" * 80)
print("APPROACH 3: Monitor process activity")
print("-" * 80)
print()
print("Instructions:")
print("1. Open a NEW terminal window")
print("2. Run this command:")
print()
print("   sudo fs_usage -w -f filesys 19787 | grep -i 'wav\\|aiff\\|audio\\|sample'")
print()
print("3. While that's running, go play a sound in Trigger Instrument Editor")
print("4. Watch the output - it will show any file operations")
print("5. If it writes audio to disk, you'll see it!")
print()

print("=" * 80)
print("APPROACH 4: The Nuclear Option")  
print("-" * 80)
print()
print("If nothing else works:")
print()
print("1. In Trigger Instrument Editor, look for:")
print("   - Export menu")
print("   - Save As WAV option")
print("   - Bounce/Render function")
print()
print("2. You may be able to export each cell as a WAV directly!")
print()
print("3. Or route audio through a virtual audio device:")
print("   - Install Loopback or BlackHole")
print("   - Record the output when playing each cell")
print()

print("=" * 80)
print("What do you want to try?")
print("=" * 80)
print()
print("A) Check lsof output above for mapped files")
print("B) Run fs_usage monitor and play sounds")
print("C) Look for export function in Trigger Editor")
print("D) Just disable SIP and use the debugger (fastest)")
print()
