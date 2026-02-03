#!/usr/bin/env python3
"""
Remove freq and freqConfidence fields from all preset.json files.
Used to test the preset metadata installer.
"""

import json
import os
from pathlib import Path

def remove_freq_fields(preset_path):
    """Remove freq and freqConfidence from a preset.json file."""
    try:
        with open(preset_path, 'r') as f:
            data = json.load(f)
        
        # Check if fields exist
        had_freq = 'freq' in data
        had_confidence = 'freqConfidence' in data
        
        # Remove fields
        if 'freq' in data:
            del data['freq']
        if 'freqConfidence' in data:
            del data['freqConfidence']
        
        # Only write if we removed something
        if had_freq or had_confidence:
            with open(preset_path, 'w') as f:
                json.dump(data, f, indent=2)
            return True
        
        return False
    except Exception as e:
        print(f"Error processing {preset_path}: {e}")
        return False

def main():
    # Get the script directory
    script_dir = Path(__file__).parent
    presets_dir = script_dir / "presets"
    
    if not presets_dir.exists():
        print(f"Error: {presets_dir} does not exist")
        return
    
    print("Removing freq and freqConfidence fields from preset.json files...")
    print(f"Scanning: {presets_dir}")
    print()
    
    # Find all preset.json files
    preset_files = list(presets_dir.rglob("preset.json"))
    print(f"Found {len(preset_files)} preset.json files")
    print()
    
    # Process each file
    modified_count = 0
    for preset_path in preset_files:
        if remove_freq_fields(preset_path):
            modified_count += 1
            rel_path = preset_path.relative_to(presets_dir)
            print(f"✓ {rel_path}")
    
    print()
    print(f"Modified {modified_count} preset files")
    print(f"Skipped {len(preset_files) - modified_count} files (no freq data)")

if __name__ == "__main__":
    main()
