#!/usr/bin/env python3
"""
Verify TCI JSON mapping against actual WAV files
Checks if all files referenced in the JSON exist
"""

import json
import sys
from pathlib import Path

def verify_mapping(json_path):
    """Verify that all WAV files in the JSON mapping exist"""
    
    with open(json_path) as f:
        data = json.load(f)
    
    print(f"Verifying mapping: {json_path}")
    print("=" * 80)
    print(f"Instrument: {data['name']}")
    print(f"Sample Rate: {data['sampleRate']} Hz")
    print()
    
    all_files = []
    missing_files = []
    
    for art_idx, articulation in enumerate(data['articulations']):
        print(f"Articulation {art_idx + 1}: {articulation['name']} (MIDI Note: {articulation['midiNote']})")
        print("-" * 80)
        
        for vel_layer in articulation['velocityLayers']:
            vel_range = vel_layer['velocityRange']
            print(f"\n  Velocity Layer: {vel_layer['name']} (vel {vel_range['min']}-{vel_range['max']})")
            
            for rr in vel_layer['roundRobins']:
                filepath = Path(rr['file'])
                all_files.append(filepath)
                
                exists = filepath.exists()
                status = "✓" if exists else "✗"
                
                print(f"    {status} RR{rr['index'] + 1}: {filepath.name}")
                
                if not exists:
                    missing_files.append(filepath)
    
    # Summary
    print("\n" + "=" * 80)
    print("Summary:")
    print(f"  Total files referenced: {len(all_files)}")
    print(f"  Files found: {len(all_files) - len(missing_files)}")
    print(f"  Files missing: {len(missing_files)}")
    
    if missing_files:
        print("\nMissing files:")
        for f in missing_files:
            print(f"  - {f}")
        return False
    else:
        print("\n✓ All files verified successfully!")
        return True

def main():
    if len(sys.argv) < 2:
        print("Usage: python3 verify_mapping.py <mapping.json>")
        sys.exit(1)
    
    json_path = sys.argv[1]
    
    if not Path(json_path).exists():
        print(f"Error: File not found: {json_path}")
        sys.exit(1)
    
    success = verify_mapping(json_path)
    sys.exit(0 if success else 1)

if __name__ == "__main__":
    main()
