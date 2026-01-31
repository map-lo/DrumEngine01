#!/usr/bin/env python3
"""
Batch TCI Converter
Converts multiple TCI files to JSON mappings
"""

import sys
import json
from pathlib import Path
from tci_extractor import TCIFile

def find_wav_folder(tci_file_path):
    """
    Try to automatically find the corresponding WAV folder
    based on common Slate Trigger 2 installation patterns
    """
    tci_path = Path(tci_file_path)
    tci_name = tci_path.stem
    
    # Common locations
    possible_bases = [
        Path.home() / "Downloads" / "SPINLIGHT SAMPLES" / "WAV Files",
        Path.home() / "Music" / "Slate Digital" / "Trigger 2" / "Samples",
        Path.home() / "Documents" / "Slate Digital" / "Trigger 2" / "Samples",
        Path("/Library/Application Support/Slate Digital/Trigger 2/Samples"),
    ]
    
    for base in possible_bases:
        if base.exists():
            # Look for matching folder name
            for folder in base.rglob("*"):
                if folder.is_dir() and tci_name.lower() in folder.name.lower():
                    return folder
    
    return None

def batch_convert(tci_files, output_dir=None, wav_base_dir=None):
    """Convert multiple TCI files to JSON mappings"""
    
    if output_dir:
        output_path = Path(output_dir)
        output_path.mkdir(parents=True, exist_ok=True)
    
    results = []
    
    for tci_file in tci_files:
        tci_path = Path(tci_file)
        
        if not tci_path.exists():
            print(f"⚠️  File not found: {tci_file}")
            results.append({'file': tci_file, 'success': False, 'error': 'File not found'})
            continue
        
        print(f"\nProcessing: {tci_path.name}")
        print("-" * 80)
        
        try:
            # Load TCI file
            tci = TCIFile(tci_path)
            header = tci.parse_header()
            
            # Find WAV folder
            wav_folder = None
            if wav_base_dir:
                # User provided base directory
                wav_folder = Path(wav_base_dir) / tci_path.stem
                if not wav_folder.exists():
                    print(f"  ⚠️  WAV folder not found: {wav_folder}")
                    wav_folder = find_wav_folder(tci_path)
            else:
                wav_folder = find_wav_folder(tci_path)
            
            if not wav_folder:
                print(f"  ⚠️  Could not find WAV folder automatically")
                print(f"  Please provide --wav-base-dir argument")
                results.append({'file': str(tci_file), 'success': False, 'error': 'WAV folder not found'})
                continue
            
            print(f"  ✓ Found WAV folder: {wav_folder}")
            
            # Generate output filename
            if output_dir:
                json_file = output_path / f"{tci_path.stem}.json"
            else:
                json_file = tci_path.parent / f"{tci_path.stem}.json"
            
            # Create mapping
            mapping = tci.create_mapping_json(json_file, wav_folder)
            
            print(f"  ✓ Created: {json_file}")
            print(f"  Samples: {header['total_samples']}, Velocity Layers: {header['velocity_layers']}, Round Robins: {header['round_robins']}")
            
            results.append({
                'file': str(tci_file),
                'success': True,
                'json': str(json_file),
                'wav_folder': str(wav_folder),
                'samples': header['total_samples']
            })
            
        except Exception as e:
            print(f"  ✗ Error: {e}")
            results.append({'file': str(tci_file), 'success': False, 'error': str(e)})
    
    return results

def main():
    import argparse
    
    parser = argparse.ArgumentParser(description='Batch convert TCI files to JSON mappings')
    parser.add_argument('tci_files', nargs='+', help='TCI files to convert')
    parser.add_argument('--output-dir', '-o', help='Output directory for JSON files')
    parser.add_argument('--wav-base-dir', '-w', help='Base directory containing WAV folders')
    parser.add_argument('--summary', action='store_true', help='Print summary at the end')
    
    args = parser.parse_args()
    
    results = batch_convert(args.tci_files, args.output_dir, args.wav_base_dir)
    
    # Print summary
    print("\n" + "=" * 80)
    print("Conversion Summary")
    print("=" * 80)
    
    successful = [r for r in results if r['success']]
    failed = [r for r in results if not r['success']]
    
    print(f"Total: {len(results)}")
    print(f"✓ Successful: {len(successful)}")
    print(f"✗ Failed: {len(failed)}")
    
    if failed:
        print("\nFailed conversions:")
        for r in failed:
            print(f"  - {Path(r['file']).name}: {r.get('error', 'Unknown error')}")
    
    if successful:
        print(f"\n✓ JSON files created: {len(successful)}")
        if args.summary:
            for r in successful:
                print(f"  {r['json']}")

if __name__ == "__main__":
    main()
