#!/usr/bin/env python3
"""
Recursive TCI Converter
Recursively searches for .tci files in a directory tree and converts them to JSON mappings
"""

import sys
import json
from pathlib import Path
from tci_extractor import TCIFile

def find_tci_files(root_dir, recursive=True):
    """
    Find all .tci files in a directory
    
    Args:
        root_dir: Root directory to search
        recursive: If True, search subdirectories
        
    Returns:
        List of Path objects for .tci files
    """
    root_path = Path(root_dir)
    
    if not root_path.exists():
        print(f"Error: Directory not found: {root_dir}")
        return []
    
    if recursive:
        tci_files = list(root_path.rglob("*.tci"))
    else:
        tci_files = list(root_path.glob("*.tci"))
    
    return sorted(tci_files)

def find_wav_folder_for_tci(tci_file, wav_search_paths=None):
    """
    Try to find the corresponding WAV folder for a TCI file
    
    Strategy:
    1. Look for folder with same name in same directory
    2. Look for folder with same name in parent directory
    3. Search in provided search paths
    4. Look in common Slate Trigger 2 locations
    """
    tci_path = Path(tci_file)
    tci_name = tci_path.stem
    
    # Strategy 1: Same directory
    same_dir_folder = tci_path.parent / tci_name
    if same_dir_folder.exists() and same_dir_folder.is_dir():
        return same_dir_folder
    
    # Strategy 2: Parent directory
    parent_folder = tci_path.parent.parent / tci_name
    if parent_folder.exists() and parent_folder.is_dir():
        return parent_folder
    
    # Strategy 3: Search in provided paths
    if wav_search_paths:
        for search_path in wav_search_paths:
            search_root = Path(search_path)
            if search_root.exists():
                # Search recursively for matching folder
                for folder in search_root.rglob("*"):
                    if folder.is_dir() and tci_name.lower() in folder.name.lower():
                        # Check if it contains WAV files
                        if any(folder.glob("*.wav")):
                            return folder
    
    # Strategy 4: Common locations
    common_bases = [
        Path.home() / "Downloads" / "SPINLIGHT SAMPLES" / "WAV Files",
        Path.home() / "Music" / "Slate Digital" / "Trigger 2" / "Samples",
        Path.home() / "Documents" / "Slate Digital" / "Trigger 2" / "Samples",
        Path("/Library/Application Support/Slate Digital/Trigger 2/Samples"),
        Path.home() / "Samples",
    ]
    
    for base in common_bases:
        if base.exists():
            for folder in base.rglob("*"):
                if folder.is_dir() and tci_name.lower() in folder.name.lower():
                    if any(folder.glob("*.wav")):
                        return folder
    
    return None

def recursive_convert(input_dir, output_dir=None, wav_search_paths=None, 
                     preserve_structure=True, dry_run=False):
    """
    Recursively convert all TCI files in a directory tree
    
    Args:
        input_dir: Root directory containing .tci files
        output_dir: Output directory for JSON files (default: same as input)
        wav_search_paths: List of directories to search for WAV files
        preserve_structure: Preserve directory structure in output
        dry_run: If True, only show what would be done
    """
    
    print("=" * 80)
    print("Recursive TCI Converter")
    print("=" * 80)
    print(f"Input Directory: {input_dir}")
    print(f"Output Directory: {output_dir or 'Same as input'}")
    print(f"Preserve Structure: {preserve_structure}")
    print(f"Dry Run: {dry_run}")
    print()
    
    # Find all TCI files
    print("Searching for .tci files...")
    tci_files = find_tci_files(input_dir, recursive=True)
    
    if not tci_files:
        print("No .tci files found.")
        return []
    
    print(f"Found {len(tci_files)} .tci file(s)")
    print()
    
    # Process each TCI file
    results = []
    input_path = Path(input_dir)
    output_path = Path(output_dir) if output_dir else None
    
    for idx, tci_file in enumerate(tci_files, 1):
        tci_path = Path(tci_file)
        rel_path = tci_path.relative_to(input_path)
        
        print(f"[{idx}/{len(tci_files)}] {rel_path}")
        print("-" * 80)
        
        try:
            # Parse TCI file
            tci = TCIFile(tci_path)
            header = tci.parse_header()
            
            print(f"  Samples: {header['total_samples']}, "
                  f"Vel Layers: {header['velocity_layers']}, "
                  f"RR: {header['round_robins']}")
            
            # Find WAV folder
            wav_folder = find_wav_folder_for_tci(tci_path, wav_search_paths)
            
            if not wav_folder:
                print(f"  ⚠️  WAV folder not found")
                results.append({
                    'file': str(tci_path),
                    'relative_path': str(rel_path),
                    'success': False,
                    'error': 'WAV folder not found'
                })
                print()
                continue
            
            print(f"  ✓ WAV folder: {wav_folder}")
            
            # Verify WAV files exist
            wav_files = list(Path(wav_folder).glob("*.wav"))
            if len(wav_files) != header['total_samples']:
                print(f"  ⚠️  Expected {header['total_samples']} WAV files, found {len(wav_files)}")
            
            # Determine output file path
            if output_path:
                if preserve_structure:
                    # Preserve directory structure
                    json_rel_path = rel_path.with_suffix('.json')
                    json_file = output_path / json_rel_path
                else:
                    # Flat structure
                    json_file = output_path / f"{tci_path.stem}.json"
            else:
                # Same directory as TCI file
                json_file = tci_path.with_suffix('.json')
            
            if dry_run:
                print(f"  [DRY RUN] Would create: {json_file}")
            else:
                # Create output directory
                json_file.parent.mkdir(parents=True, exist_ok=True)
                
                # Create mapping
                mapping = tci.create_mapping_json(json_file, wav_folder)
                print(f"  ✓ Created: {json_file}")
            
            results.append({
                'file': str(tci_path),
                'relative_path': str(rel_path),
                'success': True,
                'json': str(json_file),
                'wav_folder': str(wav_folder),
                'samples': header['total_samples']
            })
            
        except Exception as e:
            print(f"  ✗ Error: {e}")
            results.append({
                'file': str(tci_path),
                'relative_path': str(rel_path),
                'success': False,
                'error': str(e)
            })
        
        print()
    
    # Print summary
    print("=" * 80)
    print("Conversion Summary")
    print("=" * 80)
    
    successful = [r for r in results if r['success']]
    failed = [r for r in results if not r['success']]
    
    print(f"Total files: {len(results)}")
    print(f"✓ Successful: {len(successful)}")
    print(f"✗ Failed: {len(failed)}")
    
    if successful:
        total_samples = sum(r.get('samples', 0) for r in successful)
        print(f"\nTotal samples mapped: {total_samples}")
    
    if failed:
        print("\nFailed conversions:")
        for r in failed:
            print(f"  - {r['relative_path']}: {r.get('error', 'Unknown error')}")
    
    return results

def main():
    import argparse
    
    parser = argparse.ArgumentParser(
        description='Recursively convert TCI files to JSON mappings',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Convert all TCI files in a directory, preserving structure
  python3 recursive_tci_converter.py /path/to/tci/files --output-dir ./json
  
  # Dry run to see what would be done
  python3 recursive_tci_converter.py /path/to/tci/files --dry-run
  
  # Specify WAV search paths
  python3 recursive_tci_converter.py /path/to/tci/files \\
      --wav-search /path/to/samples1 \\
      --wav-search /path/to/samples2
  
  # Flat output structure (all JSONs in one directory)
  python3 recursive_tci_converter.py /path/to/tci/files \\
      --output-dir ./json \\
      --no-preserve-structure
        """
    )
    
    parser.add_argument('input_dir', 
                       help='Root directory containing .tci files')
    parser.add_argument('--output-dir', '-o', 
                       help='Output directory for JSON files (default: same as input)')
    parser.add_argument('--wav-search', '-w', 
                       action='append',
                       dest='wav_search_paths',
                       help='Directories to search for WAV files (can be used multiple times)')
    parser.add_argument('--no-preserve-structure',
                       action='store_false',
                       dest='preserve_structure',
                       help='Do not preserve directory structure in output')
    parser.add_argument('--dry-run',
                       action='store_true',
                       help='Show what would be done without creating files')
    parser.add_argument('--summary-json',
                       help='Save summary to JSON file')
    
    args = parser.parse_args()
    
    # Validate input directory
    if not Path(args.input_dir).exists():
        print(f"Error: Input directory not found: {args.input_dir}")
        sys.exit(1)
    
    # Run conversion
    results = recursive_convert(
        args.input_dir,
        args.output_dir,
        args.wav_search_paths,
        args.preserve_structure,
        args.dry_run
    )
    
    # Save summary if requested
    if args.summary_json and not args.dry_run:
        summary = {
            'input_dir': args.input_dir,
            'output_dir': args.output_dir,
            'total_files': len(results),
            'successful': len([r for r in results if r['success']]),
            'failed': len([r for r in results if not r['success']]),
            'results': results
        }
        
        summary_path = Path(args.summary_json)
        summary_path.parent.mkdir(parents=True, exist_ok=True)
        
        with open(summary_path, 'w') as f:
            json.dump(summary, f, indent=2)
        
        print(f"\n✓ Summary saved to: {summary_path}")
    
    # Exit with appropriate code
    failed_count = len([r for r in results if not r['success']])
    sys.exit(0 if failed_count == 0 else 1)

if __name__ == "__main__":
    main()
