#!/usr/bin/env python3
"""
Preset Packager for DrumEngine01

This script packages .preset folders for installer distribution:
- Copies .preset folders (containing preset.json and sample WAV files) to dist/factory-content/presets/
- Maintains folder structure and organization
- No JSON rewriting needed since rootFolder is auto-resolved to preset folder location

Usage:
    python package_presets_for_installer.py [--limit N]
    
Options:
    --limit N    Limit to N presets per subfolder (for testing smaller installers)
    
Output:
    dist/factory-content/
        presets/
            factory01/
                ThatSound DarrenKing/
                    Kick/
                        BOWSER.preset/
                            preset.json
                            DRY/
                                BOWSER DRY V01.wav
                            OVERHEADS/
                                BOWSER OH V01.wav
"""

import argparse
import json
import shutil
from pathlib import Path
from typing import Dict, List, Set
import os


class PresetPackager:
    def __init__(self, source_presets_dir: Path, output_dir: Path, limit_per_folder: int = None):
        self.source_presets_dir = source_presets_dir
        self.output_dir = output_dir
        self.presets_output_dir = output_dir / "presets"
        self.limit_per_folder = limit_per_folder
        
        self.processed_count = 0
        self.skipped_count = 0
        self.error_count = 0
        self.errors: List[str] = []
    
    def process_all_presets(self):
        """Main entry point - scan and process all .preset folders"""
        print(f"Starting preset packaging...")
        print(f"Source: {self.source_presets_dir}")
        print(f"Output: {self.output_dir}")
        if self.limit_per_folder:
            print(f"Limit: {self.limit_per_folder} presets per folder")
        print()
        
        # Create output directories
        self.presets_output_dir.mkdir(parents=True, exist_ok=True)
        
        # Find all .preset folders recursively
        preset_folders = [p for p in self.source_presets_dir.rglob("*") 
                         if p.is_dir() and p.name.endswith(".preset")]
        print(f"Found {len(preset_folders)} preset folders")
        print()
        
        # Group folders by parent directory if limiting
        if self.limit_per_folder:
            folders_by_parent = {}
            for preset_folder in preset_folders:
                parent = preset_folder.parent
                if parent not in folders_by_parent:
                    folders_by_parent[parent] = []
                folders_by_parent[parent].append(preset_folder)
            
            # Limit each parent folder and flatten
            preset_folders_to_process = []
            for parent, folders in folders_by_parent.items():
                limited_folders = folders[:self.limit_per_folder]
                preset_folders_to_process.extend(limited_folders)
                skipped = len(folders) - len(limited_folders)
                if skipped > 0:
                    self.skipped_count += skipped
                    print(f"Limiting {parent.name}: processing {len(limited_folders)}/{len(folders)} presets")
            
            print(f"\nProcessing {len(preset_folders_to_process)} presets (skipped {self.skipped_count})")
            print()
            preset_folders = preset_folders_to_process
        
        for preset_folder in preset_folders:
            try:
                self.process_preset(preset_folder)
            except Exception as e:
                error_msg = f"Error processing {preset_folder}: {e}"
                self.errors.append(error_msg)
                self.error_count += 1
                print(f"❌ {error_msg}")
        
        # Print summary
        print()
        print("=" * 70)
        print(f"Processing complete!")
        print(f"✅ Successfully processed: {self.processed_count} presets")
        if self.skipped_count > 0:
            print(f"⏭️  Skipped (limit): {self.skipped_count} presets")
        if self.error_count > 0:
            print(f"❌ Errors: {self.error_count}")
            print()
            print("Error details:")
            for error in self.errors:
                print(f"  - {error}")
        print("=" * 70)
    
    def process_preset(self, preset_folder: Path):
        """Process a single .preset folder by copying it wholesale"""
        # Calculate relative path from source directory
        rel_path = preset_folder.relative_to(self.source_presets_dir)
        
        print(f"Processing: {rel_path}")
        
        # Verify preset.json exists
        preset_json = preset_folder / "preset.json"
        if not preset_json.exists():
            raise ValueError(f"Missing preset.json in {preset_folder}")
        
        # Count WAV files
        wav_files = list(preset_folder.rglob("*.wav"))
        
        # Copy entire .preset folder to output
        output_preset_folder = self.presets_output_dir / rel_path
        
        # Use shutil.copytree to copy the entire folder structure
        shutil.copytree(preset_folder, output_preset_folder, dirs_exist_ok=True)
        
        print(f"  ✅ Copied preset folder with {len(wav_files)} samples")
        print()
        
        self.processed_count += 1


def main():
    # Parse command-line arguments
    parser = argparse.ArgumentParser(
        description='Package DrumEngine01 presets and samples for installer',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python package_presets_for_installer.py              # Package all presets
  python package_presets_for_installer.py --limit 2    # Limit to 2 presets per folder (testing)
        """
    )
    parser.add_argument(
        '--limit',
        type=int,
        metavar='N',
        help='Limit to N presets per subfolder (useful for testing smaller installers)'
    )
    
    args = parser.parse_args()
    
    # Paths relative to this script
    script_dir = Path(__file__).parent
    project_root = script_dir.parent
    
    source_presets = project_root / "presets"
    output_dir = project_root / "dist" / "factory-content"
    
    if not source_presets.exists():
        print(f"❌ Error: Source presets directory not found: {source_presets}")
        print("Please ensure presets/ exists in the project root")
        return 1
    
    # Clean factory-content directory if it exists
    if output_dir.exists():
        print(f"Cleaning existing factory-content directory: {output_dir}")
        shutil.rmtree(output_dir)
        print()
    
    packager = PresetPackager(source_presets, output_dir, limit_per_folder=args.limit)
    packager.process_all_presets()
    
    return 0 if packager.error_count == 0 else 1


if __name__ == "__main__":
    exit(main())
