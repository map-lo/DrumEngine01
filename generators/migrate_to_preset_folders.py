#!/usr/bin/env python3
"""
Migrate existing presets to .preset folder structure

This script converts old-style presets (JSON + external samples) to new .preset folders:
- Creates {PresetName}.preset/ folder for each .json file
- Moves JSON as preset.json inside the folder
- Copies samples from rootFolder into the .preset folder
- Removes rootFolder field from JSON

Usage:
    python migrate_to_preset_folders.py [--dry-run]
    
Options:
    --dry-run    Show what would be done without making changes
"""

import argparse
import json
import shutil
from pathlib import Path
from typing import List
import os


class PresetMigrator:
    def __init__(self, presets_dir: Path, dry_run: bool = False):
        self.presets_dir = presets_dir
        self.dry_run = dry_run
        
        self.processed_count = 0
        self.error_count = 0
        self.errors: List[str] = []
    
    def migrate_all_presets(self):
        """Main entry point - scan and migrate all presets"""
        print(f"Starting preset migration to .preset folder structure...")
        print(f"Source: {self.presets_dir}")
        if self.dry_run:
            print("DRY RUN MODE - No changes will be made")
        print()
        
        # Find all JSON preset files recursively (but not inside .preset folders)
        json_files = []
        for json_file in self.presets_dir.rglob("*.json"):
            # Skip if already inside a .preset folder
            if any(parent.name.endswith(".preset") for parent in json_file.parents):
                continue
            json_files.append(json_file)
        
        print(f"Found {len(json_files)} preset files to migrate")
        print()
        
        for json_file in json_files:
            try:
                self.migrate_preset(json_file)
            except Exception as e:
                error_msg = f"Error migrating {json_file}: {e}"
                self.errors.append(error_msg)
                self.error_count += 1
                print(f"❌ {error_msg}")
        
        # Print summary
        print()
        print("=" * 70)
        print(f"Migration complete!")
        print(f"✅ Successfully migrated: {self.processed_count} presets")
        if self.error_count > 0:
            print(f"❌ Errors: {self.error_count}")
            print()
            print("Error details:")
            for error in self.errors:
                print(f"  - {error}")
        print("=" * 70)
    
    def migrate_preset(self, json_file: Path):
        """Migrate a single preset file to .preset folder structure"""
        rel_path = json_file.relative_to(self.presets_dir)
        print(f"Migrating: {rel_path}")
        
        # Read and parse JSON
        with open(json_file, 'r') as f:
            preset_data = json.load(f)
        
        # Get the current rootFolder (absolute path to samples)
        original_root_folder = preset_data.get("rootFolder", "")
        if not original_root_folder:
            print(f"  ⚠️  Warning: No rootFolder found, skipping")
            return
        
        # Get preset name (without extension)
        preset_name = json_file.stem
        
        # Create .preset folder path
        preset_folder = json_file.parent / f"{preset_name}.preset"
        
        print(f"  Creating: {preset_folder.name}/")
        
        if not self.dry_run:
            preset_folder.mkdir(exist_ok=True)
        
        # Copy all sample files referenced in the preset
        velocity_layers = preset_data.get("velocityLayers", [])
        copied_samples = 0
        
        for layer in velocity_layers:
            wavs_by_slot = layer.get("wavsBySlot", {})
            
            for slot_num, wav_paths in wavs_by_slot.items():
                if not isinstance(wav_paths, list):
                    continue
                
                for relative_wav_path in wav_paths:
                    if not relative_wav_path:
                        continue
                    
                    # Source: original_root_folder + relative_wav_path
                    source_wav = Path(original_root_folder) / relative_wav_path
                    
                    # Destination: preset_folder + relative_wav_path (preserve subfolder structure)
                    dest_wav = preset_folder / relative_wav_path
                    
                    # Copy the WAV file
                    if source_wav.exists():
                        if not self.dry_run:
                            dest_wav.parent.mkdir(parents=True, exist_ok=True)
                            shutil.copy2(source_wav, dest_wav)
                        copied_samples += 1
                    else:
                        print(f"  ⚠️  Warning: Sample not found: {source_wav}")
        
        # Remove rootFolder field from JSON
        if "rootFolder" in preset_data:
            del preset_data["rootFolder"]
        
        # Write preset.json inside the .preset folder
        preset_json = preset_folder / "preset.json"
        if not self.dry_run:
            with open(preset_json, 'w') as f:
                json.dump(preset_data, f, indent=2)
            
            # Remove old JSON file
            json_file.unlink()
        
        print(f"  ✅ Copied {copied_samples} samples")
        print(f"  📝 Created preset.json (removed rootFolder field)")
        if not self.dry_run:
            print(f"  🗑️  Removed old {json_file.name}")
        print()
        
        self.processed_count += 1


def main():
    # Parse command-line arguments
    parser = argparse.ArgumentParser(
        description='Migrate DrumEngine01 presets to .preset folder structure',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python migrate_to_preset_folders.py              # Migrate all presets
  python migrate_to_preset_folders.py --dry-run    # Show what would be done
        """
    )
    parser.add_argument(
        '--dry-run',
        action='store_true',
        help='Show what would be done without making changes'
    )
    
    args = parser.parse_args()
    
    # Paths relative to this script
    script_dir = Path(__file__).parent
    project_root = script_dir.parent
    
    presets_dir = project_root / "presets" / "factory01"
    
    if not presets_dir.exists():
        print(f"❌ Error: Presets directory not found: {presets_dir}")
        print("Please ensure presets/ exists in the project root")
        return 1
    
    migrator = PresetMigrator(presets_dir, dry_run=args.dry_run)
    migrator.migrate_all_presets()
    
    return 0 if migrator.error_count == 0 else 1


if __name__ == "__main__":
    exit(main())
