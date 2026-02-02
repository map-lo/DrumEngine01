#!/usr/bin/env python3
"""
Migrate User-Installed Presets to .preset Folder Structure

This script migrates presets from ~/Documents/DrumEngine01/ old structure to new .preset folders:
- Finds JSON files in ~/Documents/DrumEngine01/presets/
- Creates {PresetName}.preset/ folders
- Copies samples from ~/Documents/DrumEngine01/samples/ into .preset folders
- Removes rootFolder field from JSON
- Removes old JSON files and samples directory after migration

Usage:
    python migrate_user_presets.py [--dry-run]
    
Options:
    --dry-run    Show what would be done without making changes
"""

import argparse
import json
import shutil
from pathlib import Path
from typing import List
import os


class UserPresetMigrator:
    def __init__(self, dry_run: bool = False):
        self.dry_run = dry_run
        self.docs_dir = Path.home() / "Documents" / "DrumEngine01"
        self.presets_dir = self.docs_dir / "presets"
        self.samples_dir = self.docs_dir / "samples"
        
        self.processed_count = 0
        self.error_count = 0
        self.errors: List[str] = []
    
    def migrate_all_presets(self):
        """Main entry point - scan and migrate all installed presets"""
        print(f"Starting user preset migration to .preset folder structure...")
        print(f"Location: {self.docs_dir}")
        if self.dry_run:
            print("DRY RUN MODE - No changes will be made")
        print()
        
        # Check if directories exist
        if not self.presets_dir.exists():
            print(f"❌ Error: Presets directory not found: {self.presets_dir}")
            print("No presets to migrate.")
            return
        
        if not self.samples_dir.exists():
            print(f"⚠️  Warning: Samples directory not found: {self.samples_dir}")
            print("Will create .preset folders without samples.")
            print()
        
        # Find all JSON preset files recursively (but not inside .preset folders)
        json_files = []
        for json_file in self.presets_dir.rglob("*.json"):
            # Skip if already inside a .preset folder
            if any(parent.name.endswith(".preset") for parent in json_file.parents):
                continue
            json_files.append(json_file)
        
        if len(json_files) == 0:
            print("No presets to migrate (all presets are already in .preset format)")
            return
        
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
        
        # Clean up old samples directory if migration was successful
        if not self.dry_run and self.processed_count > 0 and self.error_count == 0:
            print()
            if self.samples_dir.exists():
                print(f"Removing old samples directory: {self.samples_dir}")
                shutil.rmtree(self.samples_dir)
                print("✅ Old samples directory removed")
    
    def migrate_preset(self, json_file: Path):
        """Migrate a single preset file to .preset folder structure"""
        rel_path = json_file.relative_to(self.presets_dir)
        print(f"Migrating: {rel_path}")
        
        # Read and parse JSON
        with open(json_file, 'r') as f:
            preset_data = json.load(f)
        
        # Get the current rootFolder (path to samples)
        original_root_folder = preset_data.get("rootFolder", "")
        
        # Get preset name (without extension)
        preset_name = json_file.stem
        
        # Create .preset folder path
        preset_folder = json_file.parent / f"{preset_name}.preset"
        
        print(f"  Creating: {preset_folder.name}/")
        
        if not self.dry_run:
            preset_folder.mkdir(exist_ok=True)
        
        # Copy samples if rootFolder is specified and samples directory exists
        copied_samples = 0
        common_prefix = None
        new_wav_paths_map = {}  # Track updated paths for rewriting JSON
        
        if original_root_folder:
            # The rootFolder in installed presets typically looks like:
            # ~/Documents/DrumEngine01/samples/ThatSound DarrenKing/Kick/BOWSER
            # We need to resolve ~ and convert to Path
            if original_root_folder.startswith("~"):
                root_folder_path = Path(os.path.expanduser(original_root_folder))
            else:
                root_folder_path = Path(original_root_folder)
            
            if root_folder_path.exists():
                # First pass: collect all WAV paths to find common prefix
                velocity_layers = preset_data.get("velocityLayers", [])
                all_wav_paths = []
                
                for layer in velocity_layers:
                    wavs_by_slot = layer.get("wavsBySlot", {})
                    for slot_num, wav_paths in wavs_by_slot.items():
                        if isinstance(wav_paths, list):
                            all_wav_paths.extend([p for p in wav_paths if p])
                
                # Find common prefix in all paths (e.g., "Trigger2 Snares/NeverSnare/")
                if all_wav_paths:
                    path_parts_list = [Path(p).parts for p in all_wav_paths]
                    if path_parts_list:
                        common_parts = []
                        for parts in zip(*path_parts_list):
                            if len(set(parts)) == 1:  # All paths have same part at this level
                                common_parts.append(parts[0])
                            else:
                                break
                        if common_parts:
                            common_prefix = Path(*common_parts)
                
                # Second pass: copy files with flattened paths
                for layer_idx, layer in enumerate(velocity_layers):
                    wavs_by_slot = layer.get("wavsBySlot", {})
                    
                    for slot_num, wav_paths in wavs_by_slot.items():
                        if not isinstance(wav_paths, list):
                            continue
                        
                        new_paths = []
                        for relative_wav_path in wav_paths:
                            if not relative_wav_path:
                                new_paths.append(relative_wav_path)
                                continue
                            
                            # Source: root_folder_path + relative_wav_path
                            source_wav = root_folder_path / relative_wav_path
                            
                            # Remove common prefix from destination path
                            rel_path = Path(relative_wav_path)
                            if common_prefix and rel_path.is_relative_to(common_prefix):
                                flattened_path = rel_path.relative_to(common_prefix)
                            else:
                                flattened_path = rel_path
                            
                            # Destination: preset_folder + flattened_path
                            dest_wav = preset_folder / flattened_path
                            
                            # Copy the WAV file
                            if source_wav.exists():
                                if not self.dry_run:
                                    dest_wav.parent.mkdir(parents=True, exist_ok=True)
                                    shutil.copy2(source_wav, dest_wav)
                                copied_samples += 1
                                new_paths.append(str(flattened_path))
                            else:
                                print(f"  ⚠️  Warning: Sample not found: {source_wav}")
                                new_paths.append(relative_wav_path)
                        
                        # Update the wav paths in the JSON data
                        preset_data["velocityLayers"][layer_idx]["wavsBySlot"][slot_num] = new_paths
            else:
                print(f"  ⚠️  Warning: Root folder not found: {root_folder_path}")
        
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
        description='Migrate installed DrumEngine01 presets to .preset folder structure',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python migrate_user_presets.py              # Migrate all installed presets
  python migrate_user_presets.py --dry-run    # Show what would be done

This script migrates presets in:
  ~/Documents/DrumEngine01/presets/
  
It will remove the old samples directory after successful migration.
        """
    )
    parser.add_argument(
        '--dry-run',
        action='store_true',
        help='Show what would be done without making changes'
    )
    
    args = parser.parse_args()
    
    migrator = UserPresetMigrator(dry_run=args.dry_run)
    migrator.migrate_all_presets()
    
    return 0 if migrator.error_count == 0 else 1


if __name__ == "__main__":
    exit(main())
