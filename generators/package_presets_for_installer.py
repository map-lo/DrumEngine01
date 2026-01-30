#!/usr/bin/env python3
"""
Preset Packager for DrumEngine01

This script converts local development presets to an installer-ready package:
- Copies preset JSON files to dist/factory-content/presets/ maintaining folder structure
- Copies sample WAV files from absolute paths to dist/factory-content/samples/ organized by preset path
- Rewrites JSON rootFolder to use ~/Documents/DrumEngine01/samples/{preset_path}
- Preserves wavsBySlot relative paths unchanged

Usage:
    python package_presets_for_installer.py
    
Output:
    dist/factory-content/
        presets/
            factory01/
                ThatSound DarrenKing/
                    Kick/
                        BOWSER.json
                    Snare/
                        BITE.json
        samples/
            factory01/
                ThatSound DarrenKing/
                    Kick/
                        BOWSER/
                            DRY/
                                BOWSER DRY V01.wav
                            OVERHEADS/
                                BOWSER OH V01.wav
"""

import json
import shutil
from pathlib import Path
from typing import Dict, List, Set
import os


class PresetPackager:
    def __init__(self, source_presets_dir: Path, output_dir: Path):
        self.source_presets_dir = source_presets_dir
        self.output_dir = output_dir
        self.presets_output_dir = output_dir / "presets"
        self.samples_output_dir = output_dir / "samples"
        
        self.processed_count = 0
        self.error_count = 0
        self.errors: List[str] = []
    
    def process_all_presets(self):
        """Main entry point - scan and process all presets"""
        print(f"Starting preset packaging...")
        print(f"Source: {self.source_presets_dir}")
        print(f"Output: {self.output_dir}")
        print()
        
        # Create output directories
        self.presets_output_dir.mkdir(parents=True, exist_ok=True)
        self.samples_output_dir.mkdir(parents=True, exist_ok=True)
        
        # Find all JSON preset files recursively
        json_files = list(self.source_presets_dir.rglob("*.json"))
        print(f"Found {len(json_files)} preset files")
        print()
        
        for json_file in json_files:
            try:
                self.process_preset(json_file)
            except Exception as e:
                error_msg = f"Error processing {json_file}: {e}"
                self.errors.append(error_msg)
                self.error_count += 1
                print(f"❌ {error_msg}")
        
        # Print summary
        print()
        print("=" * 70)
        print(f"Processing complete!")
        print(f"✅ Successfully processed: {self.processed_count} presets")
        if self.error_count > 0:
            print(f"❌ Errors: {self.error_count}")
            print()
            print("Error details:")
            for error in self.errors:
                print(f"  - {error}")
        print("=" * 70)
    
    def process_preset(self, json_file: Path):
        """Process a single preset file"""
        # Calculate relative path from source directory
        rel_path = json_file.relative_to(self.source_presets_dir)
        
        print(f"Processing: {rel_path}")
        
        # Read and parse JSON
        with open(json_file, 'r') as f:
            preset_data = json.load(f)
        
        # Get the current rootFolder (absolute path to samples)
        original_root_folder = preset_data.get("rootFolder", "")
        if not original_root_folder:
            raise ValueError(f"Missing rootFolder in {json_file}")
        
        # Get preset name (without extension)
        preset_name = json_file.stem
        
        # Calculate the category path (relative path without the filename)
        category_path = rel_path.parent
        
        # Create new sample directory path in output
        # dist/samples/factory01/ThatSound DarrenKing/Kick/BOWSER/
        new_sample_dir = self.samples_output_dir / category_path / preset_name
        new_sample_dir.mkdir(parents=True, exist_ok=True)
        
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
                    
                    # Destination: new_sample_dir + relative_wav_path (preserve subfolder structure)
                    dest_wav = new_sample_dir / relative_wav_path
                    
                    # Copy the WAV file
                    if source_wav.exists():
                        dest_wav.parent.mkdir(parents=True, exist_ok=True)
                        shutil.copy2(source_wav, dest_wav)
                        copied_samples += 1
                    else:
                        print(f"  ⚠️  Warning: Sample not found: {source_wav}")
        
        # Update rootFolder to use tilde path
        # ~/Documents/DrumEngine01/samples/factory01/ThatSound DarrenKing/Kick/BOWSER
        new_root_folder = f"~/Documents/DrumEngine01/samples/{category_path}/{preset_name}"
        preset_data["rootFolder"] = new_root_folder
        
        # Write updated JSON to output directory
        output_json = self.presets_output_dir / rel_path
        output_json.parent.mkdir(parents=True, exist_ok=True)
        
        with open(output_json, 'w') as f:
            json.dump(preset_data, f, indent=2)
        
        print(f"  ✅ Copied {copied_samples} samples")
        print(f"  📝 Updated rootFolder: {new_root_folder}")
        print()
        
        self.processed_count += 1


def main():
    # Paths relative to this script
    script_dir = Path(__file__).parent
    project_root = script_dir.parent
    
    source_presets = project_root / "presets" / "factory01"
    output_dir = project_root / "dist" / "factory-content"
    
    if not source_presets.exists():
        print(f"❌ Error: Source presets directory not found: {source_presets}")
        print("Please ensure presets/factory01/ exists in the project root")
        return 1
    
    # Clean factory-content directory if it exists
    if output_dir.exists():
        print(f"Cleaning existing factory-content directory: {output_dir}")
        shutil.rmtree(output_dir)
        print()
    
    packager = PresetPackager(source_presets, output_dir)
    packager.process_all_presets()
    
    return 0 if packager.error_count == 0 else 1


if __name__ == "__main__":
    exit(main())
