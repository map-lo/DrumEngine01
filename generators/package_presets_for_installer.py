#!/usr/bin/env python3
"""
Preset Packager for DrumEngine01

This script packages presets for installer distribution:
- Copies the full presets folder (including all subfolders) to dist/factory-content/presets/

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
        """Main entry point - copy full presets folder"""
        print("Starting preset packaging...")
        print(f"Source: {self.source_presets_dir}")
        print(f"Output: {self.output_dir}")
        print()

        # Copy the entire presets tree without filtering or inspection
        shutil.copytree(self.source_presets_dir, self.presets_output_dir, dirs_exist_ok=True)

        print("✅ Copied full presets folder")
        print()
        print("=" * 70)
        print("Processing complete!")
        print("=" * 70)
    
    def process_preset(self, preset_folder: Path):
        """Deprecated: per-preset processing is no longer used."""
        pass


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
