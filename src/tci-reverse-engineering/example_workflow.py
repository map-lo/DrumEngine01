#!/usr/bin/env python3
"""
Example: Convert TCI file and generate plugin-compatible preset JSON
This demonstrates the complete workflow from TCI to usable plugin preset
"""

import json
from pathlib import Path
from tci_extractor import TCIFile

def convert_tci_to_plugin_preset(tci_path, wav_folder, output_json):
    """
    Complete workflow to convert a TCI file into a plugin preset
    
    Args:
        tci_path: Path to .tci file
        wav_folder: Path to folder containing WAV files
        output_json: Output path for JSON preset file
    """
    
    print("=" * 80)
    print("TCI to Plugin Preset Converter")
    print("=" * 80)
    print()
    
    # Step 1: Analyze TCI file
    print("Step 1: Analyzing TCI file...")
    print("-" * 80)
    tci = TCIFile(tci_path)
    header = tci.parse_header()
    
    print(f"✓ TCI File: {Path(tci_path).name}")
    print(f"  - Samples: {header['total_samples']}")
    print(f"  - Velocity Layers: {header['velocity_layers']}")
    print(f"  - Round Robins: {header['round_robins']}")
    print(f"  - Sample Rate: {header['sample_rate']} Hz")
    print()
    
    # Step 2: Verify WAV files exist
    print("Step 2: Verifying WAV files...")
    print("-" * 80)
    wav_path = Path(wav_folder)
    
    if not wav_path.exists():
        print(f"✗ Error: WAV folder not found: {wav_folder}")
        return False
    
    wav_files = list(wav_path.glob("*.wav"))
    print(f"✓ Found {len(wav_files)} WAV files in: {wav_path}")
    
    expected_files = header['total_samples']
    if len(wav_files) != expected_files:
        print(f"⚠️  Warning: Expected {expected_files} files, found {len(wav_files)}")
    print()
    
    # Step 3: Create mapping JSON
    print("Step 3: Creating preset JSON...")
    print("-" * 80)
    mapping = tci.create_mapping_json(output_json, wav_folder)
    print(f"✓ Created: {output_json}")
    print()
    
    # Step 4: Verify mapping
    print("Step 4: Verifying mapping...")
    print("-" * 80)
    all_valid = True
    
    for articulation in mapping['articulations']:
        for vel_layer in articulation['velocityLayers']:
            for rr in vel_layer['roundRobins']:
                if not Path(rr['file']).exists():
                    print(f"✗ Missing: {rr['file']}")
                    all_valid = False
    
    if all_valid:
        print(f"✓ All {expected_files} sample files verified")
    print()
    
    # Step 5: Generate usage example
    print("Step 5: Plugin Integration Example")
    print("-" * 80)
    print("C++ code to load this preset:")
    print()
    print("```cpp")
    print(f'// Load preset JSON')
    print(f'juce::File presetFile("{output_json}");')
    print(f'auto json = juce::JSON::parse(presetFile);')
    print(f'')
    print(f'if (auto* root = json.getDynamicObject()) {{')
    print(f'    // Get sample rate')
    print(f'    int sampleRate = root->getProperty("sampleRate");')
    print(f'    ')
    print(f'    // Load articulations')
    print(f'    auto* articulations = root->getProperty("articulations").getArray();')
    print(f'    for (auto& art : *articulations) {{')
    print(f'        auto* artObj = art.getDynamicObject();')
    print(f'        int midiNote = artObj->getProperty("midiNote");')
    print(f'        ')
    print(f'        // Load velocity layers')
    print(f'        auto* velLayers = artObj->getProperty("velocityLayers").getArray();')
    print(f'        for (auto& vel : *velLayers) {{')
    print(f'            auto* velObj = vel.getDynamicObject();')
    print(f'            auto* velRange = velObj->getProperty("velocityRange").getDynamicObject();')
    print(f'            ')
    print(f'            int minVel = velRange->getProperty("min");')
    print(f'            int maxVel = velRange->getProperty("max");')
    print(f'            ')
    print(f'            // Load round robins')
    print(f'            auto* rrs = velObj->getProperty("roundRobins").getArray();')
    print(f'            for (auto& rr : *rrs) {{')
    print(f'                auto* rrObj = rr.getDynamicObject();')
    print(f'                juce::String filePath = rrObj->getProperty("file");')
    print(f'                int rrIndex = rrObj->getProperty("index");')
    print(f'                ')
    print(f'                // Load the sample into your engine')
    print(f'                engine.loadSample(filePath, midiNote, minVel, maxVel, rrIndex);')
    print(f'            }}')
    print(f'        }}')
    print(f'    }}')
    print(f'}}')
    print("```")
    print()
    
    # Success summary
    print("=" * 80)
    print("✓ Conversion Complete!")
    print("=" * 80)
    print(f"Preset file: {output_json}")
    print(f"Sample files: {wav_folder}")
    print(f"Total samples: {expected_files}")
    print()
    print("Your preset is ready to use with your plugin!")
    
    return True

# Example usage
if __name__ == "__main__":
    # Example: Convert the Acrolite TCI file
    tci_file = "Vintage 70's Acrolite (Tight) - Close Mic.tci"
    wav_folder = "/Users/marian/Downloads/SPINLIGHT SAMPLES/WAV Files/VIntage 70's Acrolite (Tight)/Close Mic"
    output_json = "acrolite_preset_example.json"
    
    success = convert_tci_to_plugin_preset(tci_file, wav_folder, output_json)
    
    if success:
        print("\nNext steps:")
        print("1. Copy the JSON file to your plugin's presets folder")
        print("2. Implement the JSON loader in your C++ code (see example above)")
        print("3. Test loading the preset in your plugin")
        print("4. Repeat for other TCI files!")
