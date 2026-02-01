import os
import json

# Paths
revival_snares_path = "/Users/marian/Samples/YurtRock/RevivalSnares"
presets_path = "/Users/marian/Development/JUCE-Plugins/DrumEngine01/presets/factory01/YurtRock RevivalSnare"

# Mapping from mic folder names to slot numbers
mic_to_slot = {
    "TOP": 1,
    "BOTTOM": 2,
    "OVERHEAD": 3,
    "ROOM AKG": 4,
    "ROOM R88": 5
}

# Slot names as per the example
slot_names = ["top", "bottom", "oh", "room1", "room2", "extra1", "extra2", "extra3"]

# Ensure presets path exists
os.makedirs(presets_path, exist_ok=True)

# Process each snare folder
for snare_folder in sorted(os.listdir(revival_snares_path)):
    if not snare_folder.startswith("SNARE_"):
        continue
    
    snare_path = os.path.join(revival_snares_path, snare_folder)
    if not os.path.isdir(snare_path):
        continue
    
    print(f"Processing {snare_folder}")
    
    root_folder = snare_path
    wavs_by_slot = {str(i): [] for i in range(1, 9)}
    
    # Collect CENTER wavs for each mic
    for mic, slot in mic_to_slot.items():
        mic_path = os.path.join(snare_path, mic)
        if not os.path.exists(mic_path):
            continue
        
        wavs = []
        for file in os.listdir(mic_path):
            if file.endswith(".wav") and "_CENTER_" in file:
                wavs.append(file)
        
        # Sort wavs (assuming they are numbered sequentially)
        wavs.sort()
        
        # Store relative paths
        wavs_by_slot[str(slot)] = [os.path.join(mic, w) for w in wavs]
    
    # Create JSON data
    data = {
        "schemaVersion": 1,
        "instrumentType": "snare",
        "slotNames": slot_names,
        "velocityLayers": [
            {
                "index": 1,
                "lo": 1,
                "hi": 127,
                "wavsBySlot": wavs_by_slot
            }
        ],
        "velToVol": {
            "amount": 0,
            "curve": {
                "type": "builtin",
                "name": "soft"
            }
        }
    }
    
    # Create .preset folder and write JSON file
    preset_folder_path = os.path.join(presets_path, f"{snare_folder}.preset")
    os.makedirs(preset_folder_path, exist_ok=True)
    json_path = os.path.join(preset_folder_path, "preset.json")
    with open(json_path, 'w') as f:
        json.dump(data, f, indent=2)
    
    print(f"Created {json_path}")

print("Conversion complete!")