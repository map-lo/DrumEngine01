import os
import json
import re

# Paths
ts_snares_path = "/Users/marian/Samples/TS DARREN KING DELUXE/02 SNARES"
presets_path = "/Users/marian/Development/JUCE-Plugins/DrumEngine01/presets/ThatSound DarrenKing/Snare"

# Mapping from mic folder names to slot numbers
mic_to_slot = {
    "DRY": 1,
    "OVERHEADS": 3,
    "ROOM 1": 4,
    "ROOM 2": 5
}

# Slot names
slot_names = ["top", "bottom", "oh", "room1", "room2", "extra1", "extra2", "extra3"]

# Velocity layer ranges
vel_layers = [
    {"index": 1, "lo": 1, "hi": 12},
    {"index": 2, "lo": 13, "hi": 24},
    {"index": 3, "lo": 25, "hi": 36},
    {"index": 4, "lo": 37, "hi": 48},
    {"index": 5, "lo": 49, "hi": 60},
    {"index": 6, "lo": 61, "hi": 72},
    {"index": 7, "lo": 73, "hi": 84},
    {"index": 8, "lo": 85, "hi": 96},
    {"index": 9, "lo": 97, "hi": 108},
    {"index": 10, "lo": 109, "hi": 127}
]

# Ensure presets path exists
os.makedirs(presets_path, exist_ok=True)

# Function to parse velocity from filename
def parse_velocity(filename):
    # Match V01, V02, ..., V10, and suffixes a,b,c,d
    match = re.search(r'V(\d+)([a-d]?)\.wav$', filename)
    if match:
        vel = int(match.group(1))
        suffix = match.group(2) or ''
        return vel, suffix
    return None, None

# Process each snare folder
for snare_folder in sorted(os.listdir(ts_snares_path)):
    snare_path = os.path.join(ts_snares_path, snare_folder)
    if not os.path.isdir(snare_path):
        continue
    
    print(f"Processing {snare_folder}")
    
    root_folder = snare_path
    
    # Collect samples by mic and velocity
    samples_by_mic_vel = {}
    for mic in mic_to_slot.keys():
        mic_path = os.path.join(snare_path, mic)
        if not os.path.exists(mic_path):
            continue
        
        samples_by_vel = {}
        for file in os.listdir(mic_path):
            if not file.endswith(".wav"):
                continue
            vel, suffix = parse_velocity(file)
            if vel is None:
                continue
            if vel not in samples_by_vel:
                samples_by_vel[vel] = []
            samples_by_vel[vel].append((suffix, os.path.join(mic, file)))
        
        # Sort suffixes for each vel
        for vel in samples_by_vel:
            samples_by_vel[vel].sort(key=lambda x: x[0])
            samples_by_vel[vel] = [path for _, path in samples_by_vel[vel]]
        
        samples_by_mic_vel[mic] = samples_by_vel
    
    # Build velocity layers
    velocity_layers = []
    for layer in vel_layers:
        index = layer["index"]
        wavs_by_slot = {str(i): [] for i in range(1, 9)}
        for mic, slot in mic_to_slot.items():
            if mic in samples_by_mic_vel and index in samples_by_mic_vel[mic]:
                wavs_by_slot[str(slot)] = samples_by_mic_vel[mic][index]
        velocity_layers.append({
            "index": index,
            "lo": layer["lo"],
            "hi": layer["hi"],
            "wavsBySlot": wavs_by_slot
        })
    
    # Create JSON data
    data = {
        "schemaVersion": 1,
        "instrumentType": "snare",
        "slotNames": slot_names,
        "velocityLayers": velocity_layers,
        "velToVol": {
            "amount": 70,
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