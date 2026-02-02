import os
import json
import re
import shutil

# Paths
revival_kicks_path = "/Users/marian/Samples/YurtRock/RevivalBassDrums"
presets_path = "/Users/marian/Development/JUCE-Plugins/DrumEngine01/presets/YurtRock RevivalKick"

# Mapping from mic folder names to slot numbers
mic_to_slot = {
    "KICK_D112": 1,
    "KICK_U195": 3,
    "KICK_R44": 4,
    "KICK_R88": 5,
}

# Slot names
slot_names = ["top", "bottom", "oh", "room1", "room2", "extra1", "extra2", "extra3"]

# Ensure presets path exists
os.makedirs(presets_path, exist_ok=True)


def normalize_articulation(name):
    cleaned = re.sub(r"\s*_\s*", "_", name.strip())
    cleaned = re.sub(r"\s+", "_", cleaned)
    cleaned = re.sub(r"_+", "_", cleaned)
    return cleaned


def parse_articulation(filename, mic_code):
    match = re.search(rf"_{re.escape(mic_code)}_(.+)_(\d+)\.wav$", filename)
    if match:
        return normalize_articulation(match.group(1)), int(match.group(2))
    return None, None


# Process each kick folder
for kick_folder in sorted(os.listdir(revival_kicks_path)):
    if not kick_folder.startswith("KICK_"):
        continue

    kick_path = os.path.join(revival_kicks_path, kick_folder)
    if not os.path.isdir(kick_path):
        continue

    print(f"Processing {kick_folder}")

    # Collect samples by articulation and mic
    articulations = {}
    for mic_folder, slot in mic_to_slot.items():
        mic_path = os.path.join(kick_path, mic_folder)
        if not os.path.exists(mic_path):
            continue

        mic_code = mic_folder.replace("KICK_", "")
        samples_by_art = {}
        for file in os.listdir(mic_path):
            if not file.endswith(".wav"):
                continue
            art, rr = parse_articulation(file, mic_code)
            if art is None:
                continue
            source_path = os.path.join(mic_path, file)
            samples_by_art.setdefault(art, []).append((rr, mic_folder, file, source_path))

        for art, items in samples_by_art.items():
            items.sort(key=lambda x: x[0])
            if art not in articulations:
                articulations[art] = {str(i): [] for i in range(1, 9)}
            articulations[art][str(slot)] = items

    if not articulations:
        print(f"No articulations found in {kick_folder}")
        continue

    for art in sorted(articulations.keys()):
        wavs_by_slot = {str(i): [] for i in range(1, 9)}

        data = {
            "schemaVersion": 1,
            "useVelocityToVolume": True,
            "instrumentType": "kick",
            "slotNames": slot_names,
            "velocityLayers": [
                {
                    "index": 1,
                    "lo": 1,
                    "hi": 127,
                    "wavsBySlot": wavs_by_slot,
                }
            ],
            "velToVol": {
                "amount": 100,
                "curveName": "soft",
            },
        }

        preset_name = f"{kick_folder}_{art}"
        preset_folder_path = os.path.join(presets_path, f"{preset_name}.preset")
        os.makedirs(preset_folder_path, exist_ok=True)
        for slot_key, items in articulations[art].items():
            for _, mic_folder, filename, source_path in items:
                dest_folder = os.path.join(preset_folder_path, mic_folder)
                os.makedirs(dest_folder, exist_ok=True)
                dest_path = os.path.join(dest_folder, filename)
                shutil.copy2(source_path, dest_path)
                rel_path = os.path.relpath(dest_path, preset_folder_path)
                wavs_by_slot[str(slot_key)].append(rel_path)
        json_path = os.path.join(preset_folder_path, "preset.json")
        with open(json_path, "w") as f:
            json.dump(data, f, indent=2)

        print(f"Created {json_path}")

print("Conversion complete!")
