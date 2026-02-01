#!/usr/bin/env python3
import argparse
import json
import os
import re

from tci_decoder import decode_tci, decompress_bitstream, write_wav

SLOT_NAMES = ["top", "bottom", "oh", "room1", "room2", "extra1", "extra2", "extra3"]


def sanitize_name(value):
    name = (value or "articulation").strip()
    name = name.replace("/", "_").replace("\\", "_").replace(":", "_")
    return re.sub(r"\s+", " ", name)


def infer_instrument_type(name):
    lower = name.lower()
    if "snare" in lower:
        return "snare"
    if "kick" in lower:
        return "kick"
    if "tom" in lower:
        return "tom"
    if "hat" in lower:
        return "hihat"
    if "cymbal" in lower:
        return "cymbal"
    return "snare"


def build_velocity_ranges(velocities):
    ranges = []
    for idx, vel in enumerate(velocities):
        lo = max(1, int(vel))
        if idx < len(velocities) - 1:
            hi = max(lo, int(velocities[idx + 1]) - 1)
        else:
            hi = 127
        ranges.append((lo, hi))
    return ranges


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--outputRoot", default=os.path.join("presets", "Trigger2Library"))
    parser.add_argument("--presetDir")
    parser.add_argument("--sampleDir")
    parser.add_argument("--type")
    parser.add_argument("--fast", action="store_true")
    for i in range(1, 9):
        parser.add_argument(f"--mic{i}")
    args = parser.parse_args()

    mic_inputs = []
    for i in range(1, 9):
        path = getattr(args, f"mic{i}")
        if path:
            mic_inputs.append((i, path))

    if not mic_inputs:
        raise SystemExit("At least one mic input must be provided.")

    output_root = args.presetDir or args.outputRoot
    instrument_type = args.type

    mic_data = {}
    reference_mapping = None
    reference_name = None

    for mic_index, path in mic_inputs:
        parsed = decode_tci(path, fast=args.fast)
        base_name = os.path.splitext(os.path.basename(path))[0]
        mic_data[mic_index] = {
            "path": path,
            "base_name": base_name,
            "chunks": parsed["chunks"],
            "mapping": parsed["mapping"],
        }
        if reference_mapping is None:
            reference_mapping = parsed["mapping"]
            reference_name = base_name

    articulations = reference_mapping.get("articulations", [])
    if not articulations:
        articulations = [{"name": reference_name, "layers": []}]

    multiple_articulations = len(articulations) > 1

    shared_wav_root = None
    if multiple_articulations:
        shared_name = sanitize_name(reference_name)
        shared_wav_root = os.path.join(output_root, f"{shared_name}_WAVS")

    for art in articulations:
        art_name = sanitize_name(art.get("name") or reference_name)
        art_folder = art_name if multiple_articulations else ""

        preset_parent = os.path.join(output_root, art_folder) if art_folder else output_root
        os.makedirs(preset_parent, exist_ok=True)

        preset_name = art_name if multiple_articulations else reference_name
        preset_folder = os.path.join(preset_parent, f"{preset_name}.preset")
        os.makedirs(preset_folder, exist_ok=True)
        preset_path = os.path.join(preset_folder, "preset.json")

        velocity_layers = []
        velocities = [layer.get("velocity", 0) for layer in art.get("layers", [])]
        ranges = build_velocity_ranges(velocities)

        for layer_index, layer in enumerate(art.get("layers", [])):
            rr_waves = layer.get("waves", [])
            lo, hi = ranges[layer_index] if layer_index < len(ranges) else (1, 127)
            wavs_by_slot = {str(slot): [] for slot in range(1, 9)}

            for rr_index, wave_id in enumerate(rr_waves, start=1):
                if wave_id is None:
                    continue
                for mic_index, mic_info in mic_data.items():
                    chunks = mic_info["chunks"]
                    if wave_id >= len(chunks):
                        continue
                    chunk = chunks[wave_id]
                    samples = decompress_bitstream(
                        chunk["payload"],
                        chunk["bit_len"],
                        chunk["sample_count"],
                        channels=chunk["channels"],
                    )

                    mic_base = mic_info["base_name"]
                    wav_root = shared_wav_root or preset_folder
                    tci_folder = os.path.join(wav_root, mic_base)
                    if art_folder:
                        tci_folder = os.path.join(tci_folder, art_folder)
                    os.makedirs(tci_folder, exist_ok=True)

                    wav_name = f"{mic_base}_{art_name}_v{layer_index + 1}_rr{rr_index}.wav"
                    wav_path = os.path.join(tci_folder, wav_name)

                    write_wav(
                        wav_path,
                        samples,
                        sample_rate=chunk["sample_rate"],
                        channels=chunk["channels"],
                        sample_width=3,
                    )

                    rel_path = os.path.relpath(wav_path, preset_folder)
                    wavs_by_slot[str(mic_index)].append(rel_path)

            velocity_layers.append(
                {
                    "index": layer_index + 1,
                    "lo": lo,
                    "hi": hi,
                    "wavsBySlot": wavs_by_slot,
                }
            )

        resolved_type = instrument_type or infer_instrument_type(reference_name)
        preset = {
            "schemaVersion": 1,
            "instrumentType": resolved_type,
            "slotNames": SLOT_NAMES,
            "velocityLayers": velocity_layers,
            "velToVol": {
                "amount": 70,
                "curve": {"type": "builtin", "name": "soft"},
            },
        }

        with open(preset_path, "w", encoding="utf-8") as f:
            json.dump(preset, f, indent=2)

        print(f"Preset written to {preset_path}")


if __name__ == "__main__":
    main()
