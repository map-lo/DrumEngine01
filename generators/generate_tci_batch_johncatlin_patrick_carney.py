#!/usr/bin/env python3
import argparse
import json
import os
import re
import sys

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
REPO_ROOT = os.path.abspath(os.path.join(SCRIPT_DIR, ".."))
TCI_DIR = os.path.join(REPO_ROOT, "src", "preset-from-tci")
if TCI_DIR not in sys.path:
    sys.path.insert(0, TCI_DIR)

from tci_decoder import decode_tci, decompress_bitstream, write_wav

ENDING_TO_SLOT = {
    "DIR": 1,
    "OH": 3,
    "mOH": 4,
    "mRoom": 5,
    "FX": 6,
}

SLOT_NAMES = ["", "", "", "", "", "", "", ""]
for ending, slot in ENDING_TO_SLOT.items():
    SLOT_NAMES[slot - 1] = ending.lower()


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


def split_base_and_ending(filename, endings):
    base = os.path.splitext(filename)[0]
    ending_map = {e.lower(): e for e in endings}
    ending_pattern = "|".join(re.escape(e) for e in endings)
    match = re.match(rf"(.+?)[ _-]({ending_pattern})$", base, flags=re.IGNORECASE)
    if match:
        name = match.group(1).strip()
        ending_raw = match.group(2)
        ending = ending_map.get(ending_raw.lower(), ending_raw)
        return name, ending
    return base, None


def collect_tci_files(root, endings):
    groups = {}
    for dirpath, _, filenames in os.walk(root):
        for filename in filenames:
            if not filename.lower().endswith(".tci"):
                continue
            base_name, ending = split_base_and_ending(filename, endings)
            if ending is None:
                continue
            rel_dir = os.path.relpath(dirpath, root)
            key = (rel_dir, base_name)
            groups.setdefault(key, {}).setdefault(ending, []).append(
                os.path.join(dirpath, filename)
            )
    return groups


def has_existing_presets(preset_root):
    if not os.path.isdir(preset_root):
        return False
    for dirpath, _, filenames in os.walk(preset_root):
        if "preset.json" in filenames and dirpath.endswith(".preset"):
            return True
    return False


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--inputRoot",
        default="/Users/marian/Downloads/johncatlin_patrick-carney_2026-02-04_1007",
    )
    parser.add_argument("--outputRoot", default=os.path.join(REPO_ROOT, "presets", "PatrickCarney"))
    parser.add_argument("--type")
    parser.add_argument("--fast", action="store_true")
    parser.add_argument("--bitDepth", type=int, choices=[16, 24], default=24)
    parser.add_argument("--resume", action="store_true")
    args = parser.parse_args()

    input_root = args.inputRoot
    output_root = args.outputRoot
    instrument_type = args.type
    sample_width = 2 if args.bitDepth == 16 else 3
    resume = args.resume

    print(f"Input root: {input_root}")
    print(f"Output root: {output_root}")
    groups = collect_tci_files(input_root, ENDING_TO_SLOT.keys())
    if not groups:
        raise SystemExit("No .tci files found.")

    total_groups = len(groups)
    print(f"Found {total_groups} preset groups.")

    processed_groups = 0
    for (rel_dir, base_name), ending_map in sorted(groups.items()):
        processed_groups += 1
        print(f"[{processed_groups}/{total_groups}] Processing {rel_dir}/{base_name}")

        preset_root = os.path.join(output_root, rel_dir) if rel_dir != "." else output_root
        if resume and has_existing_presets(preset_root):
            print(f"[resume] skip group with existing presets {preset_root}")
            continue

        slot_sources = {}
        for ending, slot_index in ENDING_TO_SLOT.items():
            paths = ending_map.get(ending, [])
            if paths:
                slot_sources[slot_index] = sorted(paths)[0]

        if not slot_sources:
            continue

        tci_data_by_slot = {}
        reference_mapping = None
        reference_name = None

        decode_failed = False
        for slot_index, tci_path in slot_sources.items():
            try:
                parsed = decode_tci(tci_path, fast=args.fast)
            except ValueError as exc:
                print(f"[skip] Unsupported TCI: {tci_path} ({exc})")
                decode_failed = True
                break
            tci_data_by_slot[slot_index] = {
                "path": tci_path,
                "base_name": os.path.splitext(os.path.basename(tci_path))[0],
                "chunks": parsed["chunks"],
                "mapping": parsed["mapping"],
            }
            if reference_mapping is None:
                reference_mapping = parsed["mapping"]
                reference_name = os.path.splitext(os.path.basename(tci_path))[0]

        if decode_failed:
            continue

        articulations = reference_mapping.get("articulations", []) if reference_mapping else []
        if not articulations:
            articulations = [{"name": reference_name or base_name, "layers": []}]

            multiple_articulations = len(articulations) > 1
            os.makedirs(preset_root, exist_ok=True)

        for art in articulations:
            art_name = sanitize_name(art.get("name") or base_name)
            art_folder = art_name if multiple_articulations else ""

            preset_name = art_name if multiple_articulations else (reference_name or base_name)
            if art_folder and preset_name == art_folder:
                art_folder = ""

            preset_parent = os.path.join(preset_root, art_folder) if art_folder else preset_root
            os.makedirs(preset_parent, exist_ok=True)
            preset_folder = os.path.join(preset_parent, f"{preset_name}.preset")
            os.makedirs(preset_folder, exist_ok=True)
            preset_path = os.path.join(preset_folder, "preset.json")

            if resume and os.path.exists(preset_path):
                print(f"[resume] skip existing preset {preset_path}")
                continue

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
                    for slot_index, tci_data in tci_data_by_slot.items():
                        if wave_id >= len(tci_data["chunks"]):
                            continue
                        chunk = tci_data["chunks"][wave_id]
                        samples = decompress_bitstream(
                            chunk["payload"],
                            chunk["bit_len"],
                            chunk["sample_count"],
                            channels=chunk["channels"],
                        )

                        mic_base = tci_data["base_name"]
                        tci_folder = os.path.join(preset_folder, mic_base)
                        os.makedirs(tci_folder, exist_ok=True)

                        wav_name = f"{mic_base}_{art_name}_v{layer_index + 1}_rr{rr_index}.wav"
                        wav_path = os.path.join(tci_folder, wav_name)

                        write_wav(
                            wav_path,
                            samples,
                            sample_rate=chunk["sample_rate"],
                            channels=chunk["channels"],
                            sample_width=sample_width,
                        )

                        rel_path = os.path.relpath(wav_path, preset_folder)
                        wavs_by_slot[str(slot_index)].append(rel_path)

                velocity_layers.append(
                    {
                        "index": layer_index + 1,
                        "lo": lo,
                        "hi": hi,
                        "wavsBySlot": wavs_by_slot,
                    }
                )

            resolved_type = instrument_type or infer_instrument_type(reference_name or base_name)
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
