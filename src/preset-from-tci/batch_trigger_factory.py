#!/usr/bin/env python3
import argparse
import json
import os
import re

from tci_decoder import decode_tci, decompress_bitstream, write_wav

ENDINGS_PRIMARY = ["DIR", "Z1", "Z2", "Z3"]
ENDING_OH = "OH"
ENDING_SSDR = "SSDR"
ENDING_SSDRA = "SSDRa"
ENDING_NRG = "NRG"
ENDING_NRGc = "NRGc"

SLOT_ORDER_PRIMARY = [1, 2, 6, 7, 8]  # mic1, mic2, extra1, extra2, extra3


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


def split_base_and_ending(filename):
    base = os.path.splitext(filename)[0]
    if " " in base:
        name, ending = base.rsplit(" ", 1)
        return name, ending
    return base, None


def collect_tci_files(root):
    groups = {}
    for dirpath, _, filenames in os.walk(root):
        for filename in filenames:
            if not filename.lower().endswith(".tci"):
                continue
            base_name, ending = split_base_and_ending(filename)
            if ending is None:
                continue
            rel_dir = os.path.relpath(dirpath, root)
            key = (rel_dir, base_name)
            groups.setdefault(key, {}).setdefault(ending, []).append(
                os.path.join(dirpath, filename)
            )
    return groups


def ensure_wav_written(
    cache,
    tci_path,
    tci_data,
    art_name,
    layer_index,
    rr_index,
    wave_id,
    output_sample_root,
    rel_dir,
    folder_suffix,
):
    base_name = tci_data["base_name"]
    tci_folder = os.path.join(output_sample_root, rel_dir, f"{base_name}{folder_suffix}")
    os.makedirs(tci_folder, exist_ok=True)

    art_label = sanitize_name(art_name)
    wav_name = f"{base_name}_{art_label}_v{layer_index + 1}_rr{rr_index}.wav"
    wav_path = os.path.join(tci_folder, wav_name)

    if wav_path not in cache:
        chunk = tci_data["chunks"][wave_id]
        samples = decompress_bitstream(
            chunk["payload"],
            chunk["bit_len"],
            chunk["sample_count"],
        )
        if not os.path.exists(wav_path):
            write_wav(
                wav_path,
                samples,
                sample_rate=chunk["sample_rate"],
                channels=chunk["channels"],
                sample_width=3,
            )
        cache[wav_path] = True

    return os.path.relpath(wav_path, output_sample_root)


def build_slot_names(assignments):
    slot_names = ["" for _ in range(8)]
    for slot_index, ending in assignments.items():
        slot_names[slot_index - 1] = ending.lower()
    return slot_names


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--inputRoot", required=True)
    parser.add_argument("--outputRoot", default=os.path.join("dist", "preset-from-tci"))
    args = parser.parse_args()

    input_root = args.inputRoot
    output_root = args.outputRoot
    output_preset_root = os.path.join(output_root, "presets", "Trigger2Library")
    output_sample_root = os.path.join(output_root, "samples", "Trigger2Library")
    groups = collect_tci_files(input_root)
    if not groups:
        raise SystemExit("No .tci files found.")

    total_groups = len(groups)
    processed_presets = 0
    processed_groups = 0

    for (rel_dir, base_name), ending_map in groups.items():
        processed_groups += 1
        primary_files = []
        for ending in ENDINGS_PRIMARY:
            primary_files.extend(ending_map.get(ending, []))

        assigned = {}
        mic_sources = {}

        for slot_index, tci_path in zip(SLOT_ORDER_PRIMARY, primary_files):
            _, ending = split_base_and_ending(os.path.basename(tci_path))
            assigned[slot_index] = ending
            mic_sources[slot_index] = tci_path

        oh_files = ending_map.get(ENDING_OH, [])
        if oh_files:
            mic_sources[3] = oh_files[0]
            assigned[3] = ENDING_OH

        ssdr_variants = []
        ssdr_paths = {}
        if ending_map.get(ENDING_SSDR):
            ssdr_variants.append(ENDING_SSDR)
            ssdr_paths[ENDING_SSDR] = ending_map[ENDING_SSDR][0]
        if ending_map.get(ENDING_SSDRA):
            ssdr_variants.append(ENDING_SSDRA)
            ssdr_paths[ENDING_SSDRA] = ending_map[ENDING_SSDRA][0]
        if not ssdr_variants:
            ssdr_variants = [None]

        nrg_variants = []
        nrg_paths = {}
        if ending_map.get(ENDING_NRG):
            nrg_variants.append(ENDING_NRG)
            nrg_paths[ENDING_NRG] = ending_map[ENDING_NRG][0]
        if ending_map.get(ENDING_NRGc):
            nrg_variants.append(ENDING_NRGc)
            nrg_paths[ENDING_NRGc] = ending_map[ENDING_NRGc][0]
        if not nrg_variants:
            nrg_variants = [None]

        ssdr_primary = ssdr_paths.get(ENDING_SSDR) or ssdr_paths.get(ENDING_SSDRA)
        nrg_primary = nrg_paths.get(ENDING_NRG) or nrg_paths.get(ENDING_NRGc)

        preset_variants = []
        for ssdr_choice in ssdr_variants:
            for nrg_choice in nrg_variants:
                suffix_parts = []
                if len(ssdr_variants) > 1 and ssdr_choice is not None:
                    suffix_parts.append("SSDR" if ssdr_choice == ENDING_SSDR else "SSDR(a)")
                if len(nrg_variants) > 1 and nrg_choice is not None:
                    suffix_parts.append("NRG" if nrg_choice == ENDING_NRG else "NRG(c)")
                preset_variants.append((ssdr_choice, nrg_choice, suffix_parts))

        for ssdr_choice, nrg_choice, suffix_parts in preset_variants:
            variant_assigned = dict(assigned)
            variant_sources = dict(mic_sources)

            if ssdr_choice:
                ssdr_file = ssdr_primary if len(ssdr_variants) > 1 else ssdr_paths.get(ssdr_choice)
                if ssdr_file:
                    variant_sources[4] = ssdr_file
                    variant_assigned[4] = ssdr_choice

            if nrg_choice:
                nrg_file = nrg_primary if len(nrg_variants) > 1 else nrg_paths.get(nrg_choice)
                if nrg_file:
                    variant_sources[5] = nrg_file
                    variant_assigned[5] = nrg_choice

            if not variant_sources:
                continue

            tci_cache = {}
            wav_cache = {}
            reference_mapping = None
            reference_name = None

            for slot_index, tci_path in variant_sources.items():
                if tci_path in tci_cache:
                    continue
                parsed = decode_tci(tci_path)
                tci_cache[tci_path] = {
                    "base_name": os.path.splitext(os.path.basename(tci_path))[0],
                    "chunks": parsed["chunks"],
                    "mapping": parsed["mapping"],
                }
                if reference_mapping is None:
                    reference_mapping = parsed["mapping"]
                    reference_name = os.path.splitext(os.path.basename(tci_path))[0]

            articulations = reference_mapping.get("articulations", []) if reference_mapping else []
            if not articulations:
                articulations = [{"name": base_name, "layers": []}]

            multiple_articulations = len(articulations) > 1

            suffix = ""
            if suffix_parts:
                suffix = "_" + "_".join(suffix_parts)

            for art in articulations:
                art_name = sanitize_name(art.get("name") or base_name)
                folder_suffix = f" {art_name}" if multiple_articulations else ""

                preset_dir = os.path.join(output_preset_root, rel_dir)
                os.makedirs(preset_dir, exist_ok=True)

                preset_name = f"{base_name}{folder_suffix}{suffix}" if multiple_articulations else base_name + suffix
                preset_path = os.path.join(preset_dir, f"{preset_name}.json")

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
                        for slot_index, tci_path in variant_sources.items():
                            tci_data = tci_cache[tci_path]
                            if wave_id >= len(tci_data["chunks"]):
                                continue
                            rel_path = ensure_wav_written(
                                wav_cache,
                                tci_path,
                                tci_data,
                                art_name,
                                layer_index,
                                rr_index,
                                wave_id,
                                output_sample_root,
                                rel_dir,
                                folder_suffix,
                            )
                            wavs_by_slot[str(slot_index)].append(rel_path)

                    velocity_layers.append(
                        {
                            "index": layer_index + 1,
                            "lo": lo,
                            "hi": hi,
                            "wavsBySlot": wavs_by_slot,
                        }
                    )

                resolved_type = infer_instrument_type(base_name)
                preset = {
                    "schemaVersion": 1,
                    "instrumentType": resolved_type,
                    "slotNames": build_slot_names(variant_assigned),
                    "rootFolder": output_sample_root,
                    "velocityLayers": velocity_layers,
                    "velToVol": {
                        "amount": 70,
                        "curve": {"type": "builtin", "name": "soft"},
                    },
                }

                with open(preset_path, "w", encoding="utf-8") as f:
                    json.dump(preset, f, indent=2)

                processed_presets += 1
                print(
                    f"[{processed_groups}/{total_groups}] preset {processed_presets}: {preset_path}"
                )


if __name__ == "__main__":
    main()
