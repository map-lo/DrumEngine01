#!/usr/bin/env python3
import argparse
import csv
import json
import os
import re
import threading
import time
from concurrent.futures import ThreadPoolExecutor

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
    wav_root,
    rel_base,
    folder_suffix,
    sample_width,
    resume,
    lock=None,
    in_progress=None,
):
    base_name = tci_data["base_name"]
    tci_folder = os.path.join(wav_root, f"{base_name}{folder_suffix}")
    os.makedirs(tci_folder, exist_ok=True)

    art_label = sanitize_name(art_name)
    wav_name = f"{base_name}_{art_label}_v{layer_index + 1}_rr{rr_index}.wav"
    wav_path = os.path.join(tci_folder, wav_name)

    if wav_path not in cache:
        if resume and os.path.exists(wav_path):
            cache[wav_path] = True
            return os.path.relpath(wav_path, rel_base), wav_path

        if lock is not None and in_progress is not None:
            wait_for_other = False
            with lock:
                if wav_path in cache:
                    return os.path.relpath(wav_path, rel_base), wav_path
                if wav_path in in_progress:
                    wait_for_other = True
                else:
                    in_progress.add(wav_path)
            if wait_for_other:
                while not os.path.exists(wav_path):
                    time.sleep(0.01)
                with lock:
                    cache[wav_path] = True
                    in_progress.discard(wav_path)
                return os.path.relpath(wav_path, rel_base), wav_path

        chunk = tci_data["chunks"][wave_id]
        samples = decompress_bitstream(
            chunk["payload"],
            chunk["bit_len"],
            chunk["sample_count"],
            channels=chunk["channels"],
        )
        tmp_path = f"{wav_path}.tmp"
        os.makedirs(os.path.dirname(tmp_path), exist_ok=True)
        try:
            write_wav(
                tmp_path,
                samples,
                sample_rate=chunk["sample_rate"],
                channels=chunk["channels"],
                sample_width=sample_width,
            )
            os.replace(tmp_path, wav_path)
        finally:
            if lock is not None and in_progress is not None:
                with lock:
                    cache[wav_path] = True
                    in_progress.discard(wav_path)
            else:
                cache[wav_path] = True

    return os.path.relpath(wav_path, rel_base), wav_path


def build_slot_names(assignments):
    slot_names = ["" for _ in range(8)]
    for slot_index, ending in assignments.items():
        slot_names[slot_index - 1] = ending.lower()
    return slot_names


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--inputRoot", required=True)
    parser.add_argument("--outputRoot", default=os.path.join("presets", "Trigger2Library"))
    parser.add_argument("--limit", type=int, default=0)
    parser.add_argument("--bitDepth", type=int, choices=[16, 24], default=24)
    parser.add_argument("--resume", action="store_true")
    parser.add_argument("--debugOffsets", action="store_true")
    parser.add_argument("--verbose", action="store_true")
    parser.add_argument("--fast", action="store_true")
    parser.add_argument("--threads", type=int, default=1)
    parser.add_argument("--diagnoseUnsupported", action="store_true")
    parser.add_argument(
        "--onlyPaths",
        action="append",
        default=[],
        help="Restrict processing to specific .tci paths or basenames. Can be repeated or comma-separated.",
    )
    args = parser.parse_args()

    input_root = args.inputRoot
    output_root = args.outputRoot
    output_preset_root = output_root
    groups = collect_tci_files(input_root)
    if not groups:
        raise SystemExit("No .tci files found.")

    only_paths = set()
    only_basenames = set()
    for entry in args.onlyPaths:
        for raw in entry.split(","):
            item = raw.strip()
            if not item:
                continue
            expanded = os.path.abspath(os.path.expanduser(item))
            if os.path.exists(expanded):
                only_paths.add(expanded)
                only_basenames.add(os.path.basename(expanded))
            else:
                only_basenames.add(os.path.basename(item))

    def is_allowed(path):
        if not only_paths and not only_basenames:
            return True
        abs_path = os.path.abspath(path)
        if abs_path in only_paths:
            return True
        return os.path.basename(path) in only_basenames

    if only_paths or only_basenames:
        filtered = {}
        for key, ending_map in groups.items():
            keep = False
            for paths in ending_map.values():
                for tci_path in paths:
                    if is_allowed(tci_path):
                        keep = True
                        break
                if keep:
                    break
            if keep:
                filtered[key] = ending_map
        groups = filtered
        if not groups:
            raise SystemExit("No matching .tci files found for --onlyPaths.")

    total_groups = len(groups)
    processed_presets = 0
    processed_groups = 0
    limit = max(0, args.limit or 0)
    sample_width = 2 if args.bitDepth == 16 else 3
    resume = args.resume
    unsupported_rows = []

    lock = threading.Lock() if args.threads > 1 else None
    in_progress = set() if args.threads > 1 else None
    executor = (
        ThreadPoolExecutor(max_workers=max(1, args.threads)) if args.threads > 1 else None
    )

    try:
        for (rel_dir, base_name), ending_map in groups.items():
            processed_groups += 1
            if args.verbose:
                print(f"[{processed_groups}/{total_groups}] scan {rel_dir}/{base_name}")

            primary_choices = []
            for ending in ENDINGS_PRIMARY:
                paths = ending_map.get(ending, [])
                if paths and is_allowed(paths[0]):
                    primary_choices.append((ending, paths[0]))

            if not primary_choices:
                print(
                    f"[{processed_groups}/{total_groups}] skip preset: no primary TCI sources for {rel_dir}/{base_name}"
                )
                continue

            oh_files = ending_map.get(ENDING_OH, [])

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
            for primary_ending, primary_path in primary_choices:
                for ssdr_choice in ssdr_variants:
                    for nrg_choice in nrg_variants:
                        suffix_parts = []
                        if len(primary_choices) > 1:
                            suffix_parts.append(primary_ending)
                        if len(ssdr_variants) > 1 and ssdr_choice is not None:
                            suffix_parts.append("SSDR" if ssdr_choice == ENDING_SSDR else "SSDR(a)")
                        if len(nrg_variants) > 1 and nrg_choice is not None:
                            suffix_parts.append("NRG" if nrg_choice == ENDING_NRG else "NRG(c)")
                        preset_variants.append(
                            (primary_ending, primary_path, ssdr_choice, nrg_choice, suffix_parts)
                        )

            multi_preset = len(preset_variants) > 1

            for primary_ending, primary_path, ssdr_choice, nrg_choice, suffix_parts in preset_variants:
                variant_assigned = {1: primary_ending}
                variant_sources = {1: primary_path}

                if oh_files and is_allowed(oh_files[0]):
                    variant_sources[3] = oh_files[0]
                    variant_assigned[3] = ENDING_OH

                if ssdr_choice:
                    ssdr_file = ssdr_primary if len(ssdr_variants) > 1 else ssdr_paths.get(ssdr_choice)
                    if ssdr_file and is_allowed(ssdr_file):
                        variant_sources[4] = ssdr_file
                        variant_assigned[4] = ssdr_choice

                if nrg_choice:
                    nrg_file = nrg_primary if len(nrg_variants) > 1 else nrg_paths.get(nrg_choice)
                    if nrg_file and is_allowed(nrg_file):
                        variant_sources[5] = nrg_file
                        variant_assigned[5] = nrg_choice

                if not variant_sources:
                    continue

                tci_cache = {}
                wav_cache = {}
                reference_mapping = None
                reference_name = None
                valid_sources = {}
                valid_assigned = {}
                skipped_sources = []

                for slot_index, tci_path in variant_sources.items():
                    if tci_path in tci_cache:
                        valid_sources[slot_index] = tci_path
                        valid_assigned[slot_index] = variant_assigned.get(slot_index)
                        continue
                    try:
                        if args.verbose:
                            print(f"[{processed_groups}/{total_groups}] decode {tci_path}")
                        parsed = decode_tci(
                            tci_path,
                            debug=args.debugOffsets,
                            fast=args.fast,
                            diagnose=args.diagnoseUnsupported,
                        )
                    except ValueError as exc:
                        skipped_sources.append((slot_index, tci_path, str(exc)))
                        if args.diagnoseUnsupported:
                            from tci_decoder import diagnose_tci

                            diag = diagnose_tci(tci_path)
                            unsupported_rows.append(
                                {
                                    "path": tci_path,
                                    "size": diag.get("size"),
                                    "tlv_start": diag.get("tlv_start"),
                                    "zlib_xml": diag.get("zlib_xml"),
                                    "zlib_hits": ";".join(str(x) for x in diag.get("zlib_hits", [])[:8]),
                                    "gzip_hits": ";".join(str(x) for x in diag.get("gzip_hits", [])[:8]),
                                    "hdr": json.dumps(diag.get("hdr", {}), sort_keys=True),
                                }
                            )
                        continue
                    tci_cache[tci_path] = {
                        "base_name": os.path.splitext(os.path.basename(tci_path))[0],
                        "chunks": parsed["chunks"],
                        "mapping": parsed["mapping"],
                    }
                    if args.debugOffsets and parsed["mapping"].get("debug_chunks"):
                        print(f"[debug] {tci_path}")
                        for info in parsed["mapping"]["debug_chunks"]:
                            print(
                                "  wave {wave_id}: start={start} shift={shift} header_off={hoff} u_var9={uvar}".format(
                                    wave_id=info["wave_id"],
                                    start=info["start_byte"],
                                    shift=info["bit_shift"],
                                    hoff=info.get("header_byte_offset"),
                                    uvar=info.get("u_var9"),
                                )
                            )
                    valid_sources[slot_index] = tci_path
                    valid_assigned[slot_index] = variant_assigned.get(slot_index)
                    if reference_mapping is None:
                        reference_mapping = parsed["mapping"]
                        reference_name = os.path.splitext(os.path.basename(tci_path))[0]

                if skipped_sources:
                    for slot_index, tci_path, err in skipped_sources:
                        print(
                            f"[{processed_groups}/{total_groups}] skip unsupported: {tci_path} (slot {slot_index}) - {err}"
                        )

                if not valid_sources:
                    print(
                        f"[{processed_groups}/{total_groups}] skip preset: no valid TCI sources for {rel_dir}/{base_name}"
                    )
                    continue

                variant_sources = valid_sources
                variant_assigned = valid_assigned

                articulations = reference_mapping.get("articulations", []) if reference_mapping else []
                if not articulations:
                    articulations = [{"name": base_name, "layers": []}]

                full_articulations = [
                    art for art in articulations
                    if "full" in (art.get("name") or "").strip().lower()
                ]
                full_only = bool(full_articulations)
                if full_only:
                    articulations = full_articulations

                multiple_articulations = len(articulations) > 1

                suffix = ""
                if suffix_parts:
                    suffix = "_" + "_".join(suffix_parts)

                for art in articulations:
                    art_name = sanitize_name(art.get("name") or base_name)
                    is_full = "full" in art_name.lower()
                    art_name_display = "" if full_only and is_full else art_name
                    folder_suffix = (
                        f" {art_name_display}" if multiple_articulations and art_name_display else ""
                    )

                    preset_dir = os.path.join(output_preset_root, rel_dir)
                    os.makedirs(preset_dir, exist_ok=True)

                    preset_name = (
                        f"{base_name}{folder_suffix}{suffix}"
                        if multiple_articulations and art_name_display
                        else base_name + suffix
                    )
                    preset_folder = os.path.join(preset_dir, f"{preset_name}.preset")
                    os.makedirs(preset_folder, exist_ok=True)
                    preset_path = os.path.join(preset_folder, "preset.json")

                    if args.verbose:
                        print(
                            f"[{processed_groups}/{total_groups}] decoding {preset_path}"
                        )

                    velocity_layers = []
                    all_wavs_written = True
                    velocities = [layer.get("velocity", 0) for layer in art.get("layers", [])]
                    ranges = build_velocity_ranges(velocities)

                    shared_wav_root = None
                    if multi_preset:
                        shared_wav_root = os.path.join(preset_dir, f"{base_name}_WAVS")

                    for layer_index, layer in enumerate(art.get("layers", [])):
                        rr_waves = layer.get("waves", [])
                        lo, hi = ranges[layer_index] if layer_index < len(ranges) else (1, 127)
                        wavs_by_slot = {str(slot): [] for slot in range(1, 9)}

                        tasks = []
                        for rr_index, wave_id in enumerate(rr_waves, start=1):
                            if wave_id is None:
                                continue
                            for slot_index, tci_path in variant_sources.items():
                                tci_data = tci_cache[tci_path]
                                if wave_id >= len(tci_data["chunks"]):
                                    continue
                                tasks.append(
                                    (rr_index, wave_id, slot_index, tci_path, tci_data)
                                )

                        def run_task(task):
                            rr_index, wave_id, slot_index, tci_path, tci_data = task
                            rel_path, wav_path = ensure_wav_written(
                                wav_cache,
                                tci_path,
                                tci_data,
                                art_name,
                                layer_index,
                                rr_index,
                                wave_id,
                                shared_wav_root or preset_folder,
                                preset_folder,
                                folder_suffix,
                                sample_width,
                                resume,
                                lock=lock,
                                in_progress=in_progress,
                            )
                            return slot_index, rel_path, wav_path

                        if executor and tasks:
                            results = executor.map(run_task, tasks)
                            for slot_index, rel_path, wav_path in results:
                                if not os.path.exists(wav_path):
                                    all_wavs_written = False
                                wavs_by_slot[str(slot_index)].append(rel_path)
                        else:
                            for task in tasks:
                                slot_index, rel_path, wav_path = run_task(task)
                                if not os.path.exists(wav_path):
                                    all_wavs_written = False
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
                        "velocityLayers": velocity_layers,
                        "velToVol": {
                            "amount": 70,
                            "curve": {"type": "builtin", "name": "soft"},
                        },
                    }

                    if resume and os.path.exists(preset_path) and all_wavs_written:
                        print(f"[{processed_groups}/{total_groups}] resume preset: {preset_path}")
                    else:
                        tmp_preset_path = f"{preset_path}.tmp"
                        os.makedirs(os.path.dirname(tmp_preset_path), exist_ok=True)
                        with open(tmp_preset_path, "w", encoding="utf-8") as f:
                            json.dump(preset, f, indent=2)
                        os.replace(tmp_preset_path, preset_path)

                    processed_presets += 1
                    print(
                        f"[{processed_groups}/{total_groups}] preset {processed_presets}: {preset_path}"
                    )
                    if limit and processed_presets >= limit:
                        print(f"Limit reached ({limit}). Stopping.")
                        return
    finally:
        if executor:
            executor.shutdown()

    if args.diagnoseUnsupported and unsupported_rows:
        report_path = os.path.join(output_root, "unsupported_tci_report.csv")
        os.makedirs(output_root, exist_ok=True)
        fieldnames = [
            "path",
            "size",
            "tlv_start",
            "zlib_xml",
            "zlib_hits",
            "gzip_hits",
            "hdr",
        ]
        with open(report_path, "w", newline="") as handle:
            writer = csv.DictWriter(handle, fieldnames=fieldnames)
            writer.writeheader()
            for row in unsupported_rows:
                writer.writerow(row)
        print(f"Wrote unsupported TCI report: {report_path}")


if __name__ == "__main__":
    main()
