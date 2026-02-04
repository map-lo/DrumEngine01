import os
import json
import re
import shutil
from collections import defaultdict


CIRCLES_ROOT = "/Users/marian/Downloads/Circles"
PRESETS_ROOT = "/Users/marian/Development/JUCE-Plugins/DrumEngine01/presets/Circles"
REPORT_PATH = "/Users/marian/Development/JUCE-Plugins/DrumEngine01/generators/circles_skipped_samples.txt"

SLOT_NAMES = ["main", "", "", "", "", "", "", ""]

VELOCITY_WORDS = {
    "SOFT": 1,
    "MED": 2,
    "MEDIUM": 2,
    "MID": 2,
    "HARD": 3
}

INSTRUMENT_OUTPUT_FOLDERS = {
    "kick": "Kick",
    "snare": "Snare",
    "tom": "Tom",
    "hihat": "HiHat",
    "crash": "Crash",
    "ride": "Ride",
    "cymbal": "Cymbal",
    "percussion": "Percussion"
}


def tokenize(value):
    return [token for token in re.split(r"[^A-Za-z0-9]+", value) if token]


def detect_velocity_from_tokens(tokens):
    for token in tokens:
        upper = token.upper()
        if upper in VELOCITY_WORDS:
            return ("word", VELOCITY_WORDS[upper])
    return None


def detect_velocity_from_path(path_parts):
    for part in reversed(path_parts):
        tokens = tokenize(part)
        velocity = detect_velocity_from_tokens(tokens)
        if velocity is not None:
            return velocity
    return None


def parse_filename(filename, allow_letter_rr=True):
    name_no_ext = os.path.splitext(filename)[0]
    tokens = tokenize(name_no_ext)

    remaining_tokens = []
    velocity = None
    rr = None

    for index, token in enumerate(tokens):
        upper = token.upper()
        v_match = re.match(r"^V(\d+)([A-Z])?$", upper)
        if v_match:
            velocity = ("num", int(v_match.group(1)))
            if allow_letter_rr and v_match.group(2):
                rr = v_match.group(2)
            continue

        if velocity is None and upper in VELOCITY_WORDS:
            velocity = ("word", VELOCITY_WORDS[upper])
            continue

        if allow_letter_rr and rr is None and re.fullmatch(r"[A-Z]", upper) and index == len(tokens) - 1:
            rr = upper
            continue

        if rr is None and re.fullmatch(r"RR\d+", upper):
            rr = upper
            continue

        remaining_tokens.append(token)

    base_name = " ".join(remaining_tokens).strip()
    return base_name, velocity, rr


def detect_instrument_type_from_tokens(tokens):
    token_set = {token.upper() for token in tokens}

    if {"HIHAT", "HIHATS", "HAT", "HATS"} & token_set:
        return "hihat"

    if {"CRASH", "CRASHES"} & token_set:
        return "crash"

    if {"RIDE", "RIDES"} & token_set:
        return "ride"

    if {"CYMBAL", "CYMBALS"} & token_set:
        return "cymbal"

    if {"TOM", "TOMS"} & token_set:
        return "tom"

    if {"SNARE", "SNARES"} & token_set:
        return "snare"

    if {"KICK", "KICKS"} & token_set:
        return "kick"

    if {"PERCUSSION", "PERC", "CONGA", "SHAKER", "TAMBO", "TAMBOURINE"} & token_set:
        return "percussion"

    return None


def detect_instrument_type(path_parts, extra_tokens=None):
    for part in reversed(path_parts):
        tokens = tokenize(part)
        instrument_type = detect_instrument_type_from_tokens(tokens)
        if instrument_type is not None:
            return instrument_type

    if extra_tokens:
        return detect_instrument_type_from_tokens(extra_tokens)

    return None


def build_velocity_ranges(layer_count):
    if layer_count <= 0:
        return []

    if layer_count == 1:
        return [(1, 127)]

    step = 127 // layer_count
    ranges = []
    start = 1
    for index in range(layer_count):
        end = 127 if index == layer_count - 1 else start + step - 1
        ranges.append((start, end))
        start = end + 1
    return ranges


def velocity_sort_key(velocity):
    if velocity is None:
        return (0, 0)
    kind, value = velocity
    return (1, value) if kind in ("num", "word") else (2, value)


def rr_sort_key(rr):
    if rr is None:
        return (0, "")
    if isinstance(rr, str) and rr.startswith("RR"):
        digits = re.sub(r"\D", "", rr)
        return (1, int(digits) if digits else 0)
    return (2, rr)


def ensure_folder(path):
    os.makedirs(path, exist_ok=True)


def copy_wav_to_folder(source_path, dest_folder, dest_filename):
    ensure_folder(dest_folder)
    dest_path = os.path.join(dest_folder, dest_filename)
    if not os.path.exists(dest_path):
        shutil.copy2(source_path, dest_path)
        return dest_path

    base, ext = os.path.splitext(dest_filename)
    counter = 2
    while True:
        candidate = os.path.join(dest_folder, f"{base}_{counter}{ext}")
        if not os.path.exists(candidate):
            shutil.copy2(source_path, candidate)
            return candidate
        counter += 1


def should_treat_letter_rr(path_parts):
    return "PERCUSSION" not in {part.upper() for part in path_parts}


def create_preset(preset_folder_path, instrument_type, velocity_layers):
    data = {
        "schemaVersion": 1,
        "instrumentType": instrument_type,
        "slotNames": SLOT_NAMES,
        "velocityLayers": velocity_layers,
        "velToVol": {
            "amount": 70,
            "curve": {
                "type": "builtin",
                "name": "soft"
            }
        }
    }

    ensure_folder(preset_folder_path)
    json_path = os.path.join(preset_folder_path, "preset.json")
    with open(json_path, "w") as file:
        json.dump(data, file, indent=2)


def should_use_shared_folder(presets):
    source_usage = defaultdict(set)
    for preset_name, samples_by_velocity in presets.items():
        for wavs_with_rr in samples_by_velocity.values():
            for _, wav_path in wavs_with_rr:
                source_usage[wav_path].add(preset_name)
    return any(len(presets_used) > 1 for presets_used in source_usage.values())


def main():
    ensure_folder(PRESETS_ROOT)

    skipped_samples = []
    created_presets = 0

    for root, _, files in os.walk(CIRCLES_ROOT):
        wavs = [file for file in files if file.lower().endswith(".wav")]
        if not wavs:
            continue

        rel_dir = os.path.relpath(root, CIRCLES_ROOT)
        path_parts = rel_dir.split(os.sep)
        allow_letter_rr = should_treat_letter_rr(path_parts)
        samples_by_preset = defaultdict(lambda: defaultdict(lambda: defaultdict(list)))

        for wav in wavs:
            filename_tokens = tokenize(os.path.splitext(wav)[0])
            instrument_type = detect_instrument_type(path_parts, extra_tokens=filename_tokens)
            if instrument_type is None:
                skipped_samples.append(f"Unknown instrument type: {os.path.join(rel_dir, wav)}")
                continue

            base_name, velocity, rr = parse_filename(wav, allow_letter_rr=allow_letter_rr)

            if velocity is None:
                velocity = detect_velocity_from_path(path_parts)

            if not base_name:
                base_name = os.path.basename(root)

            wav_path = os.path.join(root, wav)
            samples_by_preset[instrument_type][base_name][velocity].append((rr, wav_path))

        pack_name = path_parts[0] if path_parts else "Circles"
        for instrument_type, presets in sorted(samples_by_preset.items()):
            output_folder = INSTRUMENT_OUTPUT_FOLDERS.get(instrument_type, instrument_type.title())
            preset_base_folder = os.path.join(PRESETS_ROOT, pack_name, output_folder)
            ensure_folder(preset_base_folder)

            use_shared_folder = should_use_shared_folder(presets)
            shared_folder_path = os.path.join(preset_base_folder, f"{output_folder}_WAVS") if use_shared_folder else None

            for preset_name, samples_by_velocity in sorted(presets.items()):
                velocity_keys = sorted(samples_by_velocity.keys(), key=velocity_sort_key)
                velocity_ranges = build_velocity_ranges(len(velocity_keys))
                velocity_layers = []

                preset_folder_path = os.path.join(preset_base_folder, f"{preset_name}.preset")
                if use_shared_folder:
                    wavs_folder_path = shared_folder_path
                else:
                    wavs_folder_path = preset_folder_path
                ensure_folder(wavs_folder_path)

                for index, velocity_key in enumerate(velocity_keys):
                    wavs_with_rr = samples_by_velocity[velocity_key]
                    wavs_with_rr.sort(key=lambda item: rr_sort_key(item[0]))
                    wavs_rel = []
                    for _, wav_path in wavs_with_rr:
                        dest_path = copy_wav_to_folder(wav_path, wavs_folder_path, os.path.basename(wav_path))
                        rel_path = os.path.relpath(dest_path, preset_folder_path)
                        wavs_rel.append(rel_path.replace(os.sep, "/"))

                    lo, hi = velocity_ranges[index]
                    wavs_by_slot = {str(slot): [] for slot in range(1, 9)}
                    wavs_by_slot["1"] = wavs_rel

                    velocity_layers.append({
                        "index": index + 1,
                        "lo": lo,
                        "hi": hi,
                        "wavsBySlot": wavs_by_slot
                    })

                create_preset(preset_folder_path, instrument_type, velocity_layers)
                created_presets += 1

    print(f"Created presets: {created_presets}")
    print(f"Skipped samples: {len(skipped_samples)}")

    if skipped_samples:
        print("Skipped sample paths (relative to Circles root):")
        for sample in skipped_samples:
            print(sample)

        with open(REPORT_PATH, "w") as report:
            report.write("\n".join(skipped_samples))
        print(f"Skipped sample report written to: {REPORT_PATH}")


if __name__ == "__main__":
    main()