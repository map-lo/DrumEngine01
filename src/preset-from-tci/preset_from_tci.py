#!/usr/bin/env python3
import json
import os
import sys

from tci_decoder import decode_tci, decompress_bitstream, write_wav


def main():
    if len(sys.argv) < 2:
        print("Usage: preset_from_tci.py <path-to-tci> [output-dir]")
        sys.exit(1)

    input_path = sys.argv[1]
    base_name = os.path.splitext(os.path.basename(input_path))[0]
    output_root = sys.argv[2] if len(sys.argv) > 2 else os.path.join("dist", "preset-from-tci")

    output_dir = os.path.join(output_root, base_name)
    wav_dir = os.path.join(output_dir, "wavs")
    os.makedirs(wav_dir, exist_ok=True)

    parsed = decode_tci(input_path)
    chunks = parsed["chunks"]
    mapping = parsed["mapping"]

    for index, chunk in enumerate(chunks, start=1):
        samples = decompress_bitstream(
            chunk["payload"],
            chunk["bit_len"],
            chunk["sample_count"],
        )

        wave_id = chunk.get("wave_id", index - 1)
        out_name = f"{base_name}_chunk{index}_wave{wave_id}.wav"
        out_path = os.path.join(wav_dir, out_name)
        write_wav(
            out_path,
            samples,
            sample_rate=chunk["sample_rate"],
            channels=chunk["channels"],
            sample_width=3,
        )

    mapping_path = os.path.join(output_dir, f"{base_name}_mapping.json")
    with open(mapping_path, "w", encoding="utf-8") as f:
        json.dump(mapping, f, indent=2)

    print(f"WAVs written to {wav_dir}")
    print(f"Mapping written to {mapping_path}")


if __name__ == "__main__":
    main()
