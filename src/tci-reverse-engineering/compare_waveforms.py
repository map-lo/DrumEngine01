#!/usr/bin/env python3
import glob
import os
import wave
import struct

SOURCE_DIR = "/Users/marian/Downloads/SPINLIGHT SAMPLES/WAV Files/VIntage 70's Acrolite (Tight)/Close Mic"
DECODED_DIR = "/Users/marian/Development/JUCE-Plugins/DrumEngine01/src/tci-reverse-engineering/output"
DECODED_PATTERN = "Vintage 70's Acrolite (Tight) - Close Mic_chunk*_wave5_v3.wav"


def read_wav_int24(path):
    with wave.open(path, 'rb') as w:
        frames = w.getnframes()
        channels = w.getnchannels()
        sampwidth = w.getsampwidth()
        data = w.readframes(frames)
        if sampwidth != 3:
            raise ValueError(f"Expected 24-bit WAV: {path}")
        samples = []
        for i in range(0, len(data), 3):
            b = data[i:i+3]
            samples.append(int.from_bytes(b, byteorder='little', signed=True))
        return samples, channels


def norm_samples(samples):
    scale = float(1 << 23)
    return [s / scale for s in samples]


def rms(x):
    return (sum(v * v for v in x) / len(x)) ** 0.5 if x else 0.0


def corr(a, b):
    if len(a) != len(b) or not a:
        return 0.0
    mean_a = sum(a) / len(a)
    mean_b = sum(b) / len(b)
    num = sum((x - mean_a) * (y - mean_b) for x, y in zip(a, b))
    den_a = sum((x - mean_a) ** 2 for x in a) ** 0.5
    den_b = sum((y - mean_b) ** 2 for y in b) ** 0.5
    if den_a == 0 or den_b == 0:
        return 0.0
    return num / (den_a * den_b)


def main():
    source_paths = sorted(glob.glob(os.path.join(SOURCE_DIR, "*.wav")))
    decoded_paths = sorted(glob.glob(os.path.join(DECODED_DIR, DECODED_PATTERN)))

    if not source_paths or not decoded_paths:
        print("Missing source or decoded WAVs")
        return

    source_count = len(source_paths)
    decoded_count = len(decoded_paths)
    print(f"Source WAVs: {source_count}")
    print(f"Decoded WAVs: {decoded_count}")
    print()

    pair_count = min(source_count, decoded_count)
    src_data = []
    dec_data = []

    for p in source_paths:
        samples, channels = read_wav_int24(p)
        src_data.append((p, norm_samples(samples), channels))

    for p in decoded_paths:
        samples, channels = read_wav_int24(p)
        dec_data.append((p, norm_samples(samples), channels))

    candidates = []
    for i, (src_path, src_samples, src_ch) in enumerate(src_data):
        for j, (dec_path, dec_samples, dec_ch) in enumerate(dec_data):
            if src_ch != dec_ch:
                continue
            length = min(len(src_samples), len(dec_samples))
            if length == 0:
                continue
            s = src_samples[:length]
            d = dec_samples[:length]
            r = corr(s, d)
            candidates.append((abs(r), r, i, j, length))

    candidates.sort(reverse=True, key=lambda x: x[0])
    used_src = set()
    used_dec = set()
    matches = []

    for abs_r, r, i, j, length in candidates:
        if i in used_src or j in used_dec:
            continue
        used_src.add(i)
        used_dec.add(j)
        matches.append((r, i, j, length))
        if len(matches) >= pair_count:
            break

    total_corr = 0.0
    total_rms_err = 0.0

    for r, i, j, length in matches:
        src_path, src_samples, _ = src_data[i]
        dec_path, dec_samples, _ = dec_data[j]
        s = src_samples[:length]
        d = dec_samples[:length]
        if r < 0:
            d = [-x for x in d]
            r = -r
        error = [a - b for a, b in zip(s, d)]
        e = rms(error)
        total_corr += r
        total_rms_err += e
        print(
            f"{os.path.basename(src_path)} vs {os.path.basename(dec_path)}: "
            f"corr={r:.6f} rms_err={e:.6f}"
        )

    avg_corr = total_corr / len(matches) if matches else 0.0
    avg_rms = total_rms_err / len(matches) if matches else 0.0
    print()
    print(f"Matched pairs: {len(matches)}")
    print(f"Average corr: {avg_corr:.6f}")
    print(f"Average RMS error: {avg_rms:.6f}")


if __name__ == "__main__":
    main()
