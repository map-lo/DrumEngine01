#!/usr/bin/env python3
import glob
import os
import wave

def wav_info(path):
    with wave.open(path, 'rb') as w:
        return {
            "path": path,
            "frames": w.getnframes(),
            "channels": w.getnchannels(),
            "rate": w.getframerate(),
            "sampwidth": w.getsampwidth(),
        }


def main():
    source_dir = "/Users/marian/Downloads/SPINLIGHT SAMPLES/WAV Files/VIntage 70's Acrolite (Tight)/Close Mic"
    decoded_dir = "/Users/marian/Development/JUCE-Plugins/DrumEngine01/src/tci-reverse-engineering/output"

    source_paths = sorted(glob.glob(os.path.join(source_dir, "*.wav")))
    decoded_paths = sorted(glob.glob(os.path.join(decoded_dir, "Vintage 70's Acrolite (Tight) - Close Mic_chunk*_wave5_v3.wav")))

    print(f"Source WAVs: {len(source_paths)}")
    print(f"Decoded WAVs: {len(decoded_paths)}")
    print()

    if source_paths:
        print("Source summary (first 5):")
        for p in source_paths[:5]:
            info = wav_info(p)
            print(f"  {os.path.basename(p)}: {info['frames']} frames, {info['channels']}ch, {info['rate']}Hz, {info['sampwidth']*8}-bit")
        print()

    if decoded_paths:
        print("Decoded summary (first 5):")
        for p in decoded_paths[:5]:
            info = wav_info(p)
            print(f"  {os.path.basename(p)}: {info['frames']} frames, {info['channels']}ch, {info['rate']}Hz, {info['sampwidth']*8}-bit")
        print()

    if source_paths and decoded_paths:
        source_frames = sorted(wav_info(p)["frames"] for p in source_paths)
        decoded_frames = sorted(wav_info(p)["frames"] for p in decoded_paths)
        print(f"Source frames range: {source_frames[0]}..{source_frames[-1]}")
        print(f"Decoded frames range: {decoded_frames[0]}..{decoded_frames[-1]}")


if __name__ == "__main__":
    main()
