#!/usr/bin/env python3
import struct
import sys
import wave

def main():
    filename = sys.argv[1] if len(sys.argv) > 1 else 'output/sine_440hz_v2.wav'
    with wave.open(filename, 'rb') as wav:
        n = wav.getnframes()
        channels = wav.getnchannels()
        sampwidth = wav.getsampwidth()
        frames = wav.readframes(n)

        if sampwidth != 2:
            raise ValueError(f'Unexpected sample width: {sampwidth}')

        total_samples = n * channels
        samples = list(struct.unpack('<' + 'h' * total_samples, frames))

    print(f'File: {filename}')
    print(f'Total frames: {n}')
    print(f'Channels: {channels}')
    print(f'Duration: {n / 44100:.3f} seconds')
    print()
    print('First 50 samples:')
    for i in range(0, min(50, len(samples)), 10):
        print(f'  [{i:5d}]: {samples[i:i+10]}')
    print()
    print(f'Max amplitude: {max(abs(s) for s in samples)}')
    print(f'RMS: {int((sum(s*s for s in samples) / len(samples)) ** 0.5)}')
    print()
    analysis_samples = samples[0::channels] if channels > 1 else samples
    print('Looking for 440Hz period (~100 samples at 44100Hz):')
    for period in [90, 95, 100, 105, 110]:
        if period < len(analysis_samples):
            similarity = sum(
                1 for i in range(min(period, len(analysis_samples)-period))
                if abs(analysis_samples[i] - analysis_samples[i+period]) < 1000
            )
            print(
                f'  Period {period}: '
                f'{similarity}/{min(period, len(analysis_samples)-period)} similar'
            )

if __name__ == '__main__':
    main()
