#!/usr/bin/env python3
"""
Detect fundamental frequency of drum samples and add to preset JSON.

This script analyzes the loudest velocity layer, first round robin, first mic
of each preset and adds 'freq' and 'freqConfidence' fields to preset.json.

Usage:
    python3 detect_fundamental_frequency.py
    python3 detect_fundamental_frequency.py --instrument-type kick
    python3 detect_fundamental_frequency.py --instrument-type snare
"""

import os
import json
import argparse
import sys
from pathlib import Path
from typing import Optional, Tuple, Dict, List

try:
    import numpy as np
    import librosa
    from scipy import signal
    from scipy.fft import rfft, rfftfreq
    import wave
except ImportError:
    print("Error: Required libraries not installed.")
    print("Install with: pip3 install librosa scipy numpy")
    sys.exit(1)


# Instrument-specific detection parameters
INSTRUMENT_PARAMS = {
    "kick": {
        "fmin": 22,
        "fmax": 150,
        "window_start_ms": 10,
        "window_end_ms": 200,
        "description": "Kicks (22-150 Hz, 10-200ms window)"
    },
    "snare": {
        "fmin": 80,
        "fmax": 300,
        "window_start_ms": 5,
        "window_end_ms": 100,
        "description": "Snares (80-300 Hz, 5-100ms window)"
    },
    "tom": {
        "fmin": 40,
        "fmax": 200,
        "window_start_ms": 10,
        "window_end_ms": 150,
        "description": "Toms (40-200 Hz, 10-150ms window)"
    },
    "cymbal": {
        "skip": True,
        "description": "Cymbals (skipped)"
    }
}

# Detection settings
CONFIDENCE_THRESHOLD = 0.4
YIN_CONFIDENCE_THRESHOLD = 0.5  # Fallback to FFT if YIN confidence < this


def detect_frequency_yin(audio: np.ndarray, sr: int, fmin: float, fmax: float) -> Tuple[Optional[float], float]:
    """
    Detect fundamental frequency using YIN autocorrelation algorithm.
    
    Returns:
        (frequency_hz, confidence) where confidence is 0.0-1.0
    """
    try:
        # Calculate appropriate frame_length for the given fmin
        # frame_length must be >= sr / fmin
        min_frame_length = int(np.ceil(sr / fmin)) + 1
        frame_length = max(2048, min_frame_length)
        
        # YIN algorithm from librosa
        f0 = librosa.yin(
            audio,
            fmin=fmin,
            fmax=fmax,
            sr=sr,
            frame_length=frame_length
        )
        
        # Remove unvoiced frames (zero values)
        voiced_frames = f0[f0 > 0]
        
        if len(voiced_frames) == 0:
            return None, 0.0
        
        # Take median as the fundamental
        frequency = float(np.median(voiced_frames))
        
        # Calculate confidence based on variance and number of voiced frames
        freq_std = np.std(voiced_frames)
        freq_mean = np.mean(voiced_frames)
        
        # Normalized standard deviation (coefficient of variation)
        cv = freq_std / freq_mean if freq_mean > 0 else 1.0
        
        # Confidence decreases with higher variance
        stability_confidence = np.exp(-cv * 2.0)  # Higher variance = lower confidence
        
        # Voiced frame ratio
        voiced_ratio = len(voiced_frames) / len(f0)
        
        # Combined confidence
        confidence = float(stability_confidence * voiced_ratio)
        
        return frequency, confidence
        
    except Exception as e:
        print(f"    YIN detection failed: {e}")
        return None, 0.0


def detect_frequency_fft(audio: np.ndarray, sr: int, fmin: float, fmax: float) -> Tuple[Optional[float], float]:
    """
    Detect fundamental frequency using FFT peak detection (fallback method).
    
    Returns:
        (frequency_hz, confidence) where confidence is 0.0-1.0
    """
    try:
        # Apply window to reduce spectral leakage
        windowed = audio * signal.windows.hann(len(audio))
        
        # Compute FFT
        fft_result = rfft(windowed)
        freqs = rfftfreq(len(windowed), 1/sr)
        
        # Magnitude spectrum
        magnitude = np.abs(fft_result)
        
        # Filter to frequency range of interest
        freq_mask = (freqs >= fmin) & (freqs <= fmax)
        filtered_freqs = freqs[freq_mask]
        filtered_magnitude = magnitude[freq_mask]
        
        if len(filtered_magnitude) == 0:
            return None, 0.0
        
        # Find peak
        peak_idx = np.argmax(filtered_magnitude)
        frequency = float(filtered_freqs[peak_idx])
        peak_magnitude = filtered_magnitude[peak_idx]
        
        # Calculate confidence based on peak prominence
        # Compare peak to mean magnitude in the range
        mean_magnitude = np.mean(filtered_magnitude)
        
        if mean_magnitude > 0:
            prominence = peak_magnitude / mean_magnitude
            # Normalize prominence to 0-1 confidence scale
            # Strong peaks have prominence > 3, weak peaks < 2
            confidence = float(np.clip((prominence - 1.5) / 3.0, 0.0, 1.0))
        else:
            confidence = 0.0
        
        return frequency, confidence
        
    except Exception as e:
        print(f"    FFT detection failed: {e}")
        return None, 0.0


def get_fft_magnitude_at_freq(audio: np.ndarray, sr: int, target_freq: float) -> float:
    """Return FFT magnitude at the nearest bin to target_freq."""
    if target_freq <= 0:
        return 0.0
    try:
        windowed = audio * signal.windows.hann(len(audio))
        fft_result = rfft(windowed)
        freqs = rfftfreq(len(windowed), 1 / sr)
        idx = int(np.argmin(np.abs(freqs - target_freq)))
        if idx < 0 or idx >= len(fft_result):
            return 0.0
        return float(np.abs(fft_result[idx]))
    except Exception:
        return 0.0


def detect_fundamental_frequency(
    wav_path: str,
    instrument_type: str
) -> Tuple[Optional[float], float]:
    """
    Detect fundamental frequency using hybrid YIN + FFT approach.
    
    Args:
        wav_path: Path to WAV file
        instrument_type: One of 'kick', 'snare', 'tom', 'cymbal'
    
    Returns:
        (frequency_hz, confidence) tuple, or (None, 0.0) on failure
    """
    params = INSTRUMENT_PARAMS.get(instrument_type)
    if not params or params.get("skip"):
        return None, 0.0
    
    try:
        # Load audio - try librosa first, fallback to wave module
        try:
            audio, sr = librosa.load(wav_path, sr=None, mono=True)
        except Exception as load_error:
            # Fallback: use wave module for basic WAV reading
            print(f"    Librosa load failed ({load_error}), trying wave module...")
            with wave.open(wav_path, 'rb') as wav_file:
                sr = wav_file.getframerate()
                n_channels = wav_file.getnchannels()
                sampwidth = wav_file.getsampwidth()
                frames = wav_file.readframes(wav_file.getnframes())
                
                # Convert bytes to numpy array
                if sampwidth == 1:
                    dtype = np.uint8
                    audio = np.frombuffer(frames, dtype=dtype).astype(np.float32)
                    audio = (audio - 128) / 128.0
                elif sampwidth == 2:
                    dtype = np.int16
                    audio = np.frombuffer(frames, dtype=dtype).astype(np.float32)
                    audio = audio / 32768.0
                elif sampwidth == 3:
                    # 24-bit audio
                    audio = np.frombuffer(frames, dtype=np.uint8)
                    audio = audio.reshape(-1, 3)
                    # Convert to int32 and then normalize
                    audio = ((audio[:, 2].astype(np.int32) << 16) |
                            (audio[:, 1].astype(np.int32) << 8) |
                            audio[:, 0].astype(np.int32))
                    audio = audio.astype(np.float32) / (2**23)
                elif sampwidth == 4:
                    dtype = np.int32
                    audio = np.frombuffer(frames, dtype=dtype).astype(np.float32)
                    audio = audio / (2**31)
                else:
                    raise ValueError(f"Unsupported sample width: {sampwidth}")
                
                # Convert stereo to mono if needed
                if n_channels > 1:
                    audio = audio.reshape(-1, n_channels).mean(axis=1)
        
        # Extract analysis window
        start_sample = int(params["window_start_ms"] / 1000.0 * sr)
        end_sample = int(params["window_end_ms"] / 1000.0 * sr)
        
        if end_sample > len(audio):
            end_sample = len(audio)
        
        if start_sample >= end_sample:
            return None, 0.0
        
        segment = audio[start_sample:end_sample]
        
        def run_detection(fmax: float) -> Tuple[Optional[float], float]:
            # Primary method: YIN autocorrelation
            freq_yin, conf_yin = detect_frequency_yin(
                segment, sr, params["fmin"], fmax
            )

            # If YIN confidence is good, use it
            if freq_yin and conf_yin >= YIN_CONFIDENCE_THRESHOLD:
                return freq_yin, conf_yin

            # Fallback: FFT peak detection (especially for snares)
            freq_fft, conf_fft = detect_frequency_fft(
                segment, sr, params["fmin"], fmax
            )

            # Use whichever method has higher confidence
            if freq_yin and freq_fft:
                if conf_yin >= conf_fft:
                    return freq_yin, conf_yin
                else:
                    return freq_fft, conf_fft
            elif freq_yin:
                return freq_yin, conf_yin
            elif freq_fft:
                return freq_fft, conf_fft
            else:
                return None, 0.0

        # Run initial detection with default fmax
        freq, conf = run_detection(params["fmax"])

        # If confidence is low, try reducing fmax by 50 Hz
        if conf < 0.5:
            reduced_fmax = max(params["fmin"] + 1.0, params["fmax"] - 50.0)
            freq_alt, conf_alt = run_detection(reduced_fmax)
            if conf_alt > conf:
                freq, conf = freq_alt, conf_alt

        # If detected freq is very low, check if its octave is more likely
        if freq and freq < 50.0:
            doubled = freq * 2.0
            if doubled <= params["fmax"]:
                mag_low = get_fft_magnitude_at_freq(segment, sr, freq)
                mag_double = get_fft_magnitude_at_freq(segment, sr, doubled)
                if mag_double > mag_low:
                    freq = doubled

            # Also try YIN in a tighter octave range and use it if confidence improves
            octave_center = doubled
            octave_fmin = max(params["fmin"], octave_center - 20.0)
            octave_fmax = min(params["fmax"], octave_center + 20.0)
            if octave_fmax > octave_fmin:
                freq_oct, conf_oct = detect_frequency_yin(
                    segment, sr, octave_fmin, octave_fmax
                )
                if freq_oct and conf_oct > conf:
                    freq, conf = freq_oct, conf_oct

        return freq, conf
            
    except Exception as e:
        print(f"    Error analyzing {wav_path}: {e}")
        return None, 0.0


def get_target_sample_path(preset_json_path: str) -> Optional[str]:
    """
    Parse preset JSON and return path to target sample:
    - Loudest velocity layer (max 'hi' value)
    - First populated slot (first mic)
    - First round robin
    
    Returns:
        Absolute path to target WAV file, or None if not found
    """
    try:
        with open(preset_json_path, 'r') as f:
            preset = json.load(f)
        
        velocity_layers = preset.get('velocityLayers', [])
        if not velocity_layers:
            return None
        
        # Find loudest velocity layer (highest 'hi' value)
        loudest_layer = max(velocity_layers, key=lambda l: l.get('hi', 0))
        
        wavs_by_slot = loudest_layer.get('wavsBySlot', {})
        
        # Find first populated slot (1-8)
        for slot_num in range(1, 9):
            slot_key = str(slot_num)
            if slot_key in wavs_by_slot and wavs_by_slot[slot_key]:
                # Get first round robin
                first_rr_rel_path = wavs_by_slot[slot_key][0]
                
                # Resolve absolute path
                preset_folder = os.path.dirname(preset_json_path)
                
                # Handle relative paths (including ../ for shared WAV folders)
                wav_abs_path = os.path.normpath(
                    os.path.join(preset_folder, first_rr_rel_path)
                )
                
                if os.path.exists(wav_abs_path):
                    return wav_abs_path
                else:
                    print(f"    Warning: Sample not found: {wav_abs_path}")
                    return None
        
        return None
        
    except Exception as e:
        print(f"    Error parsing preset JSON: {e}")
        return None


def update_preset_json(preset_json_path: str, freq: float, confidence: float) -> bool:
    """
    Update preset.json with freq and freqConfidence fields.
    Preserves existing formatting and field order.
    
    Returns:
        True if successful, False otherwise
    """
    try:
        with open(preset_json_path, 'r') as f:
            preset = json.load(f)
        
        # Add freq and freqConfidence at top level
        preset['freq'] = round(freq, 2)
        preset['freqConfidence'] = round(confidence, 3)
        
        # Write back with formatting
        with open(preset_json_path, 'w') as f:
            json.dump(preset, f, indent=2)
            f.write('\n')  # Add trailing newline
        
        return True
        
    except Exception as e:
        print(f"    Error updating JSON: {e}")
        return False


def process_preset(preset_folder: str, stats: Dict) -> None:
    """
    Process a single preset folder: detect frequency and update JSON.
    
    Args:
        preset_folder: Path to .preset folder
        stats: Dictionary to accumulate statistics
    """
    preset_json_path = os.path.join(preset_folder, "preset.json")
    
    if not os.path.exists(preset_json_path):
        return
    
    try:
        # Load preset to check instrument type
        with open(preset_json_path, 'r') as f:
            preset = json.load(f)
        
        instrument_type = preset.get('instrumentType', 'unknown')
        preset_name = os.path.basename(preset_folder)
        
        stats['total'] += 1
        stats['by_type'][instrument_type] = stats['by_type'].get(instrument_type, 0) + 1
        
        # Skip if instrument type not supported or cymbal
        params = INSTRUMENT_PARAMS.get(instrument_type)
        if not params or params.get('skip'):
            stats['skipped'] += 1
            print(f"⊘ {preset_name} [{instrument_type}] - Skipped")
            return
        
        print(f"→ {preset_name} [{instrument_type}]")
        
        # Get target sample path
        sample_path = get_target_sample_path(preset_json_path)
        if not sample_path:
            stats['failed'] += 1
            print(f"  ✗ No valid sample found")
            return
        
        rel_sample = os.path.relpath(sample_path, preset_folder)
        print(f"  Analyzing: {rel_sample}")
        
        # Detect frequency
        freq, confidence = detect_fundamental_frequency(sample_path, instrument_type)
        
        if freq and confidence >= CONFIDENCE_THRESHOLD:
            # Update JSON
            if update_preset_json(preset_json_path, freq, confidence):
                stats['success'] += 1
                print(f"  ✓ Detected: {freq:.1f} Hz (confidence: {confidence:.2f})")
            else:
                stats['failed'] += 1
                print(f"  ✗ Failed to update JSON")
        else:
            stats['low_confidence'] += 1
            conf_str = f"{confidence:.2f}" if confidence > 0 else "N/A"
            freq_str = f"{freq:.1f} Hz" if freq else "N/A"
            print(f"  ⚠ Low confidence: {freq_str} (confidence: {conf_str})")
            stats['low_conf_list'].append({
                'preset': preset_name,
                'type': instrument_type,
                'freq': freq,
                'confidence': confidence
            })
        
    except Exception as e:
        stats['failed'] += 1
        print(f"  ✗ Error: {e}")


def find_preset_folders(presets_root: str, instrument_filter: Optional[str] = None) -> List[str]:
    """
    Recursively find all .preset folders.
    
    Args:
        presets_root: Root presets directory
        instrument_filter: Optional filter ('kick', 'snare', 'tom')
    
    Returns:
        List of paths to .preset folders
    """
    preset_folders = []
    
    for root, dirs, files in os.walk(presets_root):
        for dir_name in dirs:
            if dir_name.endswith('.preset'):
                preset_path = os.path.join(root, dir_name)
                
                # If filtering by instrument type, check preset.json
                if instrument_filter:
                    preset_json = os.path.join(preset_path, 'preset.json')
                    if os.path.exists(preset_json):
                        try:
                            with open(preset_json, 'r') as f:
                                data = json.load(f)
                                if data.get('instrumentType') == instrument_filter:
                                    preset_folders.append(preset_path)
                        except:
                            pass
                else:
                    preset_folders.append(preset_path)
    
    return sorted(preset_folders)


def print_summary(stats: Dict) -> None:
    """Print summary statistics and low-confidence detections."""
    print("\n" + "="*70)
    print("SUMMARY")
    print("="*70)
    print(f"Total presets:        {stats['total']}")
    print(f"Successfully updated: {stats['success']}")
    print(f"Low confidence:       {stats['low_confidence']}")
    print(f"Skipped (cymbals):    {stats['skipped']}")
    print(f"Failed:               {stats['failed']}")
    
    if stats['by_type']:
        print(f"\nBy instrument type:")
        for inst_type, count in sorted(stats['by_type'].items()):
            print(f"  {inst_type}: {count}")
    
    if stats['success'] > 0:
        success_rate = (stats['success'] / max(stats['total'] - stats['skipped'], 1)) * 100
        print(f"\nSuccess rate: {success_rate:.1f}% (excluding skipped)")
    
    # Print low-confidence detections for review
    if stats['low_conf_list']:
        print(f"\n" + "-"*70)
        print(f"LOW CONFIDENCE DETECTIONS ({len(stats['low_conf_list'])} presets)")
        print("-"*70)
        for item in stats['low_conf_list'][:20]:  # Show first 20
            freq_str = f"{item['freq']:.1f} Hz" if item['freq'] else "N/A"
            conf_str = f"{item['confidence']:.2f}" if item['confidence'] else "N/A"
            print(f"  {item['preset'][:50]:50} [{item['type']:6}] {freq_str:>10} (conf: {conf_str})")
        
        if len(stats['low_conf_list']) > 20:
            print(f"  ... and {len(stats['low_conf_list']) - 20} more")


def main():
    parser = argparse.ArgumentParser(
        description='Detect fundamental frequency of drum samples and update preset JSON files.'
    )
    parser.add_argument(
        '--instrument-type',
        choices=['kick', 'snare', 'tom'],
        help='Filter to process only specific instrument type'
    )
    parser.add_argument(
        '--presets-path',
        default='presets',
        help='Path to presets directory (default: presets/)'
    )
    
    args = parser.parse_args()
    
    # Resolve presets path
    script_dir = os.path.dirname(os.path.abspath(__file__))
    project_root = os.path.dirname(script_dir)
    presets_path = os.path.join(project_root, args.presets_path)
    
    if not os.path.exists(presets_path):
        print(f"Error: Presets directory not found: {presets_path}")
        sys.exit(1)
    
    print("="*70)
    print("FUNDAMENTAL FREQUENCY DETECTION")
    print("="*70)
    print(f"Presets path: {presets_path}")
    print(f"Confidence threshold: {CONFIDENCE_THRESHOLD}")
    
    if args.instrument_type:
        print(f"Filter: {args.instrument_type} only")
        params = INSTRUMENT_PARAMS[args.instrument_type]
        print(f"Parameters: {params['description']}")
    else:
        print("Processing all instrument types:")
        for inst_type, params in INSTRUMENT_PARAMS.items():
            print(f"  - {inst_type}: {params['description']}")
    
    print("="*70 + "\n")
    
    # Find preset folders
    preset_folders = find_preset_folders(presets_path, args.instrument_type)
    
    if not preset_folders:
        print("No preset folders found.")
        return
    
    print(f"Found {len(preset_folders)} preset(s) to process.\n")
    
    # Initialize statistics
    stats = {
        'total': 0,
        'success': 0,
        'low_confidence': 0,
        'skipped': 0,
        'failed': 0,
        'by_type': {},
        'low_conf_list': []
    }
    
    # Process each preset
    for preset_folder in preset_folders:
        process_preset(preset_folder, stats)
    
    # Print summary
    print_summary(stats)


if __name__ == '__main__':
    main()
