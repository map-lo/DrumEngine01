# TCI Format Reverse Engineering

## Overview

This directory contains tools for reverse engineering the `.tci` (Trigger Compressed Instrument) file format used by Slate Trigger 2.

## TCI File Format Structure

Based on analysis of `Vintage 70's Acrolite (Tight) - Close Mic.tci`:

### Header (128 bytes)

```
Offset  Size  Description
------  ----  -----------
0x00    32    Signature: "TRIGGER COMPRESSED INSTRUMENT" (null-terminated)
0x20    32    Padding (zeros)
0x40    4     Unknown (value: 1)
0x44    4     Unknown (value: 4)
0x48    4     Unknown (value: 4)
0x4C    4     Name/String length (value: 21)
0x50    4     Unknown (value: 4)
0x54    12    Unknown/Padding
0x60    4     Unknown (value: 20)
0x64    4     Unknown (value: 4)
0x68    4     Sample Rate (48000 Hz)
0x6C    4     Unknown/Padding
0x70    4     Unknown count (value: 4)
0x74    4     Total Samples (30 in this case)
0x78    4     Velocity Layers (5 in this case)
0x7C    4     Unknown/Padding
```

### Data Section (0x80 onwards)

The audio data appears to be stored in a compressed format (not standard WAV, FLAC, or Ogg).
The compression algorithm is proprietary to Slate Digital.

## Sample Organization

For the Acrolite TCI file:

- **Total Samples**: 30
- **Velocity Layers**: 5 (Hard, Hard_Med, Med, Med_Soft, Soft)
- **Round Robins per Layer**: 6
- **Sample Rate**: 48000 Hz
- **Audio Format** (original WAVs): 24-bit stereo PCM
- **Duration**: ~2.31 seconds per sample

### Velocity Layer Mapping

The TCI file organizes samples by velocity layers:

| Layer | Name     | MIDI Velocity Range | Round Robins |
| ----- | -------- | ------------------- | ------------ |
| 1     | Hard     | 0-24                | 1-6          |
| 2     | Hard_Med | 25-49               | 1-6          |
| 3     | Med      | 50-74               | 1-6          |
| 4     | Med_Soft | 75-99               | 1-6          |
| 5     | Soft     | 100-127             | 1-6          |

### Sample Index Mapping

```
Sample Index  Velocity Layer  Round Robin  Filename
------------  --------------  -----------  --------
1             Hard            1            Hard 1.wav
2             Hard            2            Hard 2.wav
3             Hard            3            Hard 3.wav
4             Hard            4            Hard 4.wav
5             Hard            5            Hard 5.wav
6             Hard            6            Hard 6.wav
7             Hard_Med        1            Hard_Med 1.wav
8             Hard_Med        2            Hard_Med 2.wav
...           ...             ...          ...
30            Soft            6            Soft 6.wav
```

## Tools

### tci_extractor.py

Main tool for analyzing TCI files and creating JSON mappings.

**Usage:**

```bash
python3 tci_extractor.py <tci_file> --json <output.json> --wav-folder <wav_folder_path>
```

**Example:**

```bash
python3 tci_extractor.py "Vintage 70's Acrolite (Tight) - Close Mic.tci" \
    --json acrolite_mapping.json \
    --wav-folder "/Users/marian/Downloads/SPINLIGHT SAMPLES/WAV Files/VIntage 70's Acrolite (Tight)/Close Mic"
```

**Output:** Creates a JSON file with the complete sample mapping for use in your plugin.

### analyze_tci.py

Lower-level analysis tool for examining TCI file structure.

## JSON Output Format

The extractor creates a JSON file with the following structure:

```json
{
  "name": "Instrument Name",
  "source": "Slate Trigger 2",
  "sampleRate": 48000,
  "articulations": [
    {
      "name": "Articulation 1",
      "midiNote": 60,
      "velocityLayers": [
        {
          "name": "Hard",
          "velocityRange": {
            "min": 0,
            "max": 24
          },
          "roundRobins": [
            {
              "index": 0,
              "file": "path/to/Hard 1.wav"
            },
            ...
          ]
        },
        ...
      ]
    }
  ]
}
```

## Notes on Audio Extraction

### Compressed Audio Data

The TCI file contains **compressed audio data** using a proprietary compression algorithm. The actual WAV files are **not** embedded in their original form.

To use these samples with your plugin:

1. **Option 1 (Recommended)**: Use the original WAV files if available
   - Slate Trigger 2 installs with the WAV files in a separate folder
   - Use `tci_extractor.py` to create a JSON mapping to these files

2. **Option 2**: Decompress from TCI (requires reverse engineering the compression)
   - The compression algorithm is proprietary and would require extensive reverse engineering
   - Not implemented in these tools

### File Size Comparison

- Original WAV files: ~30 × 650KB = ~19.5 MB (uncompressed 24-bit stereo)
- TCI file: 9.39 MB (~48% compression)

This suggests lossy compression or high-efficiency lossless compression.

## Integration with Your Plugin

Use the generated JSON file to configure your drum engine:

```cpp
// Example usage in your plugin
auto json = loadJSON("acrolite_mapping.json");

for (auto& articulation : json["articulations"]) {
    for (auto& velLayer : articulation["velocityLayers"]) {
        int minVel = velLayer["velocityRange"]["min"];
        int maxVel = velLayer["velocityRange"]["max"];

        for (auto& rr : velLayer["roundRobins"]) {
            String filePath = rr["file"];
            loadSample(filePath, minVel, maxVel, rr["index"]);
        }
    }
}
```

## Future Work

Potential improvements:

1. **Decompress Audio**: Reverse engineer the compression algorithm to extract audio directly from TCI
2. **Metadata Extraction**: Parse additional metadata (articulation names, power values shown in UI)
3. **Batch Processing**: Process multiple TCI files at once
4. **GUI Tool**: Create a visual tool for TCI analysis and extraction

## References

- **Slate Trigger 2**: https://www.slatedigital.com/trigger-2/
- **TCI File Format**: Proprietary binary format used by Slate Digital
- **Analysis Date**: January 31, 2026
