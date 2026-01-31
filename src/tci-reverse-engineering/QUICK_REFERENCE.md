# TCI Reverse Engineering - Quick Reference

## What is .tci?

**Trigger Compressed Instrument** format used by Slate Trigger 2 to store drum samples.

## File Structure

```
┌─────────────────────────────────────┐
│ HEADER (128 bytes)                  │
│ "TRIGGER COMPRESSED INSTRUMENT"     │
│ - Sample Rate: 48000 Hz             │
│ - Total Samples: 30                 │
│ - Velocity Layers: 5                │
├─────────────────────────────────────┤
│ COMPRESSED AUDIO DATA               │
│ (Proprietary compression)           │
│ ~9.4 MB for 30 samples              │
└─────────────────────────────────────┘
```

## Sample Organization

```
Articulation (MIDI Note 60)
├─ Hard (vel 0-24)
│  ├─ RR1: Hard 1.wav
│  ├─ RR2: Hard 2.wav
│  ├─ RR3: Hard 3.wav
│  ├─ RR4: Hard 4.wav
│  ├─ RR5: Hard 5.wav
│  └─ RR6: Hard 6.wav
├─ Hard_Med (vel 25-49)
│  └─ ... 6 round robins
├─ Med (vel 50-74)
│  └─ ... 6 round robins
├─ Med_Soft (vel 75-99)
│  └─ ... 6 round robins
└─ Soft (vel 100-127)
   └─ ... 6 round robins
```

## Quick Commands

### Analyze a TCI file

```bash
python3 tci_extractor.py "file.tci" --json output.json --wav-folder /path/to/wavs
```

### Verify the mapping

```bash
python3 verify_mapping.py output.json
```

### Batch convert multiple files

```bash
python3 batch_convert.py *.tci --output-dir ./json --wav-base-dir /path/to/samples
```

### Complete workflow example

```bash
python3 example_workflow.py
```

## Tools Overview

| Tool                  | Purpose                                 |
| --------------------- | --------------------------------------- |
| `tci_extractor.py`    | Main tool - analyze TCI and create JSON |
| `verify_mapping.py`   | Verify all WAV files exist              |
| `batch_convert.py`    | Convert multiple TCI files              |
| `analyze_tci.py`      | Low-level hex dump analysis             |
| `example_workflow.py` | Complete example with C++ integration   |

## TCI Header Map

| Offset | Size | Description           | Example Value                   |
| ------ | ---- | --------------------- | ------------------------------- |
| 0x00   | 32   | Signature             | "TRIGGER COMPRESSED INSTRUMENT" |
| 0x40   | 4    | Unknown               | 1                               |
| 0x68   | 4    | Sample Rate           | 48000                           |
| 0x74   | 4    | Total Samples         | 30                              |
| 0x78   | 4    | Velocity Layers       | 5                               |
| 0x80+  | -    | Compressed Audio Data | (proprietary)                   |

## Output JSON Format

```json
{
  "name": "Instrument Name",
  "sampleRate": 48000,
  "articulations": [
    {
      "midiNote": 60,
      "velocityLayers": [
        {
          "name": "Hard",
          "velocityRange": { "min": 0, "max": 24 },
          "roundRobins": [{ "index": 0, "file": "path/to/sample.wav" }]
        }
      ]
    }
  ]
}
```

## C++ Integration Snippet

```cpp
// Load JSON preset
auto json = juce::JSON::parse(juce::File("preset.json"));

// Iterate through velocity layers
for (auto& vel : *json["articulations"][0]["velocityLayers"].getArray()) {
    auto* velObj = vel.getDynamicObject();
    int minVel = velObj->getProperty("velocityRange")["min"];
    int maxVel = velObj->getProperty("velocityRange")["max"];

    // Load round robins
    for (auto& rr : *velObj->getProperty("roundRobins").getArray()) {
        juce::String file = rr["file"].toString();
        engine.loadSample(file, minVel, maxVel);
    }
}
```

## Velocity Mapping Reference

| MIDI Velocity | Layer    | Typical Dynamic  |
| ------------- | -------- | ---------------- |
| 0-24          | Hard     | Fortissimo (fff) |
| 25-49         | Hard_Med | Forte (ff)       |
| 50-74         | Med      | Mezzo-forte (mf) |
| 75-99         | Med_Soft | Mezzo-piano (mp) |
| 100-127       | Soft     | Piano (pp)       |

## Important Notes

✅ **Can Extract:**

- Metadata (sample count, layers, etc.)
- Velocity/RR mapping
- File organization structure

❌ **Cannot Extract (without further work):**

- Compressed audio data
- (Use original WAV files instead)

## File Locations

**Typical Slate Trigger 2:**

- macOS: `/Library/Application Support/Slate Digital/Trigger 2/`
- Windows: `C:\Program Files\Slate Digital\Trigger 2\`

**Your Project:**

- Tools: `src/tci-reverse-engineering/`
- Generated JSON: `acrolite_mapping.json` (verified ✓)

## Common Issues

**Issue:** WAV folder not found  
**Solution:** Use `--wav-folder` to specify exact path

**Issue:** Sample count mismatch  
**Solution:** Verify all WAV files are in the folder (check for hidden files)

**Issue:** JSON parsing error in plugin  
**Solution:** Verify JSON with `python3 -m json.tool file.json`

## Example: Complete Conversion

```bash
# 1. Convert TCI to JSON
python3 tci_extractor.py \
    "Vintage 70's Acrolite (Tight) - Close Mic.tci" \
    --json acrolite.json \
    --wav-folder "/path/to/WAV Files/VIntage 70's Acrolite (Tight)/Close Mic"

# 2. Verify all files exist
python3 verify_mapping.py acrolite.json

# 3. Copy to presets folder
cp acrolite.json ../../presets/

# 4. Load in your plugin
# (Use C++ code snippet above)
```

## Success!

You now have:

- ✅ Complete TCI structure documented
- ✅ Tools to convert any TCI file
- ✅ Working JSON for Acrolite preset
- ✅ C++ integration examples
- ✅ All 30 WAV files verified and ready

Ready to build drum presets! 🥁
