# DrumEngine01 Implementation Summary

## Overview

A JUCE-based drum engine VST3 plugin with JSON-driven preset loading, memory-mapped sample streaming, and sophisticated voice management.

## Architecture

### 1. PresetSchema (JSON Parsing)

- **File**: [src/engine/PresetSchema.h](src/engine/PresetSchema.h), [src/engine/PresetSchema.cpp](src/engine/PresetSchema.cpp)
- Parses JSON preset files according to BITE.json schema
- Validates:
  - Schema version (must be 1)
  - Slot count (1-8 slots/mics)
  - Velocity layers (1-10 layers)
  - RR count consistency across slots within each layer (STRICT)
- Supports optional `fixedMidiNote` field (defaults to 38 for snare)
- Supports `velToVol` for velocity-to-volume curves

### 2. SampleRef (Memory-Mapped Streaming)

- **File**: [src/engine/SampleRef.h](src/engine/SampleRef.h), [src/engine/SampleRef.cpp](src/engine/SampleRef.cpp)
- Memory-mapped audio file reading using JUCE's AudioFormatReader
- Efficient frame-by-frame access with 512-frame cache
- Handles mono/stereo:
  - Mono: duplicated to L/R
  - Stereo: uses first 2 channels
- NO file I/O on audio thread (all loading done off-thread)

### 3. RuntimePreset (Resolved Sample References)

- **File**: [src/engine/RuntimePreset.h](src/engine/RuntimePreset.h), [src/engine/RuntimePreset.cpp](src/engine/RuntimePreset.cpp)
- Builds runtime structures from PresetSchema
- Sample deduplication via shared_ptr cache
- 3D sample array: `samples[velocityLayer][rrIndex][slotIndex]`
- Velocity-to-gain conversion with curves (linear, soft)
- Finds velocity layer by MIDI velocity

### 4. Voice System

- **File**: [src/engine/Voice.h](src/engine/Voice.h), [src/engine/Voice.cpp](src/engine/Voice.cpp)

#### MicVoice

- One-shot sample playback
- States: Inactive, Playing, Releasing
- Fixed-length fade-out (always N samples):
  - Applied on EOF (end-of-file)
  - Applied on steal/choke
  - Fade length independent of sample length or playback position
- Renders stereo output

#### HitGroup

- Collection of up to 8 MicVoices (one per slot)
- All voices in a group start together (aligned)
- All voices in a group fade out together when stolen

#### VoicePool

- Pool of 32 MicVoices for reuse
- Allocation strategy: inactive → releasing → oldest playing

### 5. Engine (Main Logic)

- **File**: [src/engine/Engine.h](src/engine/Engine.h), [src/engine/Engine.cpp](src/engine/Engine.cpp)

#### Core Features

- **Fixed MIDI note**: Only responds to one MIDI note (ignores others)
- **Max 3 HitGroups**: New triggers beyond 3 steal the oldest HitGroup
- **RR cycling**: Separate RR counter per velocity layer
- **Steal behavior**: Oldest HitGroup begins fixed-length fade-out
- **Thread-safe preset swapping**: Atomic pointer swap

#### Processing Flow

1. Note-on arrives
2. Check if note == fixedMidiNote
3. Find velocity layer by velocity
4. Get RR index: `rrCounter[layer]++ % rrCount[layer]`
5. If 3 HitGroups active: steal oldest (begin fade-out)
6. Allocate new HitGroup
7. Start MicVoice for each non-null slot
8. Render all active voices

### 6. Plugin Integration

- **File**: [src/PluginProcessor.h](src/PluginProcessor.h), [src/PluginProcessor.cpp](src/PluginProcessor.cpp)
- Engine initialized in `prepareToPlay`
- Preset auto-loaded if BITE.json exists
- `processBlock` delegates to `engine.processBlock`
- Public `loadPresetFromFile` method for UI integration

## JSON Schema (BITE.json)

```json
{
  "schemaVersion": 1,
  "instrumentType": "snare",
  "slotNames": ["top", "bottom", "oh", "room1", "room2", "extra1", "extra2"],
  "rootFolder": "/path/to/samples",
  "fixedMidiNote": 38,
  "velocityLayers": [
    {
      "index": 1,
      "lo": 1,
      "hi": 12,
      "wavsBySlot": {
        "1": ["DRY/BITE DRY V01.wav"],
        "4": ["ROOM 1/BITE RM1 V01.wav"],
        "5": ["ROOM 2/BITE RM2 V01.wav"]
      }
    }
  ],
  "velToVol": {
    "amount": 100,
    "curve": { "type": "builtin", "name": "soft" }
  }
}
```

### Important Rules

1. **Slot keys**: String numbers "1".."N" (1-based)
2. **Slot mapping**: "1" → slotNames[0], "2" → slotNames[1], etc.
3. **RR consistency**: All non-empty slots in a velocity layer must have same RR count
4. **Relative paths**: All wav paths are relative to `rootFolder`

## Build Instructions

```bash
cd /Users/marian/Development/JUCE-Plugins/DrumEngine01/build
cmake --build .
```

The VST3 will be automatically installed to: `/Users/marian/Library/Audio/Plug-Ins/VST3/DrumEngine01.vst3`

## Testing

1. Load plugin in a DAW
2. Send MIDI note 38 (default, or as specified in JSON `fixedMidiNote`)
3. Vary velocity (1-127) to trigger different velocity layers
4. Rapidly retrigger to test:
   - RR cycling (should alternate between round robins)
   - 3-HitGroup limit (4th trigger steals oldest)
   - Fixed-length fade-out on steals

## Implementation Status

✅ All requirements implemented:

- [x] JSON preset parsing and validation
- [x] Memory-mapped sample streaming
- [x] Runtime preset with sample deduplication
- [x] Voice system with fixed-length fade-out
- [x] 3-HitGroup limit with stealing
- [x] RR cycling per velocity layer
- [x] Fixed MIDI note filtering
- [x] Stereo output (mono samples duplicated)
- [x] CMake build configuration
- [x] Plugin integration

## Configuration

### Fade Length

Default: 32 samples
Configurable via: `engine.setFadeLengthSamples(N)`

### Preset Path

Currently hardcoded in [PluginProcessor.cpp](src/PluginProcessor.cpp):

```cpp
juce::File presetFile = juce::File("/Users/marian/Development/JUCE-Plugins/DrumEngine01/kits/ThatSound DarrenKing/Snare/BITE.json");
```

Can be changed to load different presets or made configurable via UI.

## Future Enhancements (Optional)

1. **UI for preset selection**: File browser or dropdown
2. **Parameter automation**: Velocity curve amount, fade length, etc.
3. **Multi-note support**: Multiple fixed notes with preset switching
4. **Per-slot gain controls**: Mix adjustments in UI
5. **CPU optimization**: SIMD for mixing, more efficient cache strategy
6. **State save/restore**: Persist preset path in plugin state
7. **Background preset loading**: Thread pool for async loading
8. **Additional velocity curves**: Exponential, logarithmic, custom

## Notes

- Build produces warnings (sign conversion, unused parameters) - these are cosmetic and safe to ignore
- Plugin is a synth (IS_SYNTH=TRUE) and requires MIDI input
- Supports VST3 format only (can add AU, AAX later)
- Memory usage depends on sample count and file sizes (memory-mapped, so OS manages paging)
