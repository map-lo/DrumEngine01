# DrumEngine01 Technical Specification

## JSON Schema Validation Rules

### Schema Version

- **Field**: `schemaVersion` (required, integer)
- **Valid**: Must be exactly `1`
- **Reject**: Any other value

### Slot Configuration

- **Field**: `slotNames` (required, string array)
- **Valid**: 1-8 slot names
- **Note**: Engine clamps to max 8 even if more provided
- **Usage**: Index 0 = slot "1", Index 1 = slot "2", etc.

### Root Folder

- **Field**: `rootFolder` (required, string)
- **Valid**: Non-empty absolute path
- **Usage**: All wav paths in `wavsBySlot` are relative to this

### Velocity Layers

- **Field**: `velocityLayers` (required, array of objects)
- **Valid**: 1-10 velocity layer objects
- **Sorting**: Engine sorts by `lo` value (ascending)
- **Overlap**: Allowed; first matching layer selected

#### Velocity Layer Object

```json
{
  "index": 1,           // Optional, informational only
  "lo": 1,              // Required, 1-127, must be <= hi
  "hi": 12,             // Required, 1-127, must be >= lo
  "wavsBySlot": {       // Required, object
    "1": ["path.wav"],  // String key, array of strings
    "2": [],            // Empty array = slot unused
    ...
  }
}
```

### RR Count Validation (STRICT)

For each velocity layer:

1. Iterate all slots and find max non-empty array length = `rrCount`
2. For EVERY non-empty slot: array length MUST equal `rrCount`
3. If any mismatch: **REJECT ENTIRE PRESET**
4. If `rrCount` == 0 (all slots empty): **REJECT ENTIRE PRESET**

**Example - VALID**:

```json
"wavsBySlot": {
  "1": ["a.wav", "b.wav", "c.wav"],  // 3 files
  "2": [],                            // Empty (unused)
  "3": ["d.wav", "e.wav", "f.wav"]   // 3 files (matches!)
}
```

**Example - INVALID**:

```json
"wavsBySlot": {
  "1": ["a.wav", "b.wav"],           // 2 files
  "3": ["d.wav", "e.wav", "f.wav"]   // 3 files (MISMATCH!)
}
```

### Fixed MIDI Note

- **Field**: `fixedMidiNote` (optional, integer)
- **Valid**: 0-127
- **Default**: 38 (if not specified)
- **Usage**: Only this MIDI note triggers samples

### Velocity-to-Volume

- **Field**: `velToVol` (optional, object)
- **Default**: Linear curve, 100% amount

```json
"velToVol": {
  "amount": 100,                    // 0-100, percentage influence
  "curve": {                        // Optional
    "type": "builtin",              // Currently only builtin supported
    "name": "soft"                  // "linear" or "soft"
  }
}
```

**Gain Calculation**:

```cpp
float vel01 = (velocity - 1) / 126.0f;  // Normalize to 0..1

// Apply curve
float shaped = (curveName == "soft") ? pow(vel01, 0.5f) : vel01;

// Apply amount
float amount01 = velToVolAmount / 100.0f;
float gain = shaped * amount01 + (1.0f - amount01);
```

## Voice State Machine

### MicVoice States

```
Inactive → Playing → Releasing → Inactive
   ↑          ↓          ↓           ↓
   └──────────┴──────────┴───────────┘
```

**Inactive**:

- Voice is free, no sample loaded
- Can be allocated

**Playing**:

- Reading frames from sample
- On each render call:
  - Read frame from SampleRef
  - Increment playbackFrame
  - If `playbackFrame >= totalFrames`: transition to Releasing

**Releasing**:

- Fixed-length fade-out (N samples)
- fadePosition increments each sample
- fadeGain = 1.0 - (fadePosition / fadeLenSamples)
- When `fadePosition >= fadeLenSamples`: transition to Inactive
- Sample reading stops, output is 0 \* fadeGain

### Trigger Rules

**On NoteOn (fixedMidiNote, velocity)**:

1. Find velocity layer index by `velocity ∈ [lo, hi]`
2. If no match: ignore
3. Get RR index: `rrIndex = rrCounter[layer]++ % rrCount[layer]`
4. If `activeHitGroups.size >= 3`:
   - Call `beginRelease()` on all voices in oldest HitGroup
   - Remove oldest HitGroup from queue
5. Allocate new HitGroup
6. For each slot (0..slotCount-1):
   - Get sample: `samples[layer][rrIndex][slot]`
   - If sample is nullptr: skip
   - Allocate voice from pool
   - Start voice: `voice.start(sample, gain, fadeLenSamples)`
   - Store voice pointer in HitGroup
7. Add HitGroup to queue

**On NoteOff**:

- Ignored (one-shot samples always play to completion or steal)

## Sample Streaming

### Memory Mapping

- Uses `juce::AudioFormatReader`
- Prefers memory-mapped reader when possible
- OS handles paging (efficient for large libraries)

### Cache Strategy

- Per-SampleRef: 512-frame cache
- On `getFrame(frameIndex)`:
  - If `frameIndex` not in cache: read 512-frame block starting at `frameIndex`
  - Return frame from cache

**Read Implementation**:

```cpp
void SampleRef::getFrame(int64 frameIndex, float& outL, float& outR) const
{
    if (frameIndex < cacheStart || frameIndex >= cacheStart + cacheSize)
        updateCache(frameIndex);

    int offset = frameIndex - cacheStart;
    if (numChannels == 1) {
        float mono = readCache.getSample(0, offset);
        outL = outR = mono;  // Duplicate mono to stereo
    } else {
        outL = readCache.getSample(0, offset);
        outR = readCache.getSample(1, offset);
    }
}
```

### Thread Safety

- **Preset Loading**: Off audio thread
- **Sample Loading**: Off audio thread
- **Preset Swap**: Atomic pointer exchange
- **Sample Access**: Read-only on audio thread (shared_ptr keeps alive)
- **No file I/O**: All file ops happen during preset load

## Voice Allocation

### VoicePool Strategy

1. **First pass**: Find any Inactive voice → return immediately
2. **Second pass**: Find any Releasing voice → reset & return
3. **Third pass**: Find first Playing voice → reset & return (steal)
4. **Fallback**: Reset voices[0] and return

### Stealing Priority

1. Inactive (best - no audible effect)
2. Releasing (better - already fading)
3. Playing (worst - causes abrupt cut)

In practice: With 32 voices and max 24 active (3 HitGroups × 8 slots), stealing rarely happens unless very rapid triggering.

## Rendering Pipeline

### processBlock Flow

```cpp
void Engine::processBlock(buffer, midiMessages)
{
    buffer.clear();  // Zero output

    for (auto midiMsg : midiMessages) {
        if (midiMsg.isNoteOn())
            handleNoteOn(note, velocity);
    }

    voicePool.renderAll(buffer, 0, numSamples);

    // Clean up inactive HitGroups
    removeInactive(activeHitGroups);
}
```

### Voice Rendering

```cpp
void MicVoice::render(buffer, start, numSamples)
{
    for (int i = 0; i < numSamples; ++i) {
        float l = 0, r = 0;

        if (state == Playing) {
            sample->getFrame(playbackFrame++, l, r);
            if (playbackFrame >= sample->getTotalFrames())
                beginRelease();
        }

        if (state == Releasing) {
            float fadeGain = 1.0f - (fadePos++ / (float)fadeLen);
            if (fadePos >= fadeLen) {
                reset();
                return;
            }
            l *= fadeGain;
            r *= fadeGain;
        }

        buffer.addSample(0, start + i, l * gain);
        buffer.addSample(1, start + i, r * gain);
    }
}
```

## Memory Usage

### Per Sample

- SampleRef object: ~100 bytes
- Cache: 512 frames × 2 channels × 4 bytes = 4 KB
- Reader: Minimal (memory-mapped pointer)

### Per Preset

- 10 layers × 5 RR × 8 slots = 400 max SampleRefs
- With deduplication: typically 50-200 unique samples
- Total cache: 50-200 samples × 4 KB = 200-800 KB

### Per Voice

- MicVoice object: ~64 bytes
- 32 voices × 64 bytes = 2 KB

### Total Runtime

- ~1-2 MB for engine + voices + caches
- Sample data: Memory-mapped (doesn't count toward RSS until accessed)

## Build Configuration

### CMake Setup

```cmake
target_sources(DrumEngine01 PRIVATE
    src/PluginProcessor.cpp
    src/PluginEditor.cpp
    src/engine/PresetSchema.cpp
    src/engine/SampleRef.cpp
    src/engine/RuntimePreset.cpp
    src/engine/Voice.cpp
    src/engine/Engine.cpp
)

target_link_libraries(DrumEngine01 PRIVATE
    juce::juce_audio_utils
    juce::juce_audio_formats  # Required for AudioFormatManager
)
```

### JUCE Modules Required

- `juce_core` - String, File, JSON, Result
- `juce_audio_basics` - AudioBuffer
- `juce_audio_formats` - AudioFormatReader, AudioFormatManager
- `juce_audio_processors` - AudioProcessor base class

### Compiler Requirements

- C++17 minimum (for `std::shared_ptr`, `std::unordered_map`, etc.)
- Supports: macOS (tested), Windows, Linux (untested but should work)

## Performance Characteristics

### Best Case

- Sequential playback: O(1) per frame (cache hit)
- RR selection: O(1) (array index + modulo)
- Layer selection: O(N) where N = velocity layers (max 10)
- Voice allocation: O(M) where M = pool size (32)

### Worst Case

- Cache miss every frame: O(512) per frame (block read)
- In practice: Rare due to sequential playback

### CPU Usage Estimate

- Per voice: ~0.01-0.05% CPU (modern CPU @ 44.1kHz)
- 24 voices: ~0.5-1% CPU
- Plenty of headroom for UI, effects, etc.

## Error Handling

### Preset Loading

- Invalid JSON: Log error, don't crash
- Missing file: Log warning, skip sample (slot becomes nullptr)
- Invalid schema: Reject preset, keep previous
- Thread-safe: Atomic swap ensures audio thread always has valid preset or nullptr

### Runtime

- No sample for slot: MicVoice pointer is nullptr, skipped safely
- No velocity layer match: Note ignored
- Voice pool exhausted: Oldest voice stolen (graceful degradation)

## Future Optimization Opportunities

1. **SIMD**: Vectorize mixing loop
2. **Lock-free**: Replace `std::deque` with ring buffer
3. **Prefetch**: Predict next RR and warm cache
4. **Streaming**: Load samples on-demand instead of all at once
5. **Compression**: Decompress on-the-fly (trade CPU for memory)
6. **Multi-threaded load**: Parallel sample loading on preset change
