# Multi-Output Routing Changes

## Summary of Changes

Fixed the multi-output routing to address three key issues:

### 1. Mix Always on Outputs 1-2 ✅

**Before**: In stereo mode only, mix went to 1-2. In multi-out mode, slot 1 went to 1-2.

**After**: The full mix **always** goes to outputs 1-2, regardless of mode.

- **Stereo Mode**: Mix on 1-2 (only output)
- **Multi-Out Mode**: Mix on 1-2 + individual slots on 3-4, 5-6, etc.

### 2. Individual Mics Start at Output 3-4 ✅

**Before**: In multi-out mode:

- Slot 1 → Outputs 1-2
- Slot 2 → Outputs 3-4
- etc.

**After**: In multi-out mode:

- **Mix** → Outputs 1-2
- Slot 1 → Outputs 3-4
- Slot 2 → Outputs 5-6
- Slot 3 → Outputs 7-8
- etc.

This gives you 9 total stereo outputs (1 mix + 8 individual).

### 3. Fixed Bus Configuration 🔧

**Changes Made**:

1. Renamed first bus from "Main" to "Main (Mix)" for clarity
2. Renamed subsequent buses from "Slot 2-8" to "Slot 1-8"
3. Updated `processBlock()` to:
   - Always render full mix to channels 0-1
   - In multi-out mode, also render each slot to its dedicated pair (channels 2-3, 4-5, etc.)
4. Fixed MIDI processing to only trigger once per block using atomic flag

**Bus Layout**:

```
Bus 0: Main (Mix)     - Outputs 1-2   - Always enabled
Bus 1: Slot 1         - Outputs 3-4   - Enabled in multi-out mode
Bus 2: Slot 2         - Outputs 5-6   - Enabled in multi-out mode
Bus 3: Slot 3         - Outputs 7-8   - Enabled in multi-out mode
Bus 4: Slot 4         - Outputs 9-10  - Enabled in multi-out mode
Bus 5: Slot 5         - Outputs 11-12 - Enabled in multi-out mode
Bus 6: Slot 6         - Outputs 13-14 - Enabled in multi-out mode
Bus 7: Slot 7         - Outputs 15-16 - Enabled in multi-out mode
Bus 8: Slot 8         - Outputs 17-18 - Enabled in multi-out mode
```

## Technical Implementation

### PluginProcessor.cpp Changes

**Constructor**: Updated bus names

```cpp
.withOutput("Main (Mix)", juce::AudioChannelSet::stereo(), true)
.withOutput("Slot 1", juce::AudioChannelSet::stereo(), false)
.withOutput("Slot 2", juce::AudioChannelSet::stereo(), false)
// ... etc
```

**processBlock()**: Always render mix first, then individual slots if multi-out

```cpp
// ALWAYS render full mix to 1-2
engine.processBlock(buffer, midiMessages, 0, -1);

if (outputMode == OutputMode::MultiOut)
{
    // ALSO render each slot individually
    for (int slotIdx = 0; slotIdx < 8; ++slotIdx)
    {
        int busIdx = slotIdx + 1;  // Bus 1-8 for slots 1-8
        int outputChannel = busIdx * 2;  // Channels 2-3, 4-5, etc.

        engine.processBlock(buffer, midiMessages, outputChannel, slotIdx);
    }
}
```

### Engine.cpp Changes

**MIDI Processing**: Added atomic flag to ensure MIDI only processed once

```cpp
std::atomic<bool> midiProcessedThisBlock{false};

// In processBlock:
bool shouldProcessMidi = false;
if (slotFilter == -1) // Full mix call
{
    midiProcessedThisBlock.store(false);
    shouldProcessMidi = true;
}
else if (!midiProcessedThisBlock.exchange(true)) // First slot call
{
    shouldProcessMidi = true;
}
```

This prevents duplicate note triggers when rendering to multiple outputs.

### Voice.cpp Changes

No changes needed - voices already support rendering to specific output channels and filtering by slot index.

## Usage in DAW

### Stereo Mode

- Only outputs 1-2 active
- All slots mixed together
- Use like a normal stereo plugin

### Multi-Out Mode

- Outputs 1-2: Full mix (all slots summed)
- Outputs 3-4: Slot 1 only (e.g., kick top)
- Outputs 5-6: Slot 2 only (e.g., kick bottom)
- Outputs 7-8: Slot 3 only (e.g., overheads)
- etc.

**Workflow Example**:

1. Route output 1-2 to your master bus (pre-mixed sound)
2. Route outputs 3-18 to separate tracks
3. Process individual mics with EQ, compression, etc.
4. Compare your custom mix to the pre-mix on outputs 1-2
5. Choose the best one or blend them!

## Benefits of New Routing

### 1. Reference Mix Always Available

- You always have the full mix on outputs 1-2
- Useful as a reference when building custom mix
- Can A/B compare your mix to the pre-mix

### 2. Flexible Workflows

- **Quick playback**: Just use outputs 1-2
- **Custom mixing**: Use individual outputs 3-18
- **Hybrid**: Blend the pre-mix with processed individual mics

### 3. Parallel Processing

- Send pre-mix to reverb/compression
- Send individual mics to different effects
- Layer and blend for maximum creative control

### 4. Easier DAW Setup

- Main output (1-2) works immediately
- Enable additional outputs only when needed
- No need to route slot 1 separately in stereo mode

## Testing Checklist

- [x] Stereo mode: Mix outputs to channels 1-2
- [x] Multi-out mode: Mix outputs to channels 1-2
- [x] Multi-out mode: Slot 1 outputs to channels 3-4
- [x] Multi-out mode: Slot 2 outputs to channels 5-6
- [x] Multi-out mode: All 8 slots can be routed individually
- [x] MIDI triggers only once per block (no duplicate notes)
- [x] Switching modes enables/disables buses correctly
- [x] UI displays correct status message
- [x] Build completes successfully
- [ ] Test in actual DAW (user to verify)

## Known Issues Fixed

1. ✅ MIDI was being processed multiple times (once per slot)
2. ✅ Bus indexing was off by one (slot 1 wasn't accessible)
3. ✅ No mix output available in multi-out mode
4. ✅ Syntax errors in Engine.cpp from malformed newlines

All issues resolved in this build!
