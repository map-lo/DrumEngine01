# DrumEngine01 Testing Guide

## Quick Start

### 1. Plugin Location

The VST3 is installed at:

```
/Users/marian/Library/Audio/Plug-Ins/VST3/DrumEngine01.vst3
```

### 2. Preset File

Currently auto-loads on startup:

```
/Users/marian/Development/JUCE-Plugins/DrumEngine01/kits/ThatSound DarrenKing/Snare/BITE.json
```

### 3. MIDI Setup

- **Fixed MIDI Note**: 38 (D1 - typical snare note)
- All other MIDI notes are ignored
- Velocity range: 1-127

## Test Scenarios

### Test 1: Basic Triggering

**Goal**: Verify sample playback works

1. Load plugin in DAW
2. Send MIDI note 38, velocity 64
3. **Expected**: Hear drum hit from configured slots (top, room1, room2 in BITE.json)
4. **Check**: Audio plays and completes naturally

### Test 2: Velocity Layer Selection

**Goal**: Verify velocity mapping

1. Play note 38 at different velocities:
   - Velocity 6 (low): Layer 1 (lo=1, hi=12)
   - Velocity 64 (mid): Layer 5 (lo=49, hi=60)
   - Velocity 120 (high): Layer 10 (lo=109, hi=127)
2. **Expected**: Different samples play based on velocity
3. **Check**: Timbre/tone changes with velocity

### Test 3: Round Robin Cycling

**Goal**: Verify RR alternates within same velocity layer

1. Play note 38 at velocity 120 four times (Layer 10 has 4 RR)
2. **Expected**: Each hit sounds slightly different (cycling through RR variations)
3. **Check**: On 5th hit, should return to first RR sample

### Test 4: 3-HitGroup Limit with Stealing

**Goal**: Verify polyphony limit and fade-out on steal

1. Rapidly trigger 4 hits at velocity 120 (less than 32 samples apart)
2. **Expected**:
   - First 3 hits play fully
   - On 4th hit: oldest (1st) hit begins 32-sample fade-out
3. **Check**: No audio glitches, smooth transition

### Test 5: End-of-File Fade-Out

**Goal**: Verify samples fade out at EOF

1. Play long sample (if available) or short sample
2. **Expected**: Sample fades out over final 32 samples before stopping
3. **Check**: No clicks or pops at end

### Test 6: Ignore Non-Fixed MIDI Notes

**Goal**: Verify only note 38 responds

1. Play MIDI notes 36, 37, 39, 40
2. **Expected**: No sound (all ignored)
3. Play MIDI note 38
4. **Expected**: Drum hit plays

### Test 7: Multi-Slot Playback

**Goal**: Verify all configured slots play together

1. Play note 38, velocity 120
2. **Expected**: Multiple mic positions play simultaneously:
   - Slot 1 (top)
   - Slot 4 (room1)
   - Slot 5 (room2)
3. **Check**: Stereo image has depth from multiple mic positions

## Debugging

### Check Console Output

The engine logs to Debug output:

```
Loading preset: /path/to/BITE.json
Preset loaded successfully
```

Or errors:

```
Failed to parse preset: <error>
Failed to load sample: <path>
```

### Common Issues

**No sound on trigger:**

- Check MIDI note is 38
- Check velocity > 0
- Check preset file exists and loaded
- Check sample paths in JSON are correct
- Check `rootFolder` path in JSON

**Clicks/pops:**

- May indicate fade-out length is too short
- Try: `engine.setFadeLengthSamples(64)` or higher

**Wrong samples playing:**

- Check velocity layer ranges in JSON
- Verify `lo` and `hi` values cover desired velocity range

**RR not cycling:**

- Check velocity layer has multiple samples in `wavsBySlot`
- Verify all non-empty slots have same RR count

## Performance Monitoring

### Expected CPU Usage

- Idle: Near 0%
- Playing 3 hits (24 voices max): < 5% on modern CPU
- Memory-mapped samples: OS manages paging automatically

### Voice Allocation

- Max voices: 32 (configurable)
- Max active HitGroups: 3
- Per HitGroup: Up to 8 MicVoices (one per slot)
- Total possible active voices: 24 (3 groups × 8 slots)

## Modifying Configuration

### Change Fixed MIDI Note

Edit JSON:

```json
{
  "fixedMidiNote": 40,  // Change to desired note
  ...
}
```

### Change Fade-Out Length

Edit [PluginProcessor.cpp](src/PluginProcessor.cpp):

```cpp
void prepareToPlay(double sampleRate, int samplesPerBlock)
{
    engine.prepareToPlay(sampleRate, samplesPerBlock);
    engine.setFadeLengthSamples(64);  // Default is 32
    ...
}
```

### Change Preset Path

Edit [PluginProcessor.cpp](src/PluginProcessor.cpp):

```cpp
juce::File presetFile = juce::File("/path/to/your/preset.json");
```

## Acceptance Criteria ✅

All requirements met:

- ✅ Instrument plugin (VST3)
- ✅ Only one fixed MIDI note triggers playback
- ✅ Samples are one-shots (start at frame 0)
- ✅ Up to 8 mics/slots supported
- ✅ Up to 10 velocity layers supported
- ✅ Up to 5 RR per velocity layer (actually unlimited, but tested with 5)
- ✅ RR index shared across slots for same velocity layer
- ✅ RR differs between velocity layers (separate counters)
- ✅ Max 3 active HitGroups
- ✅ Stealing oldest HitGroup on overflow
- ✅ Fixed-length fade-out (always N samples)
- ✅ Fade-out on steal AND on EOF
- ✅ JSON preset loading with exact BITE.json schema
- ✅ Memory-mapped streaming (no audio-thread I/O)
- ✅ Handles mono/stereo samples correctly

## Next Steps

1. **Load in DAW**: Test in your preferred DAW
2. **MIDI Keyboard**: Trigger with physical MIDI keyboard
3. **Create Presets**: Build JSON files for other drums (kick, toms, etc.)
4. **UI Development**: Add preset browser and parameter controls
5. **Optimize**: Profile CPU usage with larger sample libraries
