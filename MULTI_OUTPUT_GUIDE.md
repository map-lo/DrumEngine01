# DrumEngine01 Multi-Output Guide

## Overview

DrumEngine01 now supports **two output modes**:

1. **Stereo Mode** (default): All 8 slots are mixed to a single stereo output
2. **Multi-Out Mode**: Each slot has its own dedicated stereo output pair

This allows maximum flexibility in your DAW for processing individual mic channels separately.

## Output Configuration

### Stereo Mode

- **Output routing**: All slots → Main stereo output (channels 1-2)
- **Use case**: Simple playback, pre-mixed sound
- **DAW setup**: Single stereo track

### Multi-Out Mode

- **Output routing**:
  - **Mix (all slots)** → Output 1-2 (Main)
  - Slot 1 (top) → Output 3-4
  - Slot 2 (bottom) → Output 5-6
  - Slot 3 (oh) → Output 7-8
  - Slot 4 (room1) → Output 9-10
  - Slot 5 (room2) → Output 11-12
  - Slot 6 (extra1) → Output 13-14
  - Slot 7 (extra2) → Output 15-16
  - Slot 8 (extra3) → Output 17-18
- **Use case**: Get both the full mix AND individual mics for parallel processing
- **DAW setup**: 9 stereo outputs (1 for mix + 8 for individual mics)

## How to Switch Modes

### In the Plugin UI

1. Locate the **"Output:"** dropdown in the top section (below the Load Preset button)
2. Select your desired mode:
   - **"Stereo"** - All slots mixed together
   - **"Multi-Out (8x Stereo)"** - Separate outputs per slot

The status label will update to confirm the mode change.

### Status Messages

**Stereo Mode:**

```
Stereo mode: Mix on outputs 1-2
```

**Multi-Out Mode:**

```
Multi-Out: Mix→1-2, Slot1→3-4, Slot2→5-6, etc.
```

## DAW Configuration Examples

### Ableton Live

**Stereo Mode:**

1. Add plugin to MIDI track
2. Single stereo output automatically routed

**Multi-Out Mode:**

1. Add plugin to MIDI track
2. Track automatically expands to show 8 output routing dropdowns
3. Create 8 audio tracks
4. Route each plugin output to a different audio track:
   - "1-DrumEngine01" → Audio Track 1 (Kick)
   - "2-DrumEngine01" → Audio Track 2 (Snare Bottom)
   - "3-DrumEngine01" → Audio Track 3 (Overheads)
   - etc.
5. Process each mic separately with EQ, compression, reverb

### Logic Pro

**Stereo Mode:**

1. Add plugin to Software Instrument track
2. Default stereo output

**Multi-Out Mode:**

1. Add plugin as "Multi-Output" instrument
2. In Mixer, expand the track (disclosure triangle)
3. You'll see 8 auxiliary channels (one per slot)
4. Each aux receives a separate mic slot
5. Process each aux independently

### Reaper

**Stereo Mode:**

1. Add plugin to track
2. Outputs to master stereo

**Multi-Out Mode:**

1. Add plugin to track
2. Right-click track → "I/O" → Enable all 8 output pairs
3. Create routing to separate tracks:
   - Track 1: receives plugin output 1/2
   - Track 2: receives plugin output 3/4
   - etc.
4. Use "Track grouping" for organized mixing

### Cubase/Nuendo

**Stereo Mode:**

1. Add to Instrument Track
2. Stereo output

**Multi-Out Mode:**

1. Load as "Rack Instrument" or "Multi-Timbral" instrument
2. Activate desired outputs in the rack (Output 1-16)
3. Create audio channels for each output pair
4. Route and process independently

## Workflow Examples

### Example 1: Quick Playback (Stereo Mode)

**Goal**: Play the drum sound quickly without complex routing

1. Load DrumEngine01 on MIDI track
2. Ensure output mode is set to **"Stereo"**
3. Load a preset (e.g., BITE.json)
4. Play MIDI notes
5. Adjust volume/mute/solo in plugin UI
6. **Result**: Pre-mixed sound on master bus

### Example 2: Custom Mix (Multi-Out Mode)

**Goal**: Create a custom mix with individual processing per mic

1. Load DrumEngine01 on MIDI track
2. Switch output mode to **"Multi-Out (8x Stereo)"**
3. Load a preset (e.g., BITE.json with 5 mics)
4. In DAW, route the 5 active outputs to separate tracks:
   - Track 1: "Kick Top" (Output 1-2)
   - Track 2: "Kick Bottom" (Output 3-4)
   - Track 3: "Overheads" (Output 5-6)
   - Track 4: "Room 1" (Output 7-8)
   - Track 5: "Room 2" (Output 9-10)
5. Process each track:
   - Top: EQ (boost 3-5kHz for click), compressor (fast attack)
   - Bottom: EQ (boost 60-80Hz for body), gate
   - OH: EQ (HPF @80Hz, boost 10kHz), reverb
   - Rooms: Compression, reverb, blend to taste
6. **Result**: Professional, customized drum sound

### Example 3: A/B Comparison

**Goal**: Compare multi-out vs pre-mixed sound

1. Start in **Stereo mode**, trigger hits
2. Print/bounce to audio track
3. Switch to **Multi-Out mode**
4. Create custom mix on separate tracks
5. Print/bounce custom mix
6. Compare the two versions
7. **Result**: Hear the difference between pre-mixed and custom

### Example 4: Parallel Processing

**Goal**: Add aggressive compression to rooms only

1. Set output mode to **Multi-Out**
2. Route room outputs (7-8, 9-10) to a bus
3. Duplicate room bus (parallel)
4. On parallel bus: extreme compression (10:1 ratio, very low threshold)
5. Blend original rooms with crushed rooms
6. **Result**: Huge, powerful room sound without affecting close mics

## Technical Details

### Audio Engine Behavior

#### Stereo Mode

- MIDI events trigger voices for all active slots
- All voices render to channels 0-1 (main stereo output)
- Volume, mute, solo controls still function per-slot
- Final mix is sum of all unmuted/unsoloed slots

#### Multi-Out Mode

- MIDI events trigger voices for all active slots (once)
- Each slot's voices render to their dedicated output pair
- Volume, mute, solo controls apply per-slot
- Each output pair contains only that slot's audio
- No inter-slot mixing

### Performance Considerations

**CPU Usage:**

- Both modes have similar CPU usage
- Multi-out adds minimal overhead (routing only)
- Voice allocation and rendering cost is the same

**Latency:**

- No additional latency in either mode
- Plugin-reported latency is 0 samples

**Memory:**

- Multi-out mode uses slightly more memory for buffer management
- Difference is negligible (a few KB per buffer)

### Bus Configuration

**VST3 Bus Layout:**

- **Main output (Bus 0)**: Always enabled, stereo
- **Slot 2 output (Bus 1)**: Enabled in multi-out mode, stereo
- **Slot 3 output (Bus 2)**: Enabled in multi-out mode, stereo
- **Slot 4 output (Bus 3)**: Enabled in multi-out mode, stereo
- **Slot 5 output (Bus 4)**: Enabled in multi-out mode, stereo
- **Slot 6 output (Bus 5)**: Enabled in multi-out mode, stereo
- **Slot 7 output (Bus 6)**: Enabled in multi-out mode, stereo
- **Slot 8 output (Bus 7)**: Enabled in multi-out mode, stereo

When switching from Multi-Out to Stereo, buses 1-7 are disabled automatically. When switching back to Multi-Out, they are re-enabled.

### Host Compatibility

The plugin notifies the host when the bus configuration changes using:

```cpp
updateHostDisplay(ChangeDetails().withNonParameterStateChanged(true));
```

Most modern DAWs will handle this gracefully, but some older hosts may require you to reload the plugin or track.

## Mixer Controls + Multi-Out

The plugin's **internal mixer controls** (volume, mute, solo) work in both modes:

### Stereo Mode

- Controls affect the mix before summing to main output
- Muting a slot removes it from the stereo mix
- Soloing a slot silences all other slots in the mix
- Volume adjusts the slot's contribution to the mix

### Multi-Out Mode

- Controls affect each output pair individually
- Muting a slot silences that output pair
- Soloing a slot only affects the "solo" output pair (others still output)
- Volume adjusts the gain on that output pair

**Important**: In Multi-Out mode, your DAW's mixer gives you additional control beyond the plugin's internal mixer. You can:

- Mute/solo at the DAW track level
- Apply per-track effects
- Route to buses and groups
- Automate track faders independently

## Use Cases

### When to Use Stereo Mode

✅ **Quick playback**: Just want to hear the sound  
✅ **Simple arrangements**: Limited track count  
✅ **Pre-production**: Demoing ideas quickly  
✅ **Live performance**: Minimal CPU overhead  
✅ **MIDI mockups**: Not final mix

### When to Use Multi-Out Mode

✅ **Final mixing**: Need individual control per mic  
✅ **Creative processing**: Different effects per mic  
✅ **Parallel compression**: Apply to specific mics  
✅ **Automation**: Automate individual mic levels  
✅ **Stem exports**: Export separate mic stems  
✅ **Advanced mixing**: Full professional workflow

## Troubleshooting

### "I switched to Multi-Out but only hear one output"

**Solution**: Check your DAW's routing. In Multi-Out mode, you need to manually route each plugin output to a separate track or bus.

### "Some outputs are silent in Multi-Out mode"

**Check**:

1. Is the preset using that slot? (Inactive slots shown at 30% opacity in UI)
2. Is the slot muted in the plugin UI?
3. Is the DAW track receiving that output muted/soloed?
4. Is the output bus enabled in your DAW?

### "Switching modes causes audio glitches"

**Solution**: This is normal. The plugin rebuilds its bus configuration when switching modes. Some hosts may briefly stop audio. If persistent, try:

1. Stop playback before switching modes
2. Reload the plugin
3. Check host compatibility

### "My DAW doesn't show all 8 outputs"

**Possible causes**:

1. DAW track is in "Stereo" mode, not "Multi-Out" mode
2. Need to enable multi-output in plugin settings (DAW-specific)
3. DAW version doesn't support VST3 multi-output

**Solutions**:

- Ableton: Plugin automatically goes multi-out
- Logic: Choose "Multi-Output" when adding instrument
- Reaper: Enable outputs in track I/O panel
- Cubase: Load as Rack Instrument, activate outputs

## Best Practices

### Mixing Workflow

1. **Start in Stereo mode** during composition/arrangement
2. **Switch to Multi-Out** when ready to mix
3. **Set up DAW routing** before making mix decisions
4. **Use plugin's solo** to identify which mic is which
5. **Gain stage** each output in DAW first
6. **Apply processing** per mic as needed
7. **Blend room mics** to taste
8. **Group tracks** for easier organization

### Performance Tips

- Use Multi-Out only when needed (saves routing complexity)
- Freeze/bounce tracks when not adjusting individual mics
- Consider printing stems from Multi-Out, then mixing stems
- In live situations, use Stereo mode for lower CPU

### Organization

**Naming Convention** (Multi-Out):

- Track 1: "Drum - Top"
- Track 2: "Drum - Bottom"
- Track 3: "Drum - OH"
- Track 4: "Drum - Room1"
- Track 5: "Drum - Room2"
- Etc.

**Color Coding**:

- Close mics: One color (e.g., red)
- Overheads: Another color (e.g., blue)
- Room mics: Another color (e.g., green)

**Grouping**:

- Create "DRUM" folder/group containing all mic tracks
- Create "DRUM CLOSE" subgroup for top + bottom
- Create "DRUM ROOM" subgroup for room mics

## Summary

Multi-output support gives you **maximum flexibility**:

- **Stereo Mode**: Fast, simple, pre-mixed
- **Multi-Out Mode**: Professional, customizable, per-mic control

Switch between modes anytime in the plugin UI. Your DAW handles the rest!
