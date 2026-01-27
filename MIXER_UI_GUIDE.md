# DrumEngine01 Mixer UI Guide

## New UI Layout (900 x 500 pixels)

The plugin now features a **professional mixer interface** with individual controls for each of the 8 potential mic slots.

```
┌──────────────────────────────────────────────────────────────────────────────────────┐
│  DrumEngine01                                                              [Header]   │
├──────────────────────────────────────────────────────────────────────────────────────┤
│                                                                                       │
│                    [ Load Preset... ]                                                │
│               ✓ Preset loaded successfully!                                          │
│                                                                                       │
│  ┌─────┐ ┌─────┐ ┌─────┐ ┌─────┐ ┌─────┐ ┌─────┐ ┌─────┐ ┌─────┐   Preset: BITE   │
│  │ top │ │ bot │ │ oh  │ │room1│ │room2│ │extra│ │extra│ │extra│   Type: snare     │
│  │  │  │ │  │  │ │  │  │ │  │  │ │  │  │ │  1  │ │  2  │ │  3  │   MIDI: 38        │
│  │  │  │ │  │  │ │  │  │ │  │  │ │  │  │ │     │ │     │ │     │   Slots: 8/8      │
│  │  ■  │ │  ■  │ │  ■  │ │  ■  │ │  ■  │ │  ░  │ │  ░  │ │  ░  │   Layers: 10      │
│  │  ■  │ │  ■  │ │  ■  │ │  ■  │ │  ■  │ │  ░  │ │  ░  │ │  ░  │                   │
│  │  ■  │ │  ■  │ │  ■  │ │  ■  │ │  ■  │ │  ░  │ │  ░  │ │  ░  │   Active slots:   │
│  │  ■  │ │  ■  │ │  ■  │ │  ■  │ │  ■  │ │  ░  │ │  ░  │ │  ░  │   1,2,3,4,5       │
│  │  ■  │ │  ■  │ │  ■  │ │  ■  │ │  ■  │ │  ░  │ │  ░  │ │  ░  │   (Slots 6-8 have │
│  │  ■  │ │  ■  │ │  ■  │ │  ■  │ │  ■  │ │  ░  │ │  ░  │ │  ░  │    no samples)    │
│  │  ■  │ │  ■  │ │  ■  │ │  ■  │ │  ■  │ │  ░  │ │  ░  │ │  ░  │                   │
│  │  ■  │ │  ■  │ │  ■  │ │  ■  │ │  ■  │ │  ░  │ │  ░  │ │  ░  │                   │
│  │  ▒  │ │  ▒  │ │  ▒  │ │  ▒  │ │  ▒  │ │  ░  │ │  ░  │ │  ░  │                   │
│  │     │ │     │ │     │ │     │ │     │ │     │ │     │ │     │                   │
│  │ [M] │ │ [M] │ │ [M] │ │ [M] │ │ [M] │ │ [M] │ │ [M] │ │ [M] │                   │
│  │ [S] │ │ [S] │ │ [S] │ │ [S] │ │ [S] │ │ [S] │ │ [S] │ │ [S] │                   │
│  └─────┘ └─────┘ └─────┘ └─────┘ └─────┘ └─────┘ └─────┘ └─────┘                   │
│                                                                                       │
│  Trigger with MIDI Note (default: 38/D1) | Solo: only that slot plays               │
└──────────────────────────────────────────────────────────────────────────────────────┘

Legend:
■ = Active slot fader (fully opaque, enabled)
░ = Inactive slot fader (30% opacity, disabled)
▒ = Fader handle
[M] = Mute button (red when active)
[S] = Solo button (yellow when active)
```

## Per-Slot Controls

Each of the 8 slots has:

### 1. **Name Label** (top)

- Shows slot name from preset (e.g., "top", "bottom", "room1")
- Falls back to slot number if no preset loaded
- **Active slots**: Full brightness, white text
- **Inactive slots**: 30% opacity, grayed out

### 2. **Vertical Volume Slider**

- Range: 0.0 to 1.0 (0% to 100%)
- Default: 1.0 (100%)
- Real-time volume control
- **Active slots**: Fully interactive, responds to mouse
- **Inactive slots**: 30% opacity, disabled (cannot be moved)

### 3. **Mute Button [M]**

- Toggles mute for that slot
- When muted: **Red** background, slot output silenced
- When unmuted: Default gray
- Muting overrides volume slider
- **Active slots**: Clickable
- **Inactive slots**: 30% opacity, disabled

### 4. **Solo Button [S]**

- Toggles solo for that slot
- When soloed: **Yellow** background
- **Solo behavior**: Only soloed slots play (all others silent)
- Multiple slots can be soloed simultaneously
- Soloing overrides mute on other slots
- **Active slots**: Clickable
- **Inactive slots**: 30% opacity, disabled

## Visual Feedback

### Active vs Inactive Slots

**Active Slots** (have samples in preset):

- ✅ Full opacity (100%)
- ✅ Controls enabled and responsive
- ✅ Name shows preset slot name
- ✅ Volume/mute/solo fully functional

**Inactive Slots** (no samples in preset):

- ⚫ 30% opacity (semi-transparent)
- ⚫ Controls disabled (grayed out)
- ⚫ Shows slot number only
- ⚫ Cannot be adjusted (but settings preserved)

### Example: BITE.json Preset

The BITE preset uses slots 1-5:

- **Slot 1 (top)**: Active ✅ - fully opaque
- **Slot 2 (bottom)**: Active ✅ - fully opaque
- **Slot 3 (oh)**: Active ✅ - fully opaque
- **Slot 4 (room1)**: Active ✅ - fully opaque
- **Slot 5 (room2)**: Active ✅ - fully opaque
- **Slot 6 (extra1)**: Inactive ⚫ - 30% opacity
- **Slot 7 (extra2)**: Inactive ⚫ - 30% opacity
- **Slot 8**: Inactive ⚫ - 30% opacity

## Control Behavior

### Volume Slider

- **Mouse drag**: Adjust volume
- **Double-click**: Reset to 100% (1.0)
- **Real-time**: Changes apply immediately to playing voices
- **Range**: 0 dB (1.0) to -∞ dB (0.0)

### Mute Button

- **Click**: Toggle mute on/off
- **Muted state**: Red button, slot produces no sound
- **Effect**: Silences slot completely (regardless of volume)
- **Overrides**: Volume slider ignored when muted

### Solo Button

- **Click**: Toggle solo on/off
- **Solo active**: Yellow button
- **Behavior**:
  - If ANY slot is soloed: Only soloed slots play
  - Multiple solos allowed: All soloed slots play together
  - Unsolo all: Normal behavior restored (all unmuted slots play)

### Interaction Examples

**Scenario 1: Mute the overheads**

1. Click [M] on slot 3 (oh)
2. Button turns red
3. Overhead mic silenced
4. All other slots continue playing

**Scenario 2: Solo just the top mic**

1. Click [S] on slot 1 (top)
2. Button turns yellow
3. Only top mic plays
4. All other slots silenced (even if unmuted)

**Scenario 3: Solo top + room1**

1. Click [S] on slot 1 (top)
2. Click [S] on slot 4 (room1)
3. Both buttons yellow
4. Only slots 1 and 4 play
5. All others silenced

**Scenario 4: Adjust room blend**

1. Drag room1 slider down to 50%
2. Drag room2 slider down to 30%
3. Room mics blend at lower levels
4. Close mics remain at 100%

## Audio Engine Implementation

### Gain Calculation

For each slot, final gain is:

```
effectiveGain = volumeSlider × velocityGain × (mute/solo logic)

Where:
- volumeSlider: 0.0 to 1.0 (from UI)
- velocityGain: from preset velocity curve
- mute/solo logic:
  - If muted: 0.0 (silent)
  - Else if any soloed AND this not soloed: 0.0 (silent)
  - Else: 1.0 (pass through)
```

### Real-Time Updates

- Volume changes apply to **new triggers** immediately
- Currently playing voices retain their starting gain
- Mute/solo checked at trigger time
- No zipper noise or clicks (discrete gain applied per trigger)

## Preset Switching Behavior

When loading a new preset:

- Active slot detection runs automatically
- UI updates to show which slots have samples
- Inactive slots become semi-transparent
- Volume/mute/solo settings **persist** across preset changes
- Example: If you muted slot 1, it stays muted when loading new preset

## Use Cases

### Mixing a Drum Hit

**Goal**: Balance close mics vs room mics

1. Load preset
2. Trigger a few hits to hear the sound
3. Adjust room sliders (4, 5) to taste
4. If too much bleed, lower overhead (3)
5. If too dry, increase rooms

### A/B Comparison

**Goal**: Compare with/without overheads

1. Trigger hit
2. Click [M] on overhead (slot 3)
3. Trigger hit again (no OH)
4. Click [M] again to unmute
5. Trigger hit (with OH)

### Isolating a Mic

**Goal**: Hear only the top mic

1. Click [S] on slot 1 (top)
2. Trigger hits
3. Only top mic audible
4. Click [S] again to unsolo
5. All mics play again

### Creating a Custom Mix

**Goal**: Close mics + subtle room

1. Set slot 1 (top) to 100%
2. Set slot 2 (bottom) to 80%
3. Set slot 3 (oh) to 60%
4. Set slot 4 (room1) to 30%
5. Set slot 5 (room2) to 20%
6. Mute extra1/extra2/extra3 if present

## Technical Details

### Thread Safety

- Slot states stored in processor with CriticalSection lock
- UI reads/writes through processor methods
- Engine receives atomic updates
- No race conditions or audio glitches

### State Persistence

- Slot settings preserved during preset load
- Volume/mute/solo survive plugin reload (if host supports)
- Default state: All unmuted, unsoloed, 100% volume

### Performance

- Minimal CPU overhead (simple multiplication)
- No DSP processing, just gain scaling
- Efficient for real-time use

## Future Enhancements

Potential additions:

1. **VU meters**: Visual level indication per slot
2. **Pan controls**: Stereo positioning per slot
3. **Group mute/solo**: All rooms, all close, etc.
4. **Preset-specific defaults**: Save mix with preset
5. **MIDI CC mapping**: Control volumes via MIDI
6. **Automation**: DAW automation of slot parameters
