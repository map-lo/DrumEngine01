# Velocity to Volume Mapping Feature

## Overview

The DrumEngine01 plugin now supports velocity-to-volume mapping as an optional feature that can be enabled per preset or controlled in real-time via the UI.

## Feature Details

### Default Behavior

By default, MIDI note velocity does **not** affect the output volume. The plugin will always play samples at full volume (1.0 gain) regardless of the velocity value received.

### Enabling Velocity to Volume

When enabled, MIDI note velocity (1-127) will modulate the output volume of all triggered samples according to the preset's `velToVol` configuration.

## How to Use

### 1. In Preset JSON Files

Add the `useVelocityToVolume` field to your preset JSON file:

```json
{
  "schemaVersion": 1,
  "instrumentType": "snare",
  "useVelocityToVolume": true,
  "slotNames": [...],
  "rootFolder": "...",
  "velocityLayers": [...],
  "velToVol": {
    "amount": 100.0,
    "curveName": "linear"
  }
}
```

**Field Details:**

- `useVelocityToVolume` (boolean, optional, default: `false`)
  - `true`: Velocity affects volume
  - `false`: Velocity does not affect volume (samples always play at full volume)

### 2. In the Plugin UI

The UI includes a "Vel->Vol" toggle button in the header section:

- Located next to the "Output" selector
- Shows current state (on/off) based on the loaded preset
- Can be toggled in real-time while playing
- State is displayed in the preset info panel

### 3. How the Velocity Curve Works

When `useVelocityToVolume` is enabled, the velocity-to-gain conversion follows this algorithm:

1. **Normalize velocity**: `vel01 = (velocity - 1) / 126.0`
2. **Apply curve shaping**:
   - `"linear"`: No shaping, uses normalized velocity as-is
   - `"soft"`: `shaped = vel01^0.5` (more gain at lower velocities)
3. **Apply amount**: `finalGain = shaped * amount + (1.0 - amount)`
   - `amount` is typically 100.0 (fully applies velocity)
   - Lower amounts blend between velocity-sensitive and constant gain

When `useVelocityToVolume` is disabled, the `velocityToGain()` function always returns `1.0` regardless of the velocity value or velToVol configuration.

## Technical Implementation

### Code Changes

1. **PresetSchema** (`src/engine/PresetSchema.h/cpp`)
   - Added `useVelocityToVolume` boolean field
   - Parser reads optional `useVelocityToVolume` from JSON

2. **RuntimePreset** (`src/engine/RuntimePreset.h/cpp`)
   - Added `useVelocityToVolume` flag
   - Added getter/setter methods
   - Modified `velocityToGain()` to check flag and return 1.0 when disabled

3. **Engine** (`src/engine/Engine.h/cpp`)
   - Added `setUseVelocityToVolume()` and `getUseVelocityToVolume()` methods
   - Methods forward to active RuntimePreset

4. **AudioPluginAudioProcessor** (`src/PluginProcessor.h/cpp`)
   - Added `useVelocityToVolume` to PresetInfo struct
   - Added getter/setter methods that sync with Engine
   - Tracks state in preset info for UI access

5. **AudioPluginAudioProcessorEditor** (`src/PluginEditor.h/cpp`)
   - Added `velocityToggle` (ToggleButton) and `velocityToggleLabel` components
   - Added `onVelocityToggleClicked()` callback
   - UI syncs toggle state with preset info
   - Displays "Vel->Vol: On/Off" in preset info panel

## Example Use Cases

### 1. Live Performance Drums

Enable velocity-to-volume for expressive playing where dynamics matter:

```json
{
  "useVelocityToVolume": true,
  "velToVol": {
    "amount": 100.0,
    "curveName": "soft"
  }
}
```

### 2. Programmed/Sample Replacement

Disable velocity-to-volume for consistent triggering where you control volume via your DAW:

```json
{
  "useVelocityToVolume": false
}
```

### 3. Hybrid Approach

- Start with velocity disabled in the preset
- Enable it in the UI when you want to add dynamics
- Toggle it off again when you need consistent triggering

## Notes

- The velocity setting is **per-preset** - each preset can have its own default
- The UI toggle **overrides** the preset's default setting in real-time
- The current state is shown in the preset info panel
- When a preset is loaded, the UI toggle reflects the preset's `useVelocityToVolume` value
- The setting is **not** saved with plugin state (it resets to preset default on reload)

## Future Enhancements

Potential improvements for future versions:

- Save velocity toggle state in plugin state (persist across sessions)
- Per-slot velocity control (apply velocity only to certain mics)
- More curve options (exponential, S-curve, etc.)
- Visual velocity response indicator
- MIDI learn for velocity toggle
