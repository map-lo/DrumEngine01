# DrumEngine01 UI Documentation

## Current UI Features

The plugin now has a **functional UI** with the following features:

### Visual Layout (500 x 400 pixels)

```
┌─────────────────────────────────────────────────┐
│  DrumEngine01                          [Header] │
├─────────────────────────────────────────────────┤
│                                                 │
│         [ Load Preset... ]  [Button]           │
│                                                 │
│    ✓ Preset loaded successfully!  [Status]     │
│                                                 │
│   Preset: BITE                                  │
│   Type: snare                                   │
│   Fixed MIDI Note: 38                           │
│   Slots: 8                                      │
│   Velocity Layers: 10                           │
│                                                 │
│   Mic Slots:                                    │
│     1: top                                      │
│     2: bottom                                   │
│     3: oh                                       │
│     4: room1                                    │
│     5: room2                                    │
│     6: extra1                                   │
│     7: extra2                                   │
│     8: extra3                                   │
│                                                 │
│                                                 │
│   Trigger with MIDI Note (default: 38/D1)      │
│   Velocity: 1-127 selects velocity layer        │
│   Max 3 concurrent hits, RR cycles per layer    │
│                                                 │
└─────────────────────────────────────────────────┘
```

### UI Components

1. **Header Section** (top 60px)
   - Dark gradient background
   - "DrumEngine01" title in white, large bold font
   - Separator line below

2. **Load Preset Button**
   - Opens file browser dialog
   - Filters for `*.json` files
   - Starts from user's home directory
   - Asynchronous file selection (non-blocking)

3. **Status Label** (color-coded)
   - 🟢 **Green**: "✓ Preset loaded successfully!"
   - 🔴 **Red**: "✗ Failed: [error message]"
   - 🟠 **Orange**: "No Preset - Click Load Button" (initial state)
   - Updates in real-time

4. **Preset Info Display**
   - Shows detailed information about loaded preset:
     - Preset name (from filename)
     - Instrument type (from JSON)
     - Fixed MIDI note number
     - Number of mic slots
     - Number of velocity layers
     - List of all mic slot names
   - Placeholder text when no preset loaded

5. **Instructions Label** (bottom)
   - Gray text with usage instructions
   - Explains MIDI triggering behavior
   - Describes velocity layer selection
   - Notes about polyphony and RR cycling

### Color Scheme

- **Background**: Dark gray (`#1e1e1e`)
- **Header**: Gradient (`#2d2d30` → `#1e1e1e`)
- **Text (primary)**: White
- **Text (secondary)**: Light gray
- **Separator**: Medium gray (`#3e3e42`)
- **Status Success**: Light green
- **Status Error**: Red
- **Status Warning**: Orange

### Feedback Mechanism

#### Before Loading Preset:

- Status shows: "No Preset - Click Load Button" (orange)
- Info area shows: "No preset loaded\n\nClick 'Load Preset...' to load a JSON preset file"

#### During File Selection:

- File browser dialog appears
- User can navigate and select `.json` file
- Or cancel without loading

#### After Successful Load:

- Status changes to: "✓ Preset loaded successfully!" (green)
- All preset info populates immediately:
  - Preset name, type, MIDI note
  - Slot count, layer count
  - Full list of mic slot names
- Updates persist until new preset loaded

#### After Failed Load:

- Status changes to: "✗ Failed: [specific error message]" (red)
- Error message includes:
  - "Invalid JSON" → parsing error
  - "Missing samples" → file not found
  - "Schema validation failed" → invalid structure
  - "RR count mismatch" → inconsistent round robins
- Previous preset info remains displayed (not cleared)

### Real-Time Updates

- **Timer-based refresh**: 100ms interval
- Status and preset info auto-update from engine
- No manual refresh needed
- Thread-safe data access (uses CriticalSection locks)

## User Workflow

### Loading Your First Preset

1. **Open the plugin** in your DAW
2. **Click "Load Preset..."** button
3. **Navigate** to your preset JSON file (e.g., `BITE.json`)
4. **Select** the file
5. **Watch status** turn green with "✓ Preset loaded successfully!"
6. **Review preset info** to verify:
   - Correct instrument type
   - Expected MIDI note
   - Number of slots/layers matches expectations
7. **Ready to play** - send MIDI to trigger

### Verifying Load Success

✅ **Success Indicators:**

- Green status message
- Preset name appears
- All info fields populated
- Slot names listed correctly
- No error messages

❌ **Failure Indicators:**

- Red status message
- Specific error description
- Info area may be empty or show previous preset
- Check console/debug output for details

### Troubleshooting UI

**Problem**: Button doesn't respond

- **Solution**: Check if plugin window has focus

**Problem**: Status stuck on "No Preset"

- **Solution**: File selection was cancelled or file invalid

**Problem**: "Failed: Invalid JSON"

- **Solution**: Check JSON syntax with validator, ensure proper formatting

**Problem**: "Failed: Schema validation"

- **Solution**: Verify RR counts match across slots, check velocity layer ranges

**Problem**: Info shows but status is red

- **Solution**: Partial load - some samples missing, check file paths in JSON

## API for UI Integration

### PluginProcessor Methods

```cpp
// Load preset and get result
juce::Result loadPresetFromFile(const juce::File& presetFile);

// Get current preset information
PresetInfo getPresetInfo() const;
```

### PresetInfo Structure

```cpp
struct PresetInfo
{
    bool isPresetLoaded;           // true if valid preset loaded
    juce::String presetName;       // filename without extension
    juce::String instrumentType;    // "snare", "kick", etc.
    int fixedMidiNote;             // 0-127
    int slotCount;                 // 1-8
    int layerCount;                // 1-10
    juce::StringArray slotNames;   // ["top", "bottom", ...]
};
```

## Future UI Enhancements

Potential additions (not yet implemented):

1. **Preset Library Browser**
   - Dropdown or list view of available presets
   - Quick preset switching without file browser

2. **Parameter Controls**
   - Fade length slider
   - Per-slot volume controls
   - Velocity curve adjustment

3. **Visual Feedback**
   - Level meters per slot
   - Active voice count display
   - RR position indicator

4. **MIDI Learn**
   - Click to assign different MIDI note
   - Multiple note support

5. **Sample Waveform Display**
   - Visual representation of loaded samples
   - RR variation visualization

6. **Dark/Light Theme Toggle**
   - User preference for UI colors

7. **Preset Save/Export**
   - Create new presets from UI
   - Export current configuration

## Technical Implementation Notes

- Uses JUCE's modern async FileChooser API
- Thread-safe preset info access with CriticalSection
- Timer-based UI updates (non-blocking)
- Persistent FileChooser object for async callbacks
- Font system uses modern FontOptions (JUCE 7+)
- Dark theme matches modern DAW aesthetics
