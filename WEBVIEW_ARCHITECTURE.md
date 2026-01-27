# DrumEngine01 WebView Architecture

## Overview

DrumEngine01 now uses **JUCE WebBrowserComponent** for its user interface instead of native JUCE UI components. This provides several advantages:

- **Modern Web Technologies**: Use HTML, CSS, and JavaScript for UI development
- **Easier Customization**: Modify the UI without recompiling C++ code
- **Responsive Design**: Better layout control with CSS Grid/Flexbox
- **Rich UI Possibilities**: Access to the full web ecosystem for styling and interactions

## Architecture

### Components

1. **Web Interface** (`src/ui/`)
   - `index.html` - HTML structure
   - `styles.css` - CSS styling
   - `app.js` - JavaScript UI logic and C++ communication

2. **C++ Backend** (`src/PluginEditor.*`)
   - `PluginEditor.h` - Header with WebView component
   - `PluginEditor.cpp` - WebView setup and JavaScript bridge

3. **Build System** (`CMakeLists.txt`)
   - Embeds web files as binary resources
   - Enables `JUCE_WEB_BROWSER=1`

### Communication Flow

```
┌─────────────────────────────────────────────────────────┐
│                    Web UI (JavaScript)                   │
│  ┌────────────────────────────────────────────────────┐ │
│  │  User interacts with HTML controls                  │ │
│  │  (buttons, sliders, dropdowns)                      │ │
│  └──────────────────┬─────────────────────────────────┘ │
│                     │                                     │
│                     ▼                                     │
│  ┌────────────────────────────────────────────────────┐ │
│  │  JavaScript sends message via window.juce.postMessage│ │
│  └──────────────────┬─────────────────────────────────┘ │
└────────────────────┼──────────────────────────────────┘
                     │ JSON message
                     ▼
┌─────────────────────────────────────────────────────────┐
│                  C++ Backend (JUCE)                      │
│  ┌────────────────────────────────────────────────────┐ │
│  │  handleMessageFromWebView()                         │ │
│  │  - Parses JSON                                      │ │
│  │  - Calls appropriate processor methods              │ │
│  └──────────────────┬─────────────────────────────────┘ │
│                     │                                     │
│                     ▼                                     │
│  ┌────────────────────────────────────────────────────┐ │
│  │  Audio Processor                                    │ │
│  │  - Updates engine state                             │ │
│  │  - Modifies parameters                              │ │
│  └──────────────────┬─────────────────────────────────┘ │
│                     │                                     │
│                     ▼                                     │
│  ┌────────────────────────────────────────────────────┐ │
│  │  sendStateUpdateToWebView()                         │ │
│  │  - Gathers current state                            │ │
│  │  - Converts to JSON                                 │ │
│  │  - Calls JavaScript function via evaluateJavascript │ │
│  └──────────────────┬─────────────────────────────────┘ │
└────────────────────┼──────────────────────────────────┘
                     │ JSON state
                     ▼
┌─────────────────────────────────────────────────────────┐
│                    Web UI (JavaScript)                   │
│  ┌────────────────────────────────────────────────────┐ │
│  │  window.updateStateFromCpp(state)                   │ │
│  │  - Updates UI controls                              │ │
│  │  - Shows current values                             │ │
│  └────────────────────────────────────────────────────┘ │
└─────────────────────────────────────────────────────────┘
```

## JavaScript to C++ API

### Sending Messages from JavaScript

All messages from JavaScript to C++ use this format:

```javascript
window.juce.postMessage(
  JSON.stringify({
    action: "actionName",
    param1: value1,
    param2: value2,
  }),
);
```

### Supported Actions

#### `requestPresetList`

Request the list of available presets.

```javascript
{
  action: "requestPresetList";
}
```

#### `requestUpdate`

Request a full state update from C++.

```javascript
{
  action: "requestUpdate";
}
```

#### `loadPresetByIndex`

Load a preset by its index in the preset list.

```javascript
{
    action: "loadPresetByIndex",
    index: 0  // Zero-based index
}
```

#### `loadNextPreset`

Load the next preset in the list (wraps around).

```javascript
{
  action: "loadNextPreset";
}
```

#### `loadPrevPreset`

Load the previous preset in the list (wraps around).

```javascript
{
  action: "loadPrevPreset";
}
```

#### `browseForPreset`

Open native file browser to select a preset file.

```javascript
{
  action: "browseForPreset";
}
```

#### `setOutputMode`

Change the output routing mode.

```javascript
{
    action: "setOutputMode",
    mode: "stereo" | "multiout"
}
```

#### `setVelocityToVolume`

Enable/disable velocity-to-volume mapping.

```javascript
{
    action: "setVelocityToVolume",
    enabled: true | false
}
```

#### `setSlotVolume`

Set the volume for a specific slot.

```javascript
{
    action: "setSlotVolume",
    slot: 0,      // Slot index (0-7)
    volume: 0.75  // Volume (0.0 - 1.0)
}
```

#### `setSlotMuted`

Mute/unmute a specific slot.

```javascript
{
    action: "setSlotMuted",
    slot: 0,     // Slot index (0-7)
    muted: true  // true or false
}
```

#### `setSlotSoloed`

Solo/unsolo a specific slot.

```javascript
{
    action: "setSlotSoloed",
    slot: 0,      // Slot index (0-7)
    soloed: true  // true or false
}
```

## C++ to JavaScript API

### Receiving Updates in JavaScript

C++ calls JavaScript functions directly using `evaluateJavascript()`:

#### `window.updateStateFromCpp(state)`

Called periodically (every 100ms) with the current state.

**State Object Structure:**

```javascript
{
    // Status display
    statusMessage: "Ready - Preset Loaded",
    statusIsError: false,
    statusIsWarning: false,

    // Preset information
    presetInfo: {
        isPresetLoaded: true,
        presetName: "SNARE_01",
        instrumentType: "snare",
        fixedMidiNote: 38,
        slotCount: 8,
        layerCount: 10,
        useVelocityToVolume: false,
        slotNames: ["top", "bottom", "oh", "room1", "room2", "extra1", "extra2", "extra3"]
    },

    // Slot states (array of 8)
    slots: [
        {
            isActive: true,
            name: "top",
            volume: 1.0,
            muted: false,
            soloed: false
        },
        // ... 7 more slots
    ],

    // Output configuration
    outputMode: "stereo" | "multiout",

    // Current preset selection
    currentPresetIndex: 0  // -1 if none selected
}
```

#### `window.updatePresetListFromCpp(presets)`

Called once at startup with the available presets.

**Presets Array Structure:**

```javascript
[
  {
    displayName: "ThatSound DarrenKing / KICK_01",
    category: "ThatSound DarrenKing",
  },
  // ... more presets
];
```

## Modifying the Web UI

### HTML Structure (`src/ui/index.html`)

The HTML is organized into:

- **Header**: Title, preset browser, navigation buttons, output selector
- **Content**: Mixer section (8 channel strips) and info panel
- **Channel Strips**: Each has label, fader, mute, and solo buttons

To modify the layout, edit the HTML structure. The JavaScript automatically finds elements by ID or class name.

### CSS Styling (`src/ui/styles.css`)

The CSS uses:

- Modern flexbox/grid layouts
- CSS variables for consistent theming
- Smooth transitions for state changes
- Custom scrollbar styling

**Key Classes:**

- `.active` - Applied to active channel strips
- `.error` - Applied to status for error messages
- `.warning` - Applied to status for warnings

To change colors, fonts, or layouts, edit the CSS. No C++ recompilation needed!

### JavaScript Logic (`src/ui/app.js`)

The JavaScript is organized as a class (`DrumEngineUI`) with:

- `initializeElements()` - Finds DOM elements
- `attachEventListeners()` - Sets up UI event handlers
- `sendMessage()` - Sends commands to C++
- `updateState()` - Updates UI from C++ state
- `updatePresetList()` - Populates preset dropdown

**Adding New Features:**

1. **Add UI element** in HTML
2. **Style it** in CSS
3. **Add event listener** in `attachEventListeners()`
4. **Send message** to C++ via `sendMessage()`
5. **Handle message** in C++ `handleMessageFromWebView()`
6. **Update UI** by including data in `sendStateUpdateToWebView()`

## Building

After modifying web files:

```bash
cd build
cmake ..
make
```

CMake automatically:

1. Reads the web files from `src/ui/`
2. Converts them to binary data
3. Embeds them in the plugin binary
4. Makes them accessible via `extern` declarations

The web files are now part of the plugin - no external files needed at runtime!

## Platform Support

### macOS

Uses native WebKit (WKWebView). No additional dependencies.

### Windows

Uses WebView2 (Edge Chromium). Requires:

- Windows 10/11
- WebView2 Runtime (usually pre-installed)

### Linux

Uses WebKitGTK. May require:

```bash
sudo apt-get install libwebkit2gtk-4.0-dev
```

## Benefits of WebView Approach

1. **Separation of Concerns**: UI logic separate from audio processing
2. **Rapid Iteration**: Change UI without full recompilation
3. **Modern Tooling**: Use browser DevTools for debugging
4. **Familiar Technologies**: HTML/CSS/JS instead of JUCE components
5. **Cross-Platform**: Same web code works on all platforms
6. **Rich Styling**: Full power of CSS for visual design

## Debugging

### Enable Browser DevTools (macOS)

```cpp
// In PluginEditor.cpp constructor
webView = std::make_unique<juce::WebBrowserComponent>(
    juce::WebBrowserComponent::Options{}
        .withOptionsFrom(juce::WebBrowserComponent::Options{}
            .withDeveloperExtrasEnabled())  // Add this
);
```

Then right-click in the WebView and select "Inspect Element".

### Console Logging

JavaScript console messages appear in:

- **macOS**: Safari Web Inspector
- **Windows**: Edge DevTools
- **Linux**: WebKit Inspector

```javascript
console.log("Debug info:", data);
```

### Message Debugging

The JavaScript code logs all messages when not running in JUCE:

```javascript
sendMessage(action, data = {}) {
    const message = { action, ...data };

    if (window.juce && window.juce.postMessage) {
        window.juce.postMessage(JSON.stringify(message));
    } else {
        console.log('Message to C++:', message);  // Debug output
    }
}
```

## Performance Considerations

- **Update Frequency**: Currently 100ms timer. Adjust if needed.
- **JSON Overhead**: Minimal for this use case
- **Memory**: WebView adds ~10-20MB to plugin memory footprint
- **CPU**: Negligible when UI is static; minimal during updates

## Future Enhancements

Possible improvements:

- **Hot Reload**: Reload web files during development without plugin restart
- **Theme Support**: Multiple color schemes selectable at runtime
- **Advanced Visualizations**: Waveform display, spectrum analyzer
- **Responsive Sizing**: Support for different window sizes
- **Accessibility**: ARIA labels and keyboard navigation
- **Animations**: Smooth transitions for level meters and state changes

## Troubleshooting

### WebView doesn't appear

- Check `JUCE_WEB_BROWSER=1` in CMakeLists.txt
- Verify binary data is linked: `AudioPluginData`
- Check platform has WebView support

### JavaScript errors

- Enable DevTools and check console
- Verify JSON message format
- Check for typos in action names

### UI doesn't update

- Verify timer is running (`startTimer(100)`)
- Check `sendStateUpdateToWebView()` is called
- Verify JavaScript functions exist on window object

### Styling issues

- Check CSS file is embedded correctly
- Verify CSS selectors match HTML structure
- Test in browser first (open HTML file directly)
