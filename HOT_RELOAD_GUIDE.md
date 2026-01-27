# Hot Reloading & Tailwind CSS Setup

## Overview

The DrumEngine01 plugin now supports hot reloading of UI files during development and uses Tailwind CSS for styling.

## Development Workflow

### Hot Reloading (Debug Builds Only)

In debug builds, the plugin loads UI files directly from disk instead of using embedded resources. This means you can:

1. **Make changes to UI files** (`index.html`, `styles.css`, `app.js`)
2. **Simply refresh** the plugin window or close and reopen it
3. **See changes immediately** without rebuilding the C++ code

The plugin automatically detects whether it's a debug build via the `JUCE_DEBUG` preprocessor flag:

- **Debug Mode**: Loads files from `src/ui/` directory using `file://` URLs
- **Release Mode**: Uses embedded BinaryData resources

### Tailwind CSS Workflow

The project uses Tailwind CSS for styling with a build process:

1. **Start the Tailwind watcher** (run once in a terminal):

   ```bash
   cd src/ui
   npm run watch:css
   ```

2. **Edit `index.html`** with Tailwind utility classes

3. **Tailwind automatically rebuilds** `styles.css` when it detects changes

4. **Refresh the plugin** to see your changes

### Complete Development Setup

**Terminal 1** - Tailwind CSS watcher:

```bash
cd /Users/marian/Development/JUCE-Plugins/DrumEngine01/src/ui
npm run watch:css
```

**Terminal 2** - Build the plugin (only needed once or when C++ code changes):

```bash
cd /Users/marian/Development/JUCE-Plugins/DrumEngine01/build
cmake --build . --config Debug
```

**Then:**

- Open your DAW and load the plugin
- Make changes to `index.html`, `app.js`, or Tailwind styles
- Close and reopen the plugin window to see changes

## File Structure

```
src/ui/
├── package.json           # npm config with Tailwind scripts
├── tailwind.config.js     # Tailwind configuration
├── input.css             # Tailwind input (directives)
├── styles.css            # Generated output (don't edit directly)
├── index.html            # Main UI structure with Tailwind classes
└── app.js                # JavaScript logic
```

## Custom Tailwind Theme

The project includes custom colors in `tailwind.config.js`:

```javascript
colors: {
  'drum-dark': '#1a1a1a',      // Dark background
  'drum-darker': '#121212',    // Darker background
  'drum-light': '#2a2a2a',     // Light panels
  'drum-border': '#333',       // Border color
  'drum-accent': '#4a9eff',    // Accent blue
  'drum-accent-hover': '#6ab0ff', // Hover state
  'drum-muted': '#666',        // Muted text
}
```

Use these in your HTML like: `bg-drum-dark`, `text-drum-accent`, etc.

## Building for Release

When building for release, the plugin automatically embeds all UI files:

```bash
cd build
cmake --build . --config Release
```

The `setupWebViewForProduction()` method:

1. Loads HTML, CSS, and JS from BinaryData
2. Inlines CSS and JS into the HTML
3. Serves via resource provider
4. No external file dependencies

## Troubleshooting

### Tailwind not detecting changes

- Check that `npm run watch:css` is running
- Verify the `content` array in `tailwind.config.js` includes your files
- Make sure you're using Tailwind utility classes in your HTML

### Hot reload not working

- Confirm you built with `--config Debug` (not Release)
- Check that `useLiveReload` is true in PluginEditor.h (should be automatic in debug)
- Verify the file path in `getUIDirectory()` is correct

### Plugin not loading

- Check the console output in your DAW
- Verify all files exist in `src/ui/`
- Ensure the file:// path is accessible

## npm Scripts

```json
"build:css": "tailwindcss -i ./input.css -o ./styles.css --minify"
"watch:css": "tailwindcss -i ./input.css -o ./styles.css --watch"
```

- **watch:css**: Runs continuously, rebuilds on file changes
- **build:css**: One-time build with minification (for release)

## Technical Implementation

### Hot Reloading

The implementation uses conditional compilation:

```cpp
#ifdef JUCE_DEBUG
    bool useLiveReload = true;
#else
    bool useLiveReload = false;
#endif
```

In `setupWebViewForDevelopment()`:

- Locates UI directory using `__FILE__` macro
- Navigates directly to the HTML file on disk
- WebView automatically reloads external CSS/JS references

### Production Build

In `setupWebViewForProduction()`:

- Creates self-contained HTML with inlined resources
- Uses resource provider for serving content
- No external file dependencies

This ensures the plugin works identically in both development and release, with the only difference being where files are loaded from.
