# Building a Release

This guide covers building DrumEngine01 from scratch for distribution.

## Version Management

**The version is defined once in [CMakeLists.txt](CMakeLists.txt):**

```cmake
project(DRUM_ENGINE_01 VERSION 0.0.1)
```

This single definition:

- ✅ Creates C++ preprocessor defines (`DRUMENGINE_VERSION="0.0.1"`, `DRUMENGINE_VERSION_MAJOR=0`, etc.)
- ✅ Automatically updates Python scripts via [build_config.py](build_config.py)
- ✅ Names the installer `DrumEngine01-0.0.1-Installer.pkg`
- ✅ Available in plugin code for UI display

**To release a new version:** Just update the VERSION in CMakeLists.txt and rebuild.

See [VERSIONING.md](VERSIONING.md) for details on accessing version in your code.

## Prerequisites

- macOS 10.13 or later
- Xcode Command Line Tools installed
- CMake 3.22 or later
- Python 3.x
- Source presets in `presets/`
- Sample libraries accessible at paths referenced in preset JSON files

## Build Steps

### 1. Configure CMake (First Time Only)

```bash
cd build
cmake .. -DCMAKE_BUILD_TYPE=Release
```

### 2. Build Plugins

```bash
cd build
cmake --build . --config Release
```

This builds:

- `build/DrumEngine01_artefacts/Release/VST3/DrumEngine01.vst3`
- `build/DrumEngine01_artefacts/Release/AU/DrumEngine01.component`

Plugins are automatically installed to:

- `/Library/Audio/Plug-Ins/VST3/`
- `/Library/Audio/Plug-Ins/Components/`

### 3. Package Factory Content

Package all presets and samples:

```bash
cd generators
python package_presets_for_installer.py
```

Or for testing with limited presets:

```bash
python package_presets_for_installer.py --limit 2
```

This creates:

- `dist/factory-content/presets/` - Preset JSON files with updated paths
- `dist/factory-content/samples/` - All sample WAV files organized by preset

### 4. Build Installer

```bash
cd installer
./build_installer.sh
```

This creates the final installer at:

- `dist/installer/DrumEngine01-Installer.pkg`

## Output Structure

After building, the `dist/` folder contains:

```
dist/
├── factory-content/
│   ├── presets/     # Packaged preset JSON files
│   └── samples/     # Packaged sample WAV files
└── installer/
    ├── DrumEngine01-Installer.pkg  # Final installer (distribute this)
    └── packages/                    # Component packages
        ├── vst3.pkg
        ├── au.pkg
        └── content.pkg
```

## Distribution

Distribute the file:

- `dist/installer/DrumEngine01-Installer.pkg`

Users double-click to install:

- VST3 and/or AU plugins (user selectable)
- Presets and samples to `~/Documents/DrumEngine01/` (optional, custom location supported)

## Clean Build

To rebuild everything from scratch:

```bash
# Clean build artifacts
rm -rf build/DrumEngine01_artefacts

# Clean packaged content
rm -rf dist

# Reconfigure and rebuild
cd build
cmake .. -DCMAKE_BUILD_TYPE=Release
cmake --build . --config Release

# Repackage and build installer
cd ../generators
python package_presets_for_installer.py
cd ../installer
./build_installer.sh
```

## Testing Builds

For faster iteration during testing:

1. **Build with limited presets:**

   ```bash
   python generators/package_presets_for_installer.py --limit 2
   ```

   This creates a much smaller installer (~140MB vs full size).

2. **Test installer without installing:**

   ```bash
   # View installer info
   pkgutil --payload-files dist/installer/DrumEngine01-Installer.pkg

   # Expand installer to inspect contents
   pkgutil --expand dist/installer/DrumEngine01-Installer.pkg /tmp/test-pkg
   ```

3. **Test installation:**
   ```bash
   sudo installer -pkg dist/installer/DrumEngine01-Installer.pkg -target /
   ```

## Troubleshooting

**CMake configuration fails:**

- Ensure Xcode Command Line Tools are installed: `xcode-select --install`
- Check CMake version: `cmake --version` (requires 3.22+)

**Preset packaging fails:**

- Verify `presets/` exists and contains `.json` files
- Check that sample paths in JSON files are accessible
- Run with verbose errors: presets that fail show error messages

**Installer build fails:**

- Ensure plugins were built successfully (check `build/DrumEngine01_artefacts/Release/`)
- Verify factory content was packaged (check `dist/factory-content/`)
- Make sure script is executable: `chmod +x installer/build_installer.sh`

**Installer too large:**

- Use `--limit N` option when packaging presets
- Consider splitting into multiple installer packages
