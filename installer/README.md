# DrumEngine01 Installer

This directory contains the macOS installer build system for DrumEngine01.

## Overview

The installer system creates a native macOS `.pkg` installer that:

- Allows users to choose which plugin formats to install (VST3, VST, AU)
- Installs plugins to their standard system locations
- Copies presets and samples to `~/Documents/DrumEngine01/`

## Prerequisites

1. **Build the plugins** - Rebuild your project with the new formats enabled:

   ```bash
   cd build
   cmake .. -DCMAKE_BUILD_TYPE=Release
   cmake --build . --config Release
   ```

2. **Package presets and samples** - Run the packaging script:
   ```bash
   cd generators
   python package_presets_for_installer.py
   ```

## Building the Installer

Run the installer build script:

```bash
cd installer
./build_installer.sh
```

The installer will be created at: `installer_output/DrumEngine01-Installer.pkg`

## Installer Components

The installer contains these selectable components:

- **VST3 Plugin** - Installs to `/Library/Audio/Plug-Ins/VST3/`
- **Audio Unit** - Installs to `/Library/Audio/Plug-Ins/Components/`
- **Presets & Samples** (Optional) - Installs to `~/Documents/DrumEngine01/`

All components are optional and can be selected during installation.

## Custom Installation Location for Presets/Samples

The standard macOS .pkg installer doesn't support custom directory selection during installation.
Presets and samples are installed to `~/Documents/DrumEngine01/` by default.

**To use a custom location:**

1. Install normally (or skip the content installation)
2. Manually copy the `dist/presets/` and `dist/samples/` folders to your preferred location
3. The plugin will still look in `~/Documents/DrumEngine01/presets/` for presets
4. Each preset's JSON file contains a `rootFolder` path that points to its samples

**Alternative approach:**

- Create a symbolic link: `ln -s /your/custom/path ~/Documents/DrumEngine01`

```
installer/
├── build_installer.sh      # Main build script
├── distribution.xml        # Installer UI definition
├── postinstall            # Script to copy presets/samples to user Documents
├── welcome.html           # Installer welcome screen
├── conclusion.html        # Installer completion screen
└── README.md             # This file
```

## Testing the Installer

To test installation via command line:

```bash
sudo installer -pkg installer_output/DrumEngine01-Installer.pkg -target /
```

Or double-click `DrumEngine01-Installer.pkg` to test the GUI installer.

## Adding AAX Support (Future)

To add AAX support:

1. Download and install the AAX SDK from Avid
2. Add to `CMakeLists.txt`:
   ```cmake
   juce_set_aax_sdk_path("/path/to/AAX_SDK")
   ```
3. Update the `FORMATS` line to include `AAX`:
   ```cmake
   FORMATS VST3 VST AU AAX
   ```
4. Update `distribution.xml` to add AAX choice
5. Update `build_installer.sh` to package AAX component

Note: AAX plugins must be signed by PACE iLok for distribution.

## Plugin Installation Locations

- **VST3**: `/Library/Audio/Plug-Ins/VST3/DrumEngine01.vst3`
- **VST**: `/Library/Audio/Plug-Ins/VST/DrumEngine01.vst`
- **AU**: `/Library/Audio/Plug-Ins/Components/DrumEngine01.component`
- **Presets**: `~/Documents/DrumEngine01/presets/`
- **Samples**: `~/Documents/DrumEngine01/samples/`

## Troubleshooting

**"No plugins found to package"**

- Make sure you've built the project first
- Check that the build succeeded in `build/DrumEngine01_artefacts/`

**"dist/presets or dist/samples not found"**

- Run `python generators/package_presets_for_installer.py` first

**Installer doesn't show all formats**

- Only formats that were successfully built will be included
- Check build output for errors

**Plugins don't appear in DAW**

- Some DAWs need to be restarted after installation
- Try rescanning plugins in your DAW preferences
- Check that the plugins were copied to the correct locations
