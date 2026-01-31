# AAX Build and Signing Setup

## Overview

DrumEngine01 now supports AAX plugin format with PACE Eden SDK signing. Dev and release builds can coexist using different plugin names and codes.

## Plugin Versions

| Build Type | Plugin Name     | Plugin Code | CMake Build Type |
| ---------- | --------------- | ----------- | ---------------- |
| Dev        | DrumEngine01Dev | Den0        | Debug            |
| Release    | DrumEngine01    | Den1        | Release          |

Both versions can be installed simultaneously in Pro Tools.

## Build Commands

### Development Build

```bash
python build.py --dev
```

Builds DrumEngine01Dev (Den0) with Debug configuration.

### Release Build

```bash
python build.py --release
```

Builds DrumEngine01 (Den1) with Release configuration.

### Skip AAX Signing (Development)

```bash
python build.py --dev --skip-signing
```

Useful when testing without PACE credentials configured.

## PACE Configuration Setup

### 1. Copy the Template

```bash
cp pace_config_template.py pace_config.py
```

### 2. Fill in Your PACE Credentials

Edit `pace_config.py` with your credentials from PACE Eden SDK:

```python
# Path to wraptool executable
WRAPTOOL_PATH = "/Applications/PACEAntiPiracy/Eden/Fusion/Current/bin/wraptool"

# PACE iLok account credentials
ACCOUNT_ID = "your-ilok-account-id"
ACCOUNT_PASSWORD = "your-ilok-password"

# Wrap Configuration GUID (from iLok Developer portal)
WCGUID = "your-wrap-configuration-guid"

# Signing Identity ID (from iLok Developer portal)
SIGNID = "your-signing-identity-id"
```

**Note:** `pace_config.py` is git-ignored and will not be committed.

### 3. Getting PACE Credentials

If you don't have PACE credentials yet:

1. **Sign up as AAX Developer**
   - Visit: https://developer.avid.com/aax/
   - Register your developer account

2. **Request Signing Tools**
   - Email: audiosdk@avid.com
   - Subject: "PACE Eden Signing Tools Request"
   - Include:
     - Plugin overview with screen recording (with audio)
     - Company name
     - Admin full name
     - Telephone number

3. **PACE Will Contact You**
   - PACE Anti-Piracy will provide signing tools
   - You'll get access to iLok Developer portal
   - Generate your wcguid from the portal

## Build Configuration Files

### build_config_dev.py

- Development build settings
- `CLEAN_BUILD = False` (faster iteration)
- `BUILD_INSTALLER = False` (skip installer)
- `PRESET_LIMIT = 4` (limited presets for testing)
- `SIGN_AAX = True` (sign AAX for Pro Tools testing)

### build_config_release.py

- Release build settings
- `CLEAN_BUILD = True` (clean builds)
- `BUILD_INSTALLER = True` (create installer)
- `PRESET_LIMIT = None` (all presets)
- `SIGN_AAX = True` (sign AAX for distribution)

## File Structure

```
DrumEngine01/
├── CMakeLists.txt              # Conditional naming based on CMAKE_BUILD_TYPE
├── build.py                    # Main build script with --dev/--release flags
├── sign_aax.py                 # AAX signing with PACE wraptool
├── pace_config_template.py     # Template for PACE credentials
├── pace_config.py              # Your PACE credentials (git-ignored)
├── build_config_dev.py         # Dev build configuration
├── build_config_release.py     # Release build configuration
└── installer/
    └── build_installer.sh      # Installer with dev/release naming
```

## Plugin Output Locations

### Dev Build (Debug)

- VST3: `build/DrumEngine01_artefacts/Debug/VST3/DrumEngine01Dev.vst3`
- AU: `build/DrumEngine01_artefacts/Debug/AU/DrumEngine01Dev.component`
- AAX: `build/DrumEngine01_artefacts/Debug/AAX/DrumEngine01Dev.aaxplugin`

### Release Build (Release)

- VST3: `build/DrumEngine01_artefacts/Release/VST3/DrumEngine01.vst3`
- AU: `build/DrumEngine01_artefacts/Release/AU/DrumEngine01.component`
- AAX: `build/DrumEngine01_artefacts/Release/AAX/DrumEngine01.aaxplugin`

## Installer Output

- Dev: `dist/installer/DrumEngine01Dev-0.0.2-Installer.pkg`
- Release: `dist/installer/DrumEngine01-0.0.2-Installer.pkg`

## AAX Installation Path

AAX plugins are installed to:

```
/Library/Application Support/Avid/Audio/Plug-Ins/
```

This is the standard location for Pro Tools AAX plugins on macOS.

## Testing AAX Plugins

### With Pro Tools Developer

- Download Pro Tools Developer (allows unsigned AAX)
- Request from devauth@avid.com
- Test without signing using `--skip-signing`

### With Commercial Pro Tools

- AAX plugins MUST be signed with PACE
- Set up `pace_config.py` with your credentials
- Build with signing enabled (default)

## Troubleshooting

### "PACE Configuration Not Found"

- Copy `pace_config_template.py` to `pace_config.py`
- Fill in your PACE credentials
- Or use `--skip-signing` for development

### "wraptool not found"

- Check `WRAPTOOL_PATH` in `pace_config.py`
- Verify PACE Eden SDK is installed
- Default path: `/Applications/PACEAntiPiracy/Eden/Fusion/Current/bin/wraptool`

### AAX Plugin Won't Load in Pro Tools

- Ensure plugin is signed (check build output)
- Verify iLok USB dongle is connected (if required)
- Check Pro Tools recognizes your signing identity

### Both Plugins Can't Coexist

- Verify different plugin codes are being used
- Dev: Den0, Release: Den1
- Check CMakeLists.txt conditional logic
- Rebuild with clean build

## Important Notes

### PACE Signing ≠ Copy Protection

- PACE signing is required for Pro Tools compatibility
- It does NOT add copy protection or licensing
- End users do NOT need iLok accounts to use your plugin
- Think of it like Apple's code signing requirement

### Plugin Codes Must Be Unique

- Each plugin variant needs a unique 4-character code
- Format: One uppercase, three lowercase (e.g., Den0, Den1)
- This allows DAWs to distinguish between dev/release versions

### Version Management

- Version is defined once in `CMakeLists.txt`
- Automatically flows to all configs and installers
- Current version: 0.0.2

## References

- JUCE AAX Documentation: `modules/JUCE/docs/JUCE AAX Format.md`
- Avid Developer Portal: https://developer.avid.com/aax/
- PACE Eden SDK: Provided after Avid approval
