# Plugin Distribution Guide for macOS

## Problem Summary

When distributing plugins to other Macs, they fail to load because:

1. **Pro Tools can't see AAX** - AAX signing may be incomplete or plugins aren't properly installed
2. **Ableton/Logic sees VST3/AU but can't open** - Missing Hardened Runtime, entitlements, or notarization

## Root Cause

macOS Gatekeeper requires distributed plugins to have:

- ✅ **Valid Developer ID signature** (not ad-hoc)
- ✅ **Hardened Runtime enabled**
- ✅ **Proper entitlements file**
- ✅ **Notarization** (for macOS 10.15+)

## What Was Fixed

### 1. Created Entitlements File (`plugin.entitlements`)

This file grants your plugin necessary permissions for audio processing while maintaining Hardened Runtime security.

### 2. Updated CMakeLists.txt

Added proper code signing configuration:

- Enabled Hardened Runtime
- Applied entitlements
- Set Developer ID and Team ID
- Added timestamp and runtime options

### 3. Updated Build Scripts

- **build_plugins.py**: Now uses entitlements file when signing
- **build_config_plugins_dev.py**: Enabled proper signing (disabled ad-hoc)

### 4. Updated Build Configs

Changed dev config to use proper Developer ID signing instead of ad-hoc.

## Distribution Workflow

### For Testing (Quick Method - No Notarization)

1. **Build with proper signing:**

   ```bash
   python3 build_plugins.py --release
   ```

2. **Create a ZIP of signed plugins:**

   ```bash
   cd build/release/DrumEngine01_artefacts/Release
   zip -r ~/Desktop/DrumEngine01-plugins.zip VST3/ AU/ AAX/
   ```

3. **Send to your friend and instruct them to:**
   - Unzip the file
   - Copy plugins to system folders:

     ```bash
     # VST3
     sudo cp -R VST3/DrumEngine01.vst3 /Library/Audio/Plug-Ins/VST3/

     # AU
     sudo cp -R AU/DrumEngine01.component /Library/Audio/Plug-Ins/Components/

     # AAX
     sudo cp -R AAX/DrumEngine01.aaxplugin "/Library/Application Support/Avid/Audio/Plug-Ins/"
     ```

   - Run this command to clear Gatekeeper quarantine:
     ```bash
     sudo xattr -r -d com.apple.quarantine /Library/Audio/Plug-Ins/VST3/DrumEngine01.vst3
     sudo xattr -r -d com.apple.quarantine /Library/Audio/Plug-Ins/Components/DrumEngine01.component
     sudo xattr -r -d com.apple.quarantine "/Library/Application Support/Avid/Audio/Plug-Ins/DrumEngine01.aaxplugin"
     ```

### For Production Distribution (Recommended - With Notarization)

1. **Set up notarization credentials:**
   - Store credentials in Keychain:
     ```bash
     xcrun notarytool store-credentials DrumEngine01Notary \
       --apple-id "your-apple-id@email.com" \
       --team-id "4V59UK4A32" \
       --password "app-specific-password"
     ```

2. **Build with notarization enabled:**

   ```bash
   python3 build_plugins.py --release
   ```

   This will:
   - Build plugins
   - Sign with Developer ID + Hardened Runtime
   - Sign AAX with PACE
   - Create installer PKG
   - Sign installer
   - **Notarize installer** (uploads to Apple, waits for approval)
   - Staple notarization ticket

3. **Distribute the notarized PKG:**
   - File will be in: `dist/installer-plugins/DrumEngine01-[version]-b[build]-Plugins.pkg`
   - Users can simply double-click to install
   - No quarantine removal needed

## Verification Commands

After building, verify your plugins are properly signed:

```bash
# Check VST3 signature and entitlements
codesign -dv --verbose=4 build/release/DrumEngine01_artefacts/Release/VST3/DrumEngine01.vst3

# Check hardened runtime
codesign -d --entitlements :- build/release/DrumEngine01_artefacts/Release/VST3/DrumEngine01.vst3

# Check AU signature
codesign -dv --verbose=4 build/release/DrumEngine01_artefacts/Release/AU/DrumEngine01.component

# Check AAX signature (should show PACE signing)
codesign -dv --verbose=4 build/release/DrumEngine01_artefacts/Release/AAX/DrumEngine01.aaxplugin
```

Expected output should include:

- `Signature=Developer ID Application: Marian Plosch (4V59UK4A32)`
- `flags=0x10000(runtime)` (Hardened Runtime enabled)
- Entitlements listed

## Troubleshooting

### "Plugin can't be opened" in DAW

**Cause:** Missing Hardened Runtime or entitlements  
**Solution:** Rebuild with the updated CMakeLists.txt (already done)

### Pro Tools can't see AAX

**Causes:**

1. AAX not properly signed with PACE wraptool
2. AAX not in correct system location
3. Pro Tools cache needs clearing

**Solutions:**

```bash
# Verify AAX location
ls -la "/Library/Application Support/Avid/Audio/Plug-Ins/"

# Clear Pro Tools cache
rm -rf ~/Library/Preferences/Avid/Pro\ Tools/Plug-In\ Settings/*
```

### "Damaged or incomplete" error

**Cause:** Gatekeeper quarantine on unsigned/improperly signed plugin  
**Solution:** Remove quarantine attribute:

```bash
sudo xattr -r -d com.apple.quarantine /path/to/plugin
```

Or better: Use notarized installer (no quarantine removal needed)

### Notarization fails

**Common issues:**

1. Missing Hardened Runtime ✅ (Fixed in CMakeLists.txt)
2. Missing entitlements ✅ (Fixed with plugin.entitlements)
3. Invalid code signature - check Developer ID certificate is valid
4. Wrong Team ID - verify `4V59UK4A32` matches your Apple Developer Team ID

**Check notarization log:**

```bash
xcrun notarytool log <submission-id> --keychain-profile DrumEngine01Notary
```

## Key Differences: Dev vs Release

| Setting          | Dev Build       | Release Build |
| ---------------- | --------------- | ------------- |
| Plugin Name      | DrumEngine01Dev | DrumEngine01  |
| Plugin Code      | Den0            | Den1          |
| Signing          | Developer ID    | Developer ID  |
| Hardened Runtime | ✅ YES          | ✅ YES        |
| Entitlements     | ✅ YES          | ✅ YES        |
| Notarization     | ❌ NO           | ✅ YES        |
| Installer        | ❌ NO           | ✅ YES        |

## Next Steps for Your Friend

### Option A: Quick Test (No Installer)

Send them the ZIP and the manual install commands above.

### Option B: Production Ready (Recommended)

1. Build with notarization: `python3 build_plugins.py --release`
2. Send them the PKG installer from `dist/installer-plugins/`
3. They double-click to install - it just works!

## Important Notes

- **Ad-hoc signing** (`-`) only works on the Mac that built the plugin
- **Developer ID signing** is required for distribution to other Macs
- **Notarization** eliminates all Gatekeeper warnings and quarantine issues
- AAX plugins must also be signed with PACE wraptool (separate from macOS signing)
