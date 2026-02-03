# Quick Start: Fix Distribution Issue

## What Was the Problem?

Your plugins were failing on your friend's Mac because:

- **VST3/AU**: Missing Hardened Runtime + entitlements
- **AAX**: Possibly not seeing due to PACE signing or installation issues
- **Ad-hoc signing** in dev builds (only works on your Mac)

## What Was Fixed?

### ✅ Files Created/Modified:

1. **plugin.entitlements** - Security entitlements for Hardened Runtime
2. **CMakeLists.txt** - Added Hardened Runtime and code signing configuration
3. **build_config_plugins_dev.py** - Enabled proper signing (disabled ad-hoc)
4. **build_plugins.py** - Updated to use entitlements file
5. **sign_existing_plugins.sh** - Quick script to sign already-built plugins
6. **create_distribution.sh** - Creates distributable ZIP package
7. **DISTRIBUTION_GUIDE.md** - Complete documentation

## Quick Fix for Existing Build

You have already-built plugins that just need proper signing:

```bash
# 1. Sign your existing release plugins
./sign_existing_plugins.sh

# 2. Verify signing worked
codesign -dv build/release/DrumEngine01_artefacts/Release/VST3/DrumEngine01.vst3

# 3. Create distribution package
./create_distribution.sh

# 4. Test ZIP contains: DrumEngine01-0.0.5-Release.zip
```

The ZIP will include:

- Signed VST3, AU, AAX plugins
- INSTALL.txt with instructions
- install.sh for easy installation

## Send to Your Friend

Send them the ZIP file and tell them to:

1. Unzip the file
2. Open Terminal in the unzipped folder
3. Run: `sudo bash install.sh`
4. Enter password when prompted
5. Clear quarantine (if still having issues):
   ```bash
   sudo xattr -r -d com.apple.quarantine /Library/Audio/Plug-Ins/VST3/DrumEngine01.vst3
   sudo xattr -r -d com.apple.quarantine /Library/Audio/Plug-Ins/Components/DrumEngine01.component
   sudo xattr -r -d com.apple.quarantine "/Library/Application Support/Avid/Audio/Plug-Ins/DrumEngine01.aaxplugin"
   ```
6. Rescan plugins in DAW

## For Future Builds

### Quick Test Build (No Notarization):

```bash
python3 build_plugins.py --release --skip-notarization
./create_distribution.sh
```

### Production Build (With Notarization):

```bash
# First time: Store notarization credentials
xcrun notarytool store-credentials DrumEngine01Notary \
  --apple-id "your-apple-id@email.com" \
  --team-id "4V59UK4A32" \
  --password "app-specific-password"

# Then build with notarization
python3 build_plugins.py --release
```

This will:

- Build plugins with Hardened Runtime
- Sign with Developer ID
- Sign AAX with PACE
- Create installer PKG
- **Notarize with Apple** (eliminates all Gatekeeper warnings!)
- Staple notarization ticket

## Verification

Check if plugins are properly signed:

```bash
# Should show: Signature=Developer ID Application: Marian Plosch
# Should show: flags=0x10000(runtime)
codesign -dv --verbose=4 build/release/DrumEngine01_artefacts/Release/VST3/DrumEngine01.vst3

# Check entitlements
codesign -d --entitlements :- build/release/DrumEngine01_artefacts/Release/VST3/DrumEngine01.vst3
```

## Troubleshooting

### "Plugin can't be opened" - Still happening?

1. **Verify Hardened Runtime is enabled:**

   ```bash
   codesign -dv build/release/.../DrumEngine01.vst3 2>&1 | grep "flags=0x10000"
   ```

   Should show `flags=0x10000(runtime)`

2. **Clear quarantine on friend's Mac:**

   ```bash
   sudo xattr -r -d com.apple.quarantine /Library/Audio/Plug-Ins/VST3/DrumEngine01.vst3
   ```

3. **Check friend's Mac security:**
   System Settings → Privacy & Security → Allow apps from App Store and identified developers

### Pro Tools can't see AAX?

1. **Verify AAX is signed with PACE:**

   ```bash
   python3 sign_aax.py --build-type=release
   ```

2. **Check AAX location:**

   ```bash
   ls -la "/Library/Application Support/Avid/Audio/Plug-Ins/"
   ```

3. **Clear Pro Tools cache:**
   ```bash
   rm -rf ~/Library/Preferences/Avid/Pro\ Tools/Plug-In\ Settings/*
   ```

## Key Differences Now

| Before                 | After                       |
| ---------------------- | --------------------------- |
| ❌ Ad-hoc signing      | ✅ Developer ID signing     |
| ❌ No Hardened Runtime | ✅ Hardened Runtime enabled |
| ❌ No entitlements     | ✅ Entitlements file        |
| ❌ No notarization     | ✅ Can notarize (optional)  |
| ❌ Fails on other Macs | ✅ Works everywhere         |

## Next Steps

1. **Immediate**: Run `./sign_existing_plugins.sh` and `./create_distribution.sh`
2. **Test**: Send ZIP to your friend
3. **Future**: Use `python3 build_plugins.py --release` for production builds with notarization

See **DISTRIBUTION_GUIDE.md** for complete documentation.
