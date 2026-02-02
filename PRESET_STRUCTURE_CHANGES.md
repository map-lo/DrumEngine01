# Preset Structure Migration to .preset Folders

## Overview

The preset structure has been migrated from a split JSON+samples approach to a unified `.preset` folder convention, similar to Superior Drummer/SSD. This simplifies preset creation, distribution, and reduces maintenance overhead.

## What Changed

### Old Structure (Before)

```
presets/
  factory01/
    ThatSound DarrenKing/
      Kick/
        BOWSER.json          # Contains rootFolder pointing to external samples
        BULLET.json

samples/                     # Separate directory hierarchy
  factory01/
    ThatSound DarrenKing/
      Kick/
        BOWSER/
          DRY/
            BOWSER DRY V01.wav
```

**Problems:**

- Required copying JSON and samples separately (two operations)
- JSON files contained absolute `rootFolder` paths that needed rewriting for distribution
- Risk of path mismatches between JSON and samples

### New Structure (After)

```
presets/
  factory01/
    ThatSound DarrenKing/
      Kick/
        BOWSER.preset/       # Self-contained preset folder
          preset.json        # No rootFolder field (auto-resolved)
          DRY/
            BOWSER DRY V01.wav
          OVERHEADS/
            BOWSER OH V01.wav
          ROOM 1/
            BOWSER RM1 V01.wav
```

**Benefits:**

- Single-copy operation to add/distribute presets
- `.preset` extension makes presets instantly recognizable
- No path rewriting needed - `rootFolder` auto-resolves to parent directory
- Self-documenting structure

## Implementation Details

### 1. PresetSchema Changes ([PresetSchema.cpp](src/engine/PresetSchema.cpp))

- Made `rootFolder` field optional in JSON
- Auto-resolves `rootFolder` to JSON file's parent directory when empty
- Maintains backward compatibility if `rootFolder` is present

```cpp
// In parseFromFile():
auto result = parseJSON(json, outSchema);
if (result.failed())
    return result;

// Auto-resolve rootFolder to parent directory if empty
if (outSchema.rootFolder.isEmpty())
{
    outSchema.rootFolder = file.getParentDirectory().getFullPathName();
}
```

### 2. Preset Scanning Changes ([PluginEditor.cpp](src/PluginEditor.cpp))

- Scans for folders ending in `.preset` instead of `.json` files
- Looks for `preset.json` inside each `.preset` folder
- Uses folder name (minus `.preset` extension) as display name
- Does not recurse into `.preset` folders (treats them as leaf nodes)

```cpp
// Separates .preset folders from regular subfolders:
if (file.getFileName().endsWithIgnoreCase(".preset"))
    presetFolders.add(file);
else
    subFolders.add(file);

// Looks for preset.json inside:
juce::File jsonFile = presetFolder.getChildFile("preset.json");
```

### 3. Generator Scripts Updated

All generator scripts now create `.preset` folder structure:

- `generate_ts_kicks.py`
- `generate_ts_snares.py`
- `generate_ts_toms.py`
- `generate_ts_cymbals.py`
- `generate_yurtrock_snares.py`

Changes:

- Create `{PresetName}.preset/` folder
- Save as `preset.json` inside the folder
- Omit `rootFolder` field from JSON
- Copy samples directly into preset folder structure

### 4. Packaging Script Simplified ([package_presets_for_installer.py](generators/package_presets_for_installer.py))

Dramatically simplified from ~244 lines to ~170 lines:

- Finds `.preset` folders instead of `.json` files
- Copies entire `.preset` folders wholesale using `shutil.copytree`
- No JSON parsing or rewriting needed
- No separate samples directory

### 5. Migration Script ([migrate_to_preset_folders.py](generators/migrate_to_preset_folders.py))

Created migration script to convert existing presets:

- Finds all `.json` files (excluding those already in `.preset` folders)
- Creates `{PresetName}.preset/` folder
- Copies samples from `rootFolder` to preset folder
- Saves as `preset.json` without `rootFolder` field
- Removes old `.json` file

**Migration completed:** 78 presets successfully migrated

## Usage Examples

### Creating a New Preset Manually

1. Create folder: `MyPreset.preset/`
2. Add `preset.json` inside (no `rootFolder` field needed)
3. Add sample subfolders: `DRY/`, `OVERHEADS/`, etc.
4. Copy to `~/Documents/DrumEngine01/presets/{Category}/`

### Using Generator Scripts

```bash
# Generate ThatSound kicks as .preset folders
python3 generators/generate_ts_kicks.py

# Output: presets/ThatSound DarrenKing/Kick/BOWSER.preset/
```

### Packaging for Installer

```bash
# Package all .preset folders for distribution
python3 generators/package_presets_for_installer.py

# Output: dist/factory-content/presets/ (ready for installer)
```

## File Format

### preset.json Structure

```json
{
  "schemaVersion": 1,
  "instrumentType": "kick",
  "slotNames": [
    "top",
    "bottom",
    "oh",
    "room1",
    "room2",
    "extra1",
    "extra2",
    "extra3"
  ],
  "velocityLayers": [
    {
      "index": 1,
      "lo": 1,
      "hi": 12,
      "wavsBySlot": {
        "1": ["DRY/BOWSER DRY V01.wav"],
        "3": ["OVERHEADS/BOWSER OH V01.wav"],
        "4": ["ROOM 1/BOWSER RM1 V01.wav"]
      }
    }
  ],
  "velToVol": {
    "amount": 70,
    "curve": { "type": "builtin", "name": "soft" }
  }
}
```

**Key points:**

- No `rootFolder` field - automatically resolved
- All WAV paths relative to preset folder root
- Sample subfolder structure library-specific (no convention enforced)

## Performance Impact

### Scanning Performance

- Minimal impact: scanning checks for `.preset` extension instead of `.json`
- Still only reads metadata (JSON), not samples
- No increase in file I/O operations

### Loading Performance

- Identical to previous implementation
- Samples still memory-mapped and cached
- No performance regression

## Backward Compatibility

**Breaking change:** Old preset structure no longer supported.

All existing presets have been migrated. Future development uses only `.preset` folder structure.

## Benefits Summary

1. **Simplified Workflow:** Single folder copy to add presets
2. **Self-Contained:** Everything for a preset lives in one place
3. **Easier Distribution:** No path rewriting or complex packaging logic
4. **Discoverable:** `.preset` extension clearly identifies preset folders
5. **Reduced Errors:** No risk of JSON/sample path mismatches
6. **Cleaner Code:** Simpler packaging and scanning logic

## Migration Date

February 1, 2026 - All 78 factory presets migrated successfully.
