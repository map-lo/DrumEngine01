# Version Management

## Single Source of Truth

The version number is defined once in [CMakeLists.txt](CMakeLists.txt):

```cmake
project(DRUM_ENGINE_01 VERSION 0.0.1)
```

## Build Number

The build number is stored in build_number.txt at the repository root and is
auto-incremented every time build.py runs. The current value is exposed as:

- DRUMENGINE_BUILD_NUMBER (environment variable for installer scripts)
- config.BUILD_NUMBER (inside build.py)

## How It Flows

```
CMakeLists.txt (VERSION 0.0.1)
    ├─> C++ Code (preprocessor defines)
    ├─> build_config.py (parsed automatically)
    └─> Installer name (DrumEngine01-0.0.1-Installer.pkg)
```

## Accessing Version in C++ Code

The version is automatically available as preprocessor defines:

```cpp
// Full version string
DRUMENGINE_VERSION  // "0.0.1"

// Individual components
DRUMENGINE_VERSION_MAJOR  // 0
DRUMENGINE_VERSION_MINOR  // 0
DRUMENGINE_VERSION_PATCH  // 1
```

### Example: Display Version in Plugin UI

```cpp
// In PluginProcessor.cpp or PluginEditor.cpp
juce::String getPluginVersion()
{
    return DRUMENGINE_VERSION;
}

// Or get individual parts
int getMajorVersion() { return DRUMENGINE_VERSION_MAJOR; }
int getMinorVersion() { return DRUMENGINE_VERSION_MINOR; }
int getPatchVersion() { return DRUMENGINE_VERSION_PATCH; }
```

### Example: Add Version to WebView UI

In your JavaScript ([src/ui/app.js](src/ui/app.js)), you can pass the version from C++:

```cpp
// In PluginEditor.cpp
void AudioPluginAudioProcessorEditor::updateUI()
{
    // Send version to webview
    webView.evaluateJavascript(
        "window.updateVersion('" + juce::String(DRUMENGINE_VERSION) + "');"
    );
}
```

Then in JavaScript:

```javascript
window.updateVersion = function (version) {
  document.getElementById("version").textContent = "v" + version;
};
```

## Build System Usage

### Python Scripts

The [build_config.py](build_config.py) automatically reads the version:

```python
import re
from pathlib import Path

def get_version_from_cmake():
    cmake_path = Path(__file__).parent / "CMakeLists.txt"
    with open(cmake_path, 'r') as f:
        content = f.read()
        match = re.search(r'project\(DRUM_ENGINE_01\s+VERSION\s+([\d.]+)\)', content)
        if match:
            return match.group(1)
    return "0.0.1"

VERSION = get_version_from_cmake()  # "0.0.1"
```

### Installer Naming

The installer script receives the version via environment variable:

```bash
# Set by build.py automatically
DRUMENGINE_VERSION=0.0.1

# Results in:
dist/installer/DrumEngine01-0.0.1-Installer.pkg
```

## Updating the Version

To release a new version:

1. **Update once in CMakeLists.txt:**

   ```cmake
   project(DRUM_ENGINE_01 VERSION 0.1.0)
   ```

2. **Build:**

   ```bash
   python build.py
   ```

3. **Everything updates automatically:**
   - C++ preprocessor defines
   - Build config
   - Installer filename: `DrumEngine01-0.1.0-Installer.pkg`
   - Plugin UI (if you access the defines)

## Version Format

Follow [Semantic Versioning](https://semver.org/):

- **MAJOR.MINOR.PATCH** (e.g., 1.2.3)
- **MAJOR**: Breaking changes
- **MINOR**: New features (backward compatible)
- **PATCH**: Bug fixes (backward compatible)

Examples:

- `0.0.1` - Initial development
- `0.1.0` - First working beta
- `1.0.0` - First stable release
- `1.1.0` - Added new features
- `1.1.1` - Bug fixes
