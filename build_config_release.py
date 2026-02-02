# Release Build Configuration for DrumEngine01

import re
from pathlib import Path

# Read version from CMakeLists.txt (single source of truth)
def get_version_from_cmake():
    cmake_path = Path(__file__).parent / "CMakeLists.txt"
    with open(cmake_path, 'r') as f:
        content = f.read()
        match = re.search(r'project\(DRUM_ENGINE_01\s+VERSION\s+([\d.]+)\)', content)
        if match:
            return match.group(1)
    return "0.0.1"  # fallback

VERSION = get_version_from_cmake()

# Build Settings
CLEAN_BUILD = True      # Clean build artifacts before building for release

# Installer Settings
BUILD_INSTALLER = True   # Build installer for release

# Preset Packaging
PRESET_LIMIT = None      # Include all presets for release builds

# Plugin Formats (must match CMakeLists.txt)
PLUGIN_FORMATS = ["VST3", "AU", "AAX"]

# AAX Signing
SIGN_AAX = True  # Set to False to skip AAX signing (requires PACE configuration)

# macOS Plugin Signing (VST3/AU)
SIGN_MAC_PLUGINS = True  # Set to False to skip macOS plugin signing
MAC_CODE_SIGN_IDENTITY = "Developer ID Application: Marian Plosch (4V59UK4A32)"  # Developer ID Application identity string

# Component PKG Notarization (VST3/AU/AAX)
NOTARIZE_COMPONENT_PKGS = True  # Set to True to notarize component pkgs only
NOTARYTOOL_PROFILE = "DrumEngine01Notary"  # Keychain profile name for notarytool (preferred)
APPLE_ID = None
TEAM_ID = None
APPLE_APP_SPECIFIC_PASSWORD = None

# Paths (usually don't need to change these)
BUILD_DIR = "build"
GENERATORS_DIR = "generators"
INSTALLER_DIR = "installer"
DIST_DIR = "dist"
