# Development Build Configuration for DrumEngine01

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
CLEAN_BUILD = False     # Set to True to clean build artifacts before building

# Installer Settings
BUILD_INSTALLER = False  # Set to False to skip installer creation

# Preset Packaging if installer is built
PRESET_LIMIT = 4     # Set to a number (e.g., 2) to limit presets per folder for testing, or None for all presets

# Plugin Formats (must match CMakeLists.txt)
PLUGIN_FORMATS = ["VST3", "AU", "AAX"]

# AAX Signing
SIGN_AAX = True  # Set to False to skip AAX signing (requires PACE configuration)

# Paths (usually don't need to change these)
BUILD_DIR = "build"
GENERATORS_DIR = "generators"
INSTALLER_DIR = "installer"
DIST_DIR = "dist"
