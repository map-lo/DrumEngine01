# Factory Content Build Configuration for DrumEngine01

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

# Factory content version (separate from plugin VERSION)
FACTORY_CONTENT_VERSION = VERSION

# Factory content pkg cache (outside dist to avoid clean deletion)
CONTENT_PKG_CACHE_DIR = "factory-content-installer"  # Relative to project root or absolute path

# macOS Installer PKG Signing
INSTALLER_CODE_SIGN_IDENTITY = "Developer ID Installer: Marian Plosch (4V59UK4A32)"  # Developer ID Installer identity string

# Notarization
NOTARYTOOL_PROFILE = "DrumEngine01Notary"  # Keychain profile name for notarytool (preferred)
APPLE_ID = None
TEAM_ID = None
APPLE_APP_SPECIFIC_PASSWORD = None

# Paths (usually don't need to change these)
INSTALLER_DIR = "installer"
DIST_DIR = "dist"
