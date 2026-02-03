#!/bin/bash
# Create Distribution Package
# Creates a ZIP file of signed plugins for testing distribution

set -e

BLUE='\033[0;34m'
GREEN='\033[0;32m'
RED='\033[0;31m'
NC='\033[0m'

echo -e "${BLUE}======================================${NC}"
echo -e "${BLUE}Creating Distribution Package${NC}"
echo -e "${BLUE}======================================${NC}"
echo ""

# Find plugins
RELEASE_DIR="build/release/DrumEngine01_artefacts/Release"
DEV_DIR="build/dev/DrumEngine01_artefacts/Debug"

if [ -d "$RELEASE_DIR" ]; then
    BUILD_DIR="$RELEASE_DIR"
    PLUGIN_NAME="DrumEngine01"
    VERSION=$(grep "project(DRUM_ENGINE_01 VERSION" CMakeLists.txt | sed -E 's/.*VERSION ([0-9.]+).*/\1/')
    OUTPUT="DrumEngine01-${VERSION}-Release.zip"
elif [ -d "$DEV_DIR" ]; then
    BUILD_DIR="$DEV_DIR"
    PLUGIN_NAME="DrumEngine01Dev"
    VERSION=$(grep "project(DRUM_ENGINE_01 VERSION" CMakeLists.txt | sed -E 's/.*VERSION ([0-9.]+).*/\1/')
    OUTPUT="DrumEngine01-${VERSION}-Dev.zip"
else
    echo -e "${RED}No build directory found${NC}"
    echo "Run: python3 build_plugins.py --release"
    exit 1
fi

# Create temp directory for packaging
TEMP_DIR=$(mktemp -d)
PKG_DIR="$TEMP_DIR/$PLUGIN_NAME"
mkdir -p "$PKG_DIR"

echo "Packaging plugins from: $BUILD_DIR"
echo "Output file: $OUTPUT"
echo ""

# Copy plugins
if [ -d "$BUILD_DIR/VST3" ]; then
    echo "Adding VST3..."
    mkdir -p "$PKG_DIR/VST3"
    cp -R "$BUILD_DIR/VST3/${PLUGIN_NAME}.vst3" "$PKG_DIR/VST3/"
fi

if [ -d "$BUILD_DIR/AU" ]; then
    echo "Adding AU..."
    mkdir -p "$PKG_DIR/AU"
    cp -R "$BUILD_DIR/AU/${PLUGIN_NAME}.component" "$PKG_DIR/AU/"
fi

if [ -d "$BUILD_DIR/AAX" ]; then
    echo "Adding AAX..."
    mkdir -p "$PKG_DIR/AAX"
    cp -R "$BUILD_DIR/AAX/${PLUGIN_NAME}.aaxplugin" "$PKG_DIR/AAX/"
fi

# Create installation instructions
cat > "$PKG_DIR/INSTALL.txt" << EOF
DrumEngine01 Installation Instructions

Quick Install (macOS):
----------------------
Run this command to copy plugins to system folders:

sudo bash install.sh

Manual Install:
--------------
Copy the plugins to these system locations:

VST3:  /Library/Audio/Plug-Ins/VST3/
AU:    /Library/Audio/Plug-Ins/Components/
AAX:   /Library/Application Support/Avid/Audio/Plug-Ins/

Clear Gatekeeper Quarantine:
----------------------------
If your DAW can't load the plugins, run:

sudo xattr -r -d com.apple.quarantine /Library/Audio/Plug-Ins/VST3/${PLUGIN_NAME}.vst3
sudo xattr -r -d com.apple.quarantine /Library/Audio/Plug-Ins/Components/${PLUGIN_NAME}.component
sudo xattr -r -d com.apple.quarantine "/Library/Application Support/Avid/Audio/Plug-Ins/${PLUGIN_NAME}.aaxplugin"

After Installation:
------------------
1. Rescan plugins in your DAW
2. For Pro Tools: Clear AAX cache if needed

Version: ${VERSION}
EOF

# Create install script
cat > "$PKG_DIR/install.sh" << EOF
#!/bin/bash
# DrumEngine01 Installation Script

set -e

echo "Installing ${PLUGIN_NAME}..."
echo ""

# Install VST3
if [ -d "VST3/${PLUGIN_NAME}.vst3" ]; then
    echo "Installing VST3..."
    sudo mkdir -p "/Library/Audio/Plug-Ins/VST3"
    sudo cp -R "VST3/${PLUGIN_NAME}.vst3" "/Library/Audio/Plug-Ins/VST3/"
    echo "✓ VST3 installed"
fi

# Install AU
if [ -d "AU/${PLUGIN_NAME}.component" ]; then
    echo "Installing AU..."
    sudo mkdir -p "/Library/Audio/Plug-Ins/Components"
    sudo cp -R "AU/${PLUGIN_NAME}.component" "/Library/Audio/Plug-Ins/Components/"
    echo "✓ AU installed"
fi

# Install AAX
if [ -d "AAX/${PLUGIN_NAME}.aaxplugin" ]; then
    echo "Installing AAX..."
    sudo mkdir -p "/Library/Application Support/Avid/Audio/Plug-Ins"
    sudo cp -R "AAX/${PLUGIN_NAME}.aaxplugin" "/Library/Application Support/Avid/Audio/Plug-Ins/"
    echo "✓ AAX installed"
fi

echo ""
echo "Installation complete!"
echo "Please rescan plugins in your DAW."
EOF

chmod +x "$PKG_DIR/install.sh"

# Create ZIP
echo ""
echo "Creating ZIP..."
cd "$TEMP_DIR"
zip -r -q "$OUTPUT" "$PLUGIN_NAME"
mv "$OUTPUT" "$OLDPWD/"
cd "$OLDPWD"

# Cleanup
rm -rf "$TEMP_DIR"

echo ""
echo -e "${GREEN}======================================${NC}"
echo -e "${GREEN}✓ Distribution package created!${NC}"
echo -e "${GREEN}======================================${NC}"
echo ""
echo "File: $OUTPUT"
echo ""
echo "Send this ZIP to your friend with instructions to:"
echo "  1. Unzip the file"
echo "  2. Open Terminal in the unzipped folder"
echo "  3. Run: sudo bash install.sh"
echo "  4. Enter password when prompted"
echo "  5. Rescan plugins in DAW"
echo ""
