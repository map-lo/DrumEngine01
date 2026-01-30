#!/bin/bash
# Build macOS installer package for DrumEngine01
# This script creates a .pkg installer with selectable plugin formats

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

echo -e "${GREEN}========================================${NC}"
echo -e "${GREEN}DrumEngine01 Installer Builder${NC}"
echo -e "${GREEN}========================================${NC}"
echo ""

# Get the script directory
SCRIPT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"
PROJECT_ROOT="$SCRIPT_DIR/.."
BUILD_DIR="$PROJECT_ROOT/build"
FACTORY_CONTENT_DIR="$PROJECT_ROOT/dist/factory-content"
INSTALLER_DIR="$SCRIPT_DIR"
OUTPUT_DIR="$PROJECT_ROOT/dist/installer"
TEMP_DIR="$OUTPUT_DIR/temp"

# Get version from environment variable or default to 0.0.1
VERSION="${DRUMENGINE_VERSION:-0.0.1}"
echo -e "${YELLOW}Version: $VERSION${NC}"
echo ""

# Plugin paths (after building)
VST3_SOURCE="$BUILD_DIR/DrumEngine01_artefacts/Release/VST3/DrumEngine01.vst3"
VST_SOURCE="$BUILD_DIR/DrumEngine01_artefacts/Release/VST/DrumEngine01.vst"
AU_SOURCE="$BUILD_DIR/DrumEngine01_artefacts/Release/AU/DrumEngine01.component"

# Check if build exists
if [ ! -d "$BUILD_DIR" ]; then
    echo -e "${RED}Error: Build directory not found at $BUILD_DIR${NC}"
    echo "Please build the project first with CMake"
    exit 1
fi

# Check if plugins exist
PLUGINS_FOUND=0
if [ -d "$VST3_SOURCE" ]; then
    echo -e "${GREEN}✓ Found VST3 plugin${NC}"
    PLUGINS_FOUND=$((PLUGINS_FOUND + 1))
else
    echo -e "${YELLOW}⚠ VST3 plugin not found${NC}"
fi

if [ -d "$VST_SOURCE" ]; then
    echo -e "${GREEN}✓ Found VST plugin${NC}"
    PLUGINS_FOUND=$((PLUGINS_FOUND + 1))
else
    echo -e "${YELLOW}⚠ VST plugin not found${NC}"
fi

if [ -d "$AU_SOURCE" ]; then
    echo -e "${GREEN}✓ Found AU plugin${NC}"
    PLUGINS_FOUND=$((PLUGINS_FOUND + 1))
else
    echo -e "${YELLOW}⚠ AU plugin not found${NC}"
fi

if [ $PLUGINS_FOUND -eq 0 ]; then
    echo -e "${RED}Error: No plugins found to package${NC}"
    echo "Build the project first: cd build && cmake --build ."
    exit 1
fi

# Check if dist folder exists (presets and samples)
if [ ! -d "$FACTORY_CONTENT_DIR/presets" ] || [ ! -d "$FACTORY_CONTENT_DIR/samples" ]; then
    echo -e "${YELLOW}⚠ Warning: dist/factory-content/presets or dist/factory-content/samples not found${NC}"
    echo "Run: python generators/package_presets_for_installer.py"
    read -p "Continue without content? (y/N) " -n 1 -r
    echo
    if [[ ! $REPLY =~ ^[Yy]$ ]]; then
        exit 1
    fi
fi

echo ""
echo "Preparing installer..."

# Clean and create output directories
rm -rf "$OUTPUT_DIR"
mkdir -p "$OUTPUT_DIR/packages"
mkdir -p "$TEMP_DIR"

# Function to create a component package
create_component_pkg() {
    local COMPONENT_NAME=$1
    local SOURCE_PATH=$2
    local INSTALL_LOCATION=$3
    local PKG_NAME=$4
    
    if [ ! -d "$SOURCE_PATH" ]; then
        echo -e "${YELLOW}Skipping $COMPONENT_NAME (not built)${NC}"
        return
    fi
    
    echo "Creating $COMPONENT_NAME package..."
    
    local PAYLOAD_DIR="$TEMP_DIR/${COMPONENT_NAME}_payload"
    mkdir -p "$PAYLOAD_DIR/$INSTALL_LOCATION"
    
    # Copy plugin to payload
    cp -R "$SOURCE_PATH" "$PAYLOAD_DIR/$INSTALL_LOCATION/"
    
    # Build package
    pkgbuild \
        --root "$PAYLOAD_DIR" \
        --identifier "com.mari.drumengine01.$PKG_NAME" \
        --version "$VERSION" \
        --install-location "/" \
        "$OUTPUT_DIR/packages/$PKG_NAME.pkg"
    
    echo -e "${GREEN}✓ Created $PKG_NAME.pkg${NC}"
}

# Create VST3 package
if [ -d "$VST3_SOURCE" ]; then
    create_component_pkg "VST3" "$VST3_SOURCE" "/Library/Audio/Plug-Ins/VST3" "vst3"
fi

# Create VST package
if [ -d "$VST_SOURCE" ]; then
    create_component_pkg "VST" "$VST_SOURCE" "/Library/Audio/Plug-Ins/VST" "vst"
fi

# Create AU package
if [ -d "$AU_SOURCE" ]; then
    create_component_pkg "AU" "$AU_SOURCE" "/Library/Audio/Plug-Ins/Components" "au"
fi

# Create content package (presets and samples)
if [ -d "$FACTORY_CONTENT_DIR/presets" ] && [ -d "$FACTORY_CONTENT_DIR/samples" ]; then
    echo "Creating content package..."
    
    CONTENT_PAYLOAD="$TEMP_DIR/content_payload"
    mkdir -p "$CONTENT_PAYLOAD/tmp/DrumEngine01_install"
    
    # Copy presets and samples to temp location for postinstall script
    cp -R "$FACTORY_CONTENT_DIR/presets" "$CONTENT_PAYLOAD/tmp/DrumEngine01_install/"
    cp -R "$FACTORY_CONTENT_DIR/samples" "$CONTENT_PAYLOAD/tmp/DrumEngine01_install/"
    
    # Make postinstall script executable
    chmod +x "$INSTALLER_DIR/postinstall"
    
    # Create scripts directory
    SCRIPTS_DIR="$TEMP_DIR/content_scripts"
    mkdir -p "$SCRIPTS_DIR"
    cp "$INSTALLER_DIR/postinstall" "$SCRIPTS_DIR/"
    
    # Build content package with postinstall script
    pkgbuild \
        --root "$CONTENT_PAYLOAD" \
        --identifier "com.mari.drumengine01.content" \
        --version "$VERSION" \
        --scripts "$SCRIPTS_DIR" \
        --install-location "/" \
        "$OUTPUT_DIR/packages/content.pkg"
    
    echo -e "${GREEN}✓ Created content.pkg${NC}"
fi

# Create final product installer
echo ""
echo "Building final installer..."

INSTALLER_NAME="DrumEngine01-${VERSION}-Installer.pkg"

productbuild \
    --distribution "$INSTALLER_DIR/distribution.xml" \
    --package-path "$OUTPUT_DIR/packages" \
    --resources "$INSTALLER_DIR" \
    "$OUTPUT_DIR/$INSTALLER_NAME"

echo ""
echo -e "${GREEN}========================================${NC}"
echo -e "${GREEN}✓ Installer created successfully!${NC}"
echo -e "${GREEN}========================================${NC}"
echo ""
echo "Installer location:"
echo "  $OUTPUT_DIR/$INSTALLER_NAME"
echo ""
echo "To test the installer:"
echo "  sudo installer -pkg \"$OUTPUT_DIR/$INSTALLER_NAME\" -target /"
echo ""
echo "Or double-click the .pkg file to install via GUI"
echo ""

# Clean up temp directory
rm -rf "$TEMP_DIR"

echo -e "${GREEN}Done!${NC}"
