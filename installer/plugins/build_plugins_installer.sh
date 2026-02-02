#!/bin/bash
# Build macOS plugins installer package for DrumEngine01 (VST3/AU/AAX)

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

echo -e "${GREEN}========================================${NC}"
echo -e "${GREEN}DrumEngine01 Plugins Installer Builder${NC}"
echo -e "${GREEN}========================================${NC}"
echo ""

# Get the script directory
SCRIPT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"
INSTALLER_ROOT="$SCRIPT_DIR/.."
PROJECT_ROOT="$INSTALLER_ROOT/.."
BUILD_DIR="$PROJECT_ROOT/build"
INSTALLER_DIR="$SCRIPT_DIR"
OUTPUT_DIR="$PROJECT_ROOT/dist/installer-plugins"
TEMP_DIR="$OUTPUT_DIR/temp"

# Get version from environment variable or default to 0.0.1
VERSION="${DRUMENGINE_VERSION:-0.0.1}"
BUILD_TYPE="${DRUMENGINE_BUILD_TYPE:-release}"

# Determine plugin name based on build type
if [ "$BUILD_TYPE" = "dev" ]; then
    PLUGIN_NAME="DrumEngine01Dev"
    CMAKE_BUILD="Debug"
else
    PLUGIN_NAME="DrumEngine01"
    CMAKE_BUILD="Release"
fi

echo -e "${YELLOW}Version: $VERSION${NC}"
echo -e "${YELLOW}Build Type: $BUILD_TYPE${NC}"
echo -e "${YELLOW}Plugin Name: $PLUGIN_NAME${NC}"
echo ""

# Plugin paths (after building)
VST3_SOURCE="$BUILD_DIR/DrumEngine01_artefacts/$CMAKE_BUILD/VST3/$PLUGIN_NAME.vst3"
AU_SOURCE="$BUILD_DIR/DrumEngine01_artefacts/$CMAKE_BUILD/AU/$PLUGIN_NAME.component"
AAX_SOURCE="$BUILD_DIR/DrumEngine01_artefacts/$CMAKE_BUILD/AAX/$PLUGIN_NAME.aaxplugin"

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
    echo -e "${YELLOW}⚠ VST3 plugin not found at $VST3_SOURCE${NC}"
fi

if [ -d "$AU_SOURCE" ]; then
    echo -e "${GREEN}✓ Found AU plugin${NC}"
    PLUGINS_FOUND=$((PLUGINS_FOUND + 1))
else
    echo -e "${YELLOW}⚠ AU plugin not found at $AU_SOURCE${NC}"
fi

if [ -d "$AAX_SOURCE" ]; then
    echo -e "${GREEN}✓ Found AAX plugin${NC}"
    PLUGINS_FOUND=$((PLUGINS_FOUND + 1))
else
    echo -e "${YELLOW}⚠ AAX plugin not found at $AAX_SOURCE${NC}"
fi

if [ $PLUGINS_FOUND -eq 0 ]; then
    echo -e "${RED}Error: No plugins found to package${NC}"
    echo "Build the project first: cd build && cmake --build ."
    exit 1
fi

echo ""
echo "Preparing installer..."

# Clean and create output directories
rm -rf "$OUTPUT_DIR"
mkdir -p "$OUTPUT_DIR/packages"
mkdir -p "$TEMP_DIR"

# Optional notarization for component pkgs (VST3/AU/AAX)
NOTARIZE_COMPONENT_PKGS="${NOTARIZE_COMPONENT_PKGS:-false}"
NOTARYTOOL_PROFILE="${NOTARYTOOL_PROFILE:-}"
APPLE_ID="${APPLE_ID:-}"
TEAM_ID="${TEAM_ID:-}"
APPLE_APP_SPECIFIC_PASSWORD="${APPLE_APP_SPECIFIC_PASSWORD:-}"
INSTALLER_CODE_SIGN_IDENTITY="${INSTALLER_CODE_SIGN_IDENTITY:-}"
NOTARIZE_FINAL_INSTALLER="${NOTARIZE_FINAL_INSTALLER:-false}"
SKIP_PKG_SIGNING="${SKIP_PKG_SIGNING:-false}"
SKIP_NOTARIZATION="${SKIP_NOTARIZATION:-false}"
SKIP_COMPONENT_PKG_SIGNING="${SKIP_COMPONENT_PKG_SIGNING:-true}"

sign_pkg() {
    local PKG_PATH="$1"

    if [ "$SKIP_PKG_SIGNING" = "true" ]; then
        return 0
    fi

    if [ "$SKIP_COMPONENT_PKG_SIGNING" = "true" ]; then
        return 0
    fi

    if [ -z "$INSTALLER_CODE_SIGN_IDENTITY" ]; then
        return 0
    fi

    if [ ! -f "$PKG_PATH" ]; then
        echo -e "${YELLOW}Skipping pkg signing (missing): $PKG_PATH${NC}"
        return 0
    fi

    echo "Signing pkg: $PKG_PATH"
    local SIGNED_PATH="${PKG_PATH%.pkg}-signed.pkg"

    productsign --sign "$INSTALLER_CODE_SIGN_IDENTITY" "$PKG_PATH" "$SIGNED_PATH"
    mv -f "$SIGNED_PATH" "$PKG_PATH"
}

notarize_pkg() {
    local PKG_PATH="$1"

    if [ "$SKIP_NOTARIZATION" = "true" ]; then
        return 0
    fi

    if [ ! -f "$PKG_PATH" ]; then
        echo -e "${YELLOW}Skipping notarization (missing): $PKG_PATH${NC}"
        return
    fi

    echo "Notarizing: $PKG_PATH"

    if [ -n "$NOTARYTOOL_PROFILE" ]; then
        xcrun notarytool submit "$PKG_PATH" --keychain-profile "$NOTARYTOOL_PROFILE" --wait
    else
        if [ -z "$APPLE_ID" ] || [ -z "$TEAM_ID" ] || [ -z "$APPLE_APP_SPECIFIC_PASSWORD" ]; then
            echo -e "${RED}Error: Notarytool credentials missing.${NC}"
            echo -e "${YELLOW}Set NOTARYTOOL_PROFILE or APPLE_ID/TEAM_ID/APPLE_APP_SPECIFIC_PASSWORD.${NC}"
            exit 1
        fi
        xcrun notarytool submit "$PKG_PATH" --apple-id "$APPLE_ID" --team-id "$TEAM_ID" --password "$APPLE_APP_SPECIFIC_PASSWORD" --wait
    fi

    echo "Stapling: $PKG_PATH"
    xcrun stapler staple "$PKG_PATH"
}

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

    sign_pkg "$OUTPUT_DIR/packages/$PKG_NAME.pkg"

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

# Create AAX package
if [ -d "$AAX_SOURCE" ]; then
    create_component_pkg "AAX" "$AAX_SOURCE" "/Library/Application Support/Avid/Audio/Plug-Ins" "aax"
fi

if [ "$NOTARIZE_COMPONENT_PKGS" = "true" ]; then
    echo ""
    echo "Notarizing component packages..."
    notarize_pkg "$OUTPUT_DIR/packages/vst3.pkg"
    notarize_pkg "$OUTPUT_DIR/packages/au.pkg"
    notarize_pkg "$OUTPUT_DIR/packages/aax.pkg"
    echo -e "${GREEN}✓ Component packages notarized${NC}"
fi

# Build plugins installer
echo ""
echo "Building plugins installer..."

BUILD_NUMBER="${DRUMENGINE_BUILD_NUMBER:-0}"
PLUGINS_INSTALLER_NAME="${PLUGIN_NAME}-${VERSION}-b${BUILD_NUMBER}-Plugins.pkg"
DISTRIBUTION_TEMPLATE="$SCRIPT_DIR/distribution.xml.in"
DISTRIBUTION_PATH="$OUTPUT_DIR/distribution-plugins.xml"

sed "s/@VERSION@/$VERSION/g" "$DISTRIBUTION_TEMPLATE" > "$DISTRIBUTION_PATH"

productbuild \
    --distribution "$DISTRIBUTION_PATH" \
    --package-path "$OUTPUT_DIR/packages" \
    --resources "$INSTALLER_DIR" \
    "$OUTPUT_DIR/$PLUGINS_INSTALLER_NAME"

if [ "$SKIP_PKG_SIGNING" != "true" ]; then
    productsign --sign "$INSTALLER_CODE_SIGN_IDENTITY" "$OUTPUT_DIR/$PLUGINS_INSTALLER_NAME" "$OUTPUT_DIR/${PLUGINS_INSTALLER_NAME%.pkg}-signed.pkg"
    mv -f "$OUTPUT_DIR/${PLUGINS_INSTALLER_NAME%.pkg}-signed.pkg" "$OUTPUT_DIR/$PLUGINS_INSTALLER_NAME"
fi

if [ "$NOTARIZE_FINAL_INSTALLER" = "true" ]; then
    echo ""
    echo "Notarizing plugins installer..."
    notarize_pkg "$OUTPUT_DIR/$PLUGINS_INSTALLER_NAME"
fi

if [ "$SKIP_PKG_SIGNING" != "true" ]; then
    echo ""
    echo -e "${GREEN}========================================${NC}"
    echo -e "${GREEN}✓ Installer created successfully!${NC}"
    echo -e "${GREEN}========================================${NC}"
else
    echo ""
    echo -e "${GREEN}========================================${NC}"
    echo -e "${GREEN}✓ Installer created (unsigned).${NC}"
    echo -e "${GREEN}========================================${NC}"
fi

echo ""
echo "Installer location:"
echo "  $OUTPUT_DIR/$PLUGINS_INSTALLER_NAME"
echo ""

echo -e "${GREEN}Done!${NC}"
