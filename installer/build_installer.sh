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
CONTENT_VERSION="${FACTORY_CONTENT_VERSION:-$VERSION}"
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

# Check if dist folder exists (presets only)
if [ ! -d "$FACTORY_CONTENT_DIR/presets" ]; then
    echo -e "${YELLOW}⚠ Warning: dist/factory-content/presets not found${NC}"
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

# Optional notarization for component pkgs (VST3/AU/AAX)
# Enable with NOTARIZE_COMPONENT_PKGS=true
NOTARIZE_COMPONENT_PKGS="${NOTARIZE_COMPONENT_PKGS:-false}"
NOTARYTOOL_PROFILE="${NOTARYTOOL_PROFILE:-}"
APPLE_ID="${APPLE_ID:-}"
TEAM_ID="${TEAM_ID:-}"
APPLE_APP_SPECIFIC_PASSWORD="${APPLE_APP_SPECIFIC_PASSWORD:-}"
INSTALLER_CODE_SIGN_IDENTITY="${INSTALLER_CODE_SIGN_IDENTITY:-}"
CONTENT_PKG_CACHE_DIR="${CONTENT_PKG_CACHE_DIR:-}"

sign_pkg() {
    local PKG_PATH="$1"

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

# Notarize component pkgs only (skip content pkg)
if [ "$NOTARIZE_COMPONENT_PKGS" = "true" ]; then
    echo ""
    echo "Notarizing component packages..."
    if [ -z "$INSTALLER_CODE_SIGN_IDENTITY" ]; then
        echo -e "${RED}Error: INSTALLER_CODE_SIGN_IDENTITY is required to notarize component pkgs.${NC}"
        exit 1
    fi
    notarize_pkg "$OUTPUT_DIR/packages/vst3.pkg"
    notarize_pkg "$OUTPUT_DIR/packages/au.pkg"
    notarize_pkg "$OUTPUT_DIR/packages/aax.pkg"
    echo -e "${GREEN}✓ Component packages notarized${NC}"
fi

# Create content package (presets only)
if [ -d "$FACTORY_CONTENT_DIR/presets" ]; then
    CACHED_CONTENT_PKG=""
    if [ -n "$CONTENT_PKG_CACHE_DIR" ]; then
        mkdir -p "$CONTENT_PKG_CACHE_DIR"
        CACHED_CONTENT_PKG="$CONTENT_PKG_CACHE_DIR/content-${CONTENT_VERSION}.pkg"
        if [ -f "$CACHED_CONTENT_PKG" ]; then
            echo "Using cached content package: $CACHED_CONTENT_PKG"
            cp "$CACHED_CONTENT_PKG" "$OUTPUT_DIR/packages/content-${CONTENT_VERSION}.pkg"
        fi
    fi

    if [ ! -f "$OUTPUT_DIR/packages/content-${CONTENT_VERSION}.pkg" ]; then
    echo "Creating content package..."
    
    CONTENT_PAYLOAD="$TEMP_DIR/content_payload"
    mkdir -p "$CONTENT_PAYLOAD/tmp/DrumEngine01_install"
    
    # Copy presets to temp location for postinstall script
    cp -R "$FACTORY_CONTENT_DIR/presets" "$CONTENT_PAYLOAD/tmp/DrumEngine01_install/"

    # Write factory content version for installation tracking
    echo "$CONTENT_VERSION" > "$CONTENT_PAYLOAD/tmp/DrumEngine01_install/version.txt"
    
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
        --version "$CONTENT_VERSION" \
        --scripts "$SCRIPTS_DIR" \
        --install-location "/" \
        "$OUTPUT_DIR/packages/content-${CONTENT_VERSION}.pkg"
    
    echo -e "${GREEN}✓ Created content-${CONTENT_VERSION}.pkg${NC}"
    fi

    if [ -n "$CACHED_CONTENT_PKG" ] && [ -f "$OUTPUT_DIR/packages/content-${CONTENT_VERSION}.pkg" ]; then
        cp "$OUTPUT_DIR/packages/content-${CONTENT_VERSION}.pkg" "$CACHED_CONTENT_PKG"
        echo -e "${GREEN}✓ Cached content package: $CACHED_CONTENT_PKG${NC}"
    fi
fi

# Create final product installer
echo ""
echo "Building final installer..."

BUILD_NUMBER="${DRUMENGINE_BUILD_NUMBER:-0}"
INSTALLER_NAME="${PLUGIN_NAME}-${VERSION}-b${BUILD_NUMBER}-Installer.pkg"

# Prepare distribution.xml with content versioned pkg filename
DISTRIBUTION_SRC="$INSTALLER_DIR/distribution.xml"
DISTRIBUTION_PATH="$OUTPUT_DIR/distribution.xml"
cp "$DISTRIBUTION_SRC" "$DISTRIBUTION_PATH"
CONTENT_PKG_NAME="content-${CONTENT_VERSION}.pkg"

if [ -f "$OUTPUT_DIR/packages/$CONTENT_PKG_NAME" ]; then
    sed -i '' -E "s@(com\.mari\.drumengine01\.content\" version=\")[^"]*(\" onConclusion=\"none\">)content\.pkg@\1${CONTENT_VERSION}\2${CONTENT_PKG_NAME}@" "$DISTRIBUTION_PATH"
fi

productbuild \
    --distribution "$DISTRIBUTION_PATH" \
    --package-path "$OUTPUT_DIR/packages" \
    --resources "$INSTALLER_DIR" \
    "$OUTPUT_DIR/$INSTALLER_NAME"

sign_pkg "$OUTPUT_DIR/$INSTALLER_NAME"

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
