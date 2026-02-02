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
FACTORY_CONTENT_DIR="$PROJECT_ROOT/presets"
INSTALLER_DIR="$SCRIPT_DIR"
OUTPUT_DIR="$PROJECT_ROOT/dist/installer"
TEMP_DIR="$OUTPUT_DIR/temp"

# Get version from environment variable or default to 0.0.1
VERSION="${DRUMENGINE_VERSION:-0.0.1}"
CONTENT_VERSION="${FACTORY_CONTENT_VERSION:-$VERSION}"
BUILD_TYPE="${DRUMENGINE_BUILD_TYPE:-release}"
BUILD_PLUGINS_INSTALLER="${BUILD_PLUGINS_INSTALLER:-true}"
BUILD_CONTENT_INSTALLER="${BUILD_CONTENT_INSTALLER:-true}"
BUILD_CONTENT_PKG="${BUILD_CONTENT_PKG:-$BUILD_CONTENT_INSTALLER}"
NOTARIZE_CONTENT_INSTALLER="${NOTARIZE_CONTENT_INSTALLER:-false}"
CONTENT_INSTALLER_PATH="${CONTENT_INSTALLER_PATH:-}"

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

if [ "$BUILD_PLUGINS_INSTALLER" = "true" ]; then
    # Check if build exists
    if [ ! -d "$BUILD_DIR" ]; then
        echo -e "${RED}Error: Build directory not found at $BUILD_DIR${NC}"
        echo "Please build the project first with CMake"
        exit 1
    fi
fi

if [ "$BUILD_PLUGINS_INSTALLER" = "true" ]; then
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
fi

if [ "$BUILD_CONTENT_INSTALLER" = "true" ] || [ "$BUILD_CONTENT_PKG" = "true" ]; then
    if [ ! -d "$FACTORY_CONTENT_DIR" ]; then
        echo -e "${YELLOW}⚠ Warning: presets folder not found at $FACTORY_CONTENT_DIR${NC}"
        read -p "Continue without content? (y/N) " -n 1 -r
        echo
        if [[ ! $REPLY =~ ^[Yy]$ ]]; then
            exit 1
        fi
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

if [ "$BUILD_PLUGINS_INSTALLER" = "true" ]; then
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
fi

if [ "$BUILD_PLUGINS_INSTALLER" = "true" ]; then
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
fi

# Create content package (presets only)
if [ "$BUILD_CONTENT_PKG" = "true" ] && [ -d "$FACTORY_CONTENT_DIR" ]; then
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

    CONTENT_ROOT="$FACTORY_CONTENT_DIR"
    CONTENT_VERSION_FILE="$CONTENT_ROOT/version.txt"
    RESTORE_VERSION_FILE=false
    ORIGINAL_VERSION_CONTENT=""

    if [ -f "$CONTENT_VERSION_FILE" ]; then
        ORIGINAL_VERSION_CONTENT="$(cat "$CONTENT_VERSION_FILE")"
    else
        RESTORE_VERSION_FILE=true
    fi

    echo "$CONTENT_VERSION" > "$CONTENT_VERSION_FILE"
    
    # Make postinstall script executable
    chmod +x "$INSTALLER_DIR/postinstall"
    
    # Create scripts directory
    SCRIPTS_DIR="$TEMP_DIR/content_scripts"
    mkdir -p "$SCRIPTS_DIR"
    cp "$INSTALLER_DIR/postinstall" "$SCRIPTS_DIR/"
    
    # Build content package with postinstall script
    pkgbuild \
        --root "$CONTENT_ROOT" \
        --identifier "com.mari.drumengine01.content" \
        --version "$CONTENT_VERSION" \
        --scripts "$SCRIPTS_DIR" \
        --install-location "/tmp/DrumEngine01_install" \
        "$OUTPUT_DIR/packages/content-${CONTENT_VERSION}.pkg"
    
    echo -e "${GREEN}✓ Created content-${CONTENT_VERSION}.pkg${NC}"

    if [ "$RESTORE_VERSION_FILE" = true ]; then
        rm -f "$CONTENT_VERSION_FILE"
    else
        echo "$ORIGINAL_VERSION_CONTENT" > "$CONTENT_VERSION_FILE"
    fi
    fi

    if [ -n "$CACHED_CONTENT_PKG" ] && [ -f "$OUTPUT_DIR/packages/content-${CONTENT_VERSION}.pkg" ]; then
        cp "$OUTPUT_DIR/packages/content-${CONTENT_VERSION}.pkg" "$CACHED_CONTENT_PKG"
        echo -e "${GREEN}✓ Cached content package: $CACHED_CONTENT_PKG${NC}"
    fi
fi

BUILD_NUMBER="${DRUMENGINE_BUILD_NUMBER:-0}"
CONTENT_PKG_NAME="content-${CONTENT_VERSION}.pkg"

if [ "$BUILD_PLUGINS_INSTALLER" = "true" ]; then
    echo ""
    echo "Building plugins installer..."

    PLUGINS_INSTALLER_NAME="${PLUGIN_NAME}-${VERSION}-b${BUILD_NUMBER}-Plugins.pkg"
    DISTRIBUTION_SRC="$INSTALLER_DIR/distribution.xml"
    PLUGINS_DISTRIBUTION_PATH="$OUTPUT_DIR/distribution-plugins.xml"
    cp "$DISTRIBUTION_SRC" "$PLUGINS_DISTRIBUTION_PATH"

    sed -i '' -E '/<line choice="content"\/>/d' "$PLUGINS_DISTRIBUTION_PATH"
    sed -i '' -E '/<choice id="content"/,/<\/choice>/d' "$PLUGINS_DISTRIBUTION_PATH"
    sed -i '' -E '/com\.mari\.drumengine01\.content/d' "$PLUGINS_DISTRIBUTION_PATH"

    productbuild \
        --distribution "$PLUGINS_DISTRIBUTION_PATH" \
        --package-path "$OUTPUT_DIR/packages" \
        --resources "$INSTALLER_DIR" \
        "$OUTPUT_DIR/$PLUGINS_INSTALLER_NAME"

    sign_pkg "$OUTPUT_DIR/$PLUGINS_INSTALLER_NAME"
fi

if [ "$BUILD_CONTENT_INSTALLER" = "true" ]; then
    if [ ! -f "$OUTPUT_DIR/packages/$CONTENT_PKG_NAME" ]; then
        echo -e "${RED}Error: Content pkg not found: $OUTPUT_DIR/packages/$CONTENT_PKG_NAME${NC}"
        exit 1
    fi
    echo ""
    echo "Building factory content installer..."

    CONTENT_INSTALLER_NAME="DrumEngine01-FactoryContent-${CONTENT_VERSION}.pkg"
    DISTRIBUTION_SRC="$INSTALLER_DIR/distribution.xml"
    CONTENT_DISTRIBUTION_PATH="$OUTPUT_DIR/distribution-content.xml"
    cp "$DISTRIBUTION_SRC" "$CONTENT_DISTRIBUTION_PATH"

    sed -i '' -E '/<line choice="vst3"\/>/d' "$CONTENT_DISTRIBUTION_PATH"
    sed -i '' -E '/<line choice="au"\/>/d' "$CONTENT_DISTRIBUTION_PATH"
    sed -i '' -E '/<line choice="aax"\/>/d' "$CONTENT_DISTRIBUTION_PATH"
    sed -i '' -E '/<choice id="vst3"/,/<\/choice>/d' "$CONTENT_DISTRIBUTION_PATH"
    sed -i '' -E '/<choice id="au"/,/<\/choice>/d' "$CONTENT_DISTRIBUTION_PATH"
    sed -i '' -E '/<choice id="aax"/,/<\/choice>/d' "$CONTENT_DISTRIBUTION_PATH"
    sed -i '' -E '/com\.mari\.drumengine01\.(vst3|au|aax)/d' "$CONTENT_DISTRIBUTION_PATH"

    sed -i '' -E "s@(com\.mari\.drumengine01\.content\" version=\")[^"]*(\" onConclusion=\"none\">)content\.pkg@\1${CONTENT_VERSION}\2${CONTENT_PKG_NAME}@" "$CONTENT_DISTRIBUTION_PATH"

    productbuild \
        --distribution "$CONTENT_DISTRIBUTION_PATH" \
        --package-path "$OUTPUT_DIR/packages" \
        --resources "$INSTALLER_DIR" \
        "$OUTPUT_DIR/$CONTENT_INSTALLER_NAME"

    sign_pkg "$OUTPUT_DIR/$CONTENT_INSTALLER_NAME"
fi

if [ "$NOTARIZE_CONTENT_INSTALLER" = "true" ]; then
    echo ""
    echo "Notarizing factory content installer..."

    if [ -n "$CONTENT_INSTALLER_PATH" ]; then
        notarize_pkg "$CONTENT_INSTALLER_PATH"
    else
        if [ -z "$CONTENT_INSTALLER_NAME" ]; then
            echo -e "${RED}Error: Content installer not built and CONTENT_INSTALLER_PATH not provided.${NC}"
            exit 1
        fi
        notarize_pkg "$OUTPUT_DIR/$CONTENT_INSTALLER_NAME"
    fi
fi

echo ""
echo -e "${GREEN}========================================${NC}"
echo -e "${GREEN}✓ Installer build completed!${NC}"
echo -e "${GREEN}========================================${NC}"
echo ""
echo "Installer locations:"
if [ "$BUILD_PLUGINS_INSTALLER" = "true" ]; then
    echo "  📦 Plugins Installer: $OUTPUT_DIR/$PLUGINS_INSTALLER_NAME"
fi
if [ "$BUILD_CONTENT_INSTALLER" = "true" ]; then
    echo "  📦 Factory Content Installer: $OUTPUT_DIR/$CONTENT_INSTALLER_NAME"
fi
echo ""

# Clean up temp directory
rm -rf "$TEMP_DIR"

echo -e "${GREEN}Done!${NC}"
