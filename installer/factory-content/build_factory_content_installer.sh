#!/bin/bash
# Build macOS factory content installer package for DrumEngine01

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

echo -e "${GREEN}========================================${NC}"
echo -e "${GREEN}DrumEngine01 Factory Content Installer Builder${NC}"
echo -e "${GREEN}========================================${NC}"
echo ""

# Get the script directory
SCRIPT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"
INSTALLER_ROOT="$SCRIPT_DIR/.."
PROJECT_ROOT="$INSTALLER_ROOT/.."
FACTORY_CONTENT_DIR="$PROJECT_ROOT/presets"
INSTALLER_DIR="$INSTALLER_ROOT"
OUTPUT_DIR="$PROJECT_ROOT/dist/installer-content"
TEMP_DIR="$OUTPUT_DIR/temp"

# Get version from environment variable or default to 0.0.1
VERSION="${DRUMENGINE_VERSION:-0.0.1}"
CONTENT_VERSION="${FACTORY_CONTENT_VERSION:-$VERSION}"

INSTALLER_CODE_SIGN_IDENTITY="${INSTALLER_CODE_SIGN_IDENTITY:-}"
NOTARYTOOL_PROFILE="${NOTARYTOOL_PROFILE:-}"
APPLE_ID="${APPLE_ID:-}"
TEAM_ID="${TEAM_ID:-}"
APPLE_APP_SPECIFIC_PASSWORD="${APPLE_APP_SPECIFIC_PASSWORD:-}"
NOTARIZE_CONTENT_INSTALLER="${NOTARIZE_CONTENT_INSTALLER:-false}"
SKIP_PKG_SIGNING="${SKIP_PKG_SIGNING:-false}"
SKIP_NOTARIZATION="${SKIP_NOTARIZATION:-false}"
BUILD_CONTENT_PKG="${BUILD_CONTENT_PKG:-true}"
BUILD_CONTENT_INSTALLER="${BUILD_CONTENT_INSTALLER:-true}"
CONTENT_INSTALLER_PATH="${CONTENT_INSTALLER_PATH:-}"

CONTENT_PKG_CACHE_DIR="${CONTENT_PKG_CACHE_DIR:-}"

sign_pkg() {
    local PKG_PATH="$1"

    if [ "$SKIP_PKG_SIGNING" = "true" ]; then
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

if [ ! -d "$FACTORY_CONTENT_DIR" ]; then
    echo -e "${YELLOW}⚠ Warning: presets folder not found at $FACTORY_CONTENT_DIR${NC}"
    read -p "Continue without content? (y/N) " -n 1 -r
    echo
    if [[ ! $REPLY =~ ^[Yy]$ ]]; then
        exit 1
    fi
fi

echo ""
echo "Preparing installer..."

mkdir -p "$OUTPUT_DIR/packages"
mkdir -p "$TEMP_DIR"

CONTENT_PKG_NAME="content-${CONTENT_VERSION}.pkg"

if [ "$BUILD_CONTENT_PKG" = "true" ]; then
    CACHED_CONTENT_PKG=""
    if [ -n "$CONTENT_PKG_CACHE_DIR" ]; then
        mkdir -p "$CONTENT_PKG_CACHE_DIR"
        CACHED_CONTENT_PKG="$CONTENT_PKG_CACHE_DIR/$CONTENT_PKG_NAME"
        if [ -f "$CACHED_CONTENT_PKG" ]; then
            echo "Using cached content package: $CACHED_CONTENT_PKG"
            cp "$CACHED_CONTENT_PKG" "$OUTPUT_DIR/packages/$CONTENT_PKG_NAME"
        fi
    fi

    if [ ! -f "$OUTPUT_DIR/packages/$CONTENT_PKG_NAME" ]; then
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

        chmod +x "$SCRIPT_DIR/postinstall"

        SCRIPTS_DIR="$TEMP_DIR/content_scripts"
        mkdir -p "$SCRIPTS_DIR"
        cp "$SCRIPT_DIR/postinstall" "$SCRIPTS_DIR/"

        pkgbuild \
            --root "$CONTENT_ROOT" \
            --identifier "com.mari.drumengine01.content" \
            --version "$CONTENT_VERSION" \
            --scripts "$SCRIPTS_DIR" \
            --install-location "/tmp/DrumEngine01_install/presets" \
            "$OUTPUT_DIR/packages/$CONTENT_PKG_NAME"

        echo -e "${GREEN}✓ Created $CONTENT_PKG_NAME${NC}"

        if [ "$RESTORE_VERSION_FILE" = true ]; then
            rm -f "$CONTENT_VERSION_FILE"
        else
            echo "$ORIGINAL_VERSION_CONTENT" > "$CONTENT_VERSION_FILE"
        fi
    fi

    if [ -n "$CACHED_CONTENT_PKG" ] && [ -f "$OUTPUT_DIR/packages/$CONTENT_PKG_NAME" ]; then
        cp "$OUTPUT_DIR/packages/$CONTENT_PKG_NAME" "$CACHED_CONTENT_PKG"
        echo -e "${GREEN}✓ Cached content package: $CACHED_CONTENT_PKG${NC}"
    fi
fi

if [ "$BUILD_CONTENT_INSTALLER" = "true" ]; then
    if [ ! -f "$OUTPUT_DIR/packages/$CONTENT_PKG_NAME" ]; then
        echo -e "${RED}Error: Content pkg not found: $OUTPUT_DIR/packages/$CONTENT_PKG_NAME${NC}"
        exit 1
    fi

    echo ""
    echo "Building factory content installer..."

    CONTENT_INSTALLER_NAME="DrumEngine01-FactoryContent-${CONTENT_VERSION}.pkg"
    DISTRIBUTION_TEMPLATE="$SCRIPT_DIR/distribution_factory_content.xml.in"
    DISTRIBUTION_PATH="$OUTPUT_DIR/distribution-content.xml"

    sed -e "s/@CONTENT_VERSION@/$CONTENT_VERSION/g" -e "s/@CONTENT_PKG@/$CONTENT_PKG_NAME/g" "$DISTRIBUTION_TEMPLATE" > "$DISTRIBUTION_PATH"

    productbuild \
        --distribution "$DISTRIBUTION_PATH" \
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
        notarize_pkg "$OUTPUT_DIR/$CONTENT_INSTALLER_NAME"
    fi
fi

echo ""
echo -e "${GREEN}========================================${NC}"
echo -e "${GREEN}✓ Factory content build completed!${NC}"
echo -e "${GREEN}========================================${NC}"

echo ""
echo "Installer location:"
if [ "$BUILD_CONTENT_INSTALLER" = "true" ]; then
    echo "  $OUTPUT_DIR/$CONTENT_INSTALLER_NAME"
fi

echo -e "${GREEN}Done!${NC}"
