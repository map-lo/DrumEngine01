#!/bin/bash
# Quick Plugin Signing Script
# Use this to sign already-built plugins with Hardened Runtime

set -e

IDENTITY="Developer ID Application: Marian Plosch (4V59UK4A32)"
ENTITLEMENTS="plugin.entitlements"
BLUE='\033[0;34m'
GREEN='\033[0;32m'
RED='\033[0;31m'
NC='\033[0m' # No Color

echo -e "${BLUE}======================================${NC}"
echo -e "${BLUE}DrumEngine01 - Quick Plugin Signing${NC}"
echo -e "${BLUE}======================================${NC}"
echo ""

# Check if entitlements file exists
if [ ! -f "$ENTITLEMENTS" ]; then
    echo -e "${RED}Error: $ENTITLEMENTS not found${NC}"
    exit 1
fi

# Find plugins
RELEASE_DIR="build/release/DrumEngine01_artefacts/Release"
DEV_DIR="build/dev/DrumEngine01_artefacts/Debug"

if [ -d "$RELEASE_DIR" ]; then
    BUILD_DIR="$RELEASE_DIR"
    PLUGIN_NAME="DrumEngine01"
    echo "Signing RELEASE plugins..."
elif [ -d "$DEV_DIR" ]; then
    BUILD_DIR="$DEV_DIR"
    PLUGIN_NAME="DrumEngine01Dev"
    echo "Signing DEV plugins..."
else
    echo -e "${RED}No build directory found${NC}"
    exit 1
fi

echo ""

# Sign VST3
VST3="$BUILD_DIR/VST3/${PLUGIN_NAME}.vst3"
if [ -d "$VST3" ]; then
    echo -e "${GREEN}Signing VST3...${NC}"
    echo "  Path: $VST3"
    codesign --force --deep --options runtime --timestamp \
        --entitlements "$ENTITLEMENTS" --sign "$IDENTITY" "$VST3"
    echo -e "${GREEN}✓ VST3 signed${NC}"
    echo ""
fi

# Sign AU
AU="$BUILD_DIR/AU/${PLUGIN_NAME}.component"
if [ -d "$AU" ]; then
    echo -e "${GREEN}Signing AU...${NC}"
    echo "  Path: $AU"
    codesign --force --deep --options runtime --timestamp \
        --entitlements "$ENTITLEMENTS" --sign "$IDENTITY" "$AU"
    echo -e "${GREEN}✓ AU signed${NC}"
    echo ""
fi

# Note about AAX
AAX="$BUILD_DIR/AAX/${PLUGIN_NAME}.aaxplugin"
if [ -d "$AAX" ]; then
    echo -e "${BLUE}Note: AAX requires PACE wraptool signing (separate process)${NC}"
    echo "  Path: $AAX"
    echo "  Use: python3 sign_aax.py --build-type=release"
    echo ""
fi

echo -e "${GREEN}======================================${NC}"
echo -e "${GREEN}Verification:${NC}"
echo -e "${GREEN}======================================${NC}"
echo ""

# Verify signatures
if [ -d "$VST3" ]; then
    echo "VST3 Signature:"
    codesign -dv --verbose=4 "$VST3" 2>&1 | grep -E "Signature|flags|Authority" || true
    echo ""
fi

if [ -d "$AU" ]; then
    echo "AU Signature:"
    codesign -dv --verbose=4 "$AU" 2>&1 | grep -E "Signature|flags|Authority" || true
    echo ""
fi

echo -e "${GREEN}✓ Done!${NC}"
echo ""
echo "Next steps:"
echo "  1. Test plugins locally in your DAW"
echo "  2. If working, create a ZIP: ./create_distribution.sh"
echo "  3. For production: python3 build_plugins.py --release (includes notarization)"
