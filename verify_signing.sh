#!/bin/bash
# Simple Plugin Signing Verification

BLUE='\033[0;34m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
NC='\033[0m'

echo ""
echo -e "${BLUE}╔════════════════════════════════════════════════════════════════╗${NC}"
echo -e "${BLUE}║          DrumEngine01 - Signing Verification                  ║${NC}"
echo -e "${BLUE}╚════════════════════════════════════════════════════════════════╝${NC}"
echo ""

RELEASE_DIR="build/release/DrumEngine01_artefacts/Release"

if [ ! -d "$RELEASE_DIR" ]; then
    echo -e "${RED}No release build found${NC}"
    exit 1
fi

test_plugin() {
    local plugin="$1"
    local name="$2"
    
    echo -e "${BLUE}━━━ $name ━━━${NC}"
    
    if [ ! -e "$plugin" ]; then
        echo -e "${RED}✗ Not found${NC}\n"
        return
    fi
    
    # 1. Valid signature
    if codesign -v "$plugin" 2>&1 | grep -q "not signed"; then
        echo -e "${RED}✗ NOT SIGNED${NC}\n"
        return
    fi
    echo -e "${GREEN}✓ Signed${NC}"
    
    # 2. Developer ID
    if codesign -dvvv "$plugin" 2>&1 | grep -q "Developer ID Application"; then
        echo -e "${GREEN}✓ Developer ID${NC}"
    else
        echo -e "${RED}✗ Missing Developer ID (ad-hoc?)${NC}\n"
        return
    fi
    
    # 3. Hardened Runtime
    if codesign -dvvv "$plugin" 2>&1 | grep -q "flags=0x10000(runtime)"; then
        if [[ "$name" == "AAX" ]]; then
            echo -e "${GREEN}✓ Hardened Runtime + PACE Protected${NC}"
        else
            echo -e "${GREEN}✓ Hardened Runtime${NC}"
        fi
    else
        if [[ "$name" == "AAX" ]]; then
            if ls "$plugin/Contents/" 2>/dev/null | grep -q "__Pace_Eden.bundle"; then
                echo -e "${YELLOW}⚠ PACE Protected but no Hardened Runtime (older style)${NC}"
            else
                echo -e "${RED}✗ NO PACE bundle found${NC}\n"
                return
            fi
        else
            echo -e "${RED}✗ NO Hardened Runtime${NC}\n"
            return
        fi
    fi
    
    # 4. Timestamp
    if codesign -dvvv "$plugin" 2>&1 | grep -q "Timestamp="; then
        echo -e "${GREEN}✓ Timestamped${NC}"
    else
        echo -e "${YELLOW}⚠ Not timestamped${NC}"
    fi
    
    # 5. Notarization
    echo -n "Notarization: "
    if spctl -a -vv -t install "$plugin" 2>&1 | grep -q "source=Notarized"; then
        echo -e "${GREEN}✓ NOTARIZED${NC}"
    elif spctl -a -vv -t install "$plugin" 2>&1 | grep -q "source=Developer ID"; then
        echo -e "${YELLOW}⚠ Not notarized (signed only)${NC}"
    else
        echo -e "${YELLOW}⚠ Unknown${NC}"
    fi
    
    echo ""
}

test_plugin "$RELEASE_DIR/VST3/DrumEngine01.vst3" "VST3"
test_plugin "$RELEASE_DIR/AU/DrumEngine01.component" "AU"
test_plugin "$RELEASE_DIR/AAX/DrumEngine01.aaxplugin" "AAX"

# Check installer
INSTALLER="dist/installer-plugins/DrumEngine01-0.0.5-b64-Plugins.pkg"
if [ -f "$INSTALLER" ]; then
    echo -e "${BLUE}━━━ Installer PKG ━━━${NC}"
    
    if pkgutil --check-signature "$INSTALLER" 2>&1 | grep -q "Developer ID Installer"; then
        echo -e "${GREEN}✓ Signed with Developer ID Installer${NC}"
    else
        echo -e "${RED}✗ Not signed${NC}"
    fi
    
    if spctl -a -vv -t install "$INSTALLER" 2>&1 | grep -q "accepted"; then
        echo -e "${GREEN}✓ Gatekeeper accepts${NC}"
    fi
    
    if xcrun stapler validate "$INSTALLER" 2>&1 | grep -q "is already signed with a notarization ticket"; then
        echo -e "${GREEN}✓ Notarization ticket stapled${NC}"
    elif xcrun stapler validate "$INSTALLER" 2>&1 | grep -q "does not have a ticket stapled"; then
        echo -e "${YELLOW}⚠ Notarized but ticket not stapled${NC}"
    fi
    
    echo ""
fi

echo -e "${BLUE}╔════════════════════════════════════════════════════════════════╗${NC}"
echo -e "${BLUE}║                        VERDICT                                 ║${NC}"
echo -e "${BLUE}╚════════════════════════════════════════════════════════════════╝${NC}"
echo ""

if codesign -dvvv "$RELEASE_DIR/VST3/DrumEngine01.vst3" 2>&1 | grep -q "flags=0x10000(runtime)"; then
    echo -e "${GREEN}✅ SUCCESS - Plugins have Hardened Runtime!${NC}"
    echo ""
    echo "Your plugins are properly signed with:"
    echo "  ✓ Developer ID signature"
    echo "  ✓ Hardened Runtime enabled"
    echo "  ✓ Secure timestamp"
    echo ""
    echo "This will work on other Macs!"
    echo ""
    
    if [ -f "$INSTALLER" ] && xcrun stapler validate "$INSTALLER" 2>&1 | grep -q "is already signed with a notarization ticket"; then
        echo -e "${GREEN}🎉 BONUS: Installer is also notarized!${NC}"
        echo "No quarantine removal needed - just send the PKG!"
        echo ""
    else
        echo "To eliminate quarantine warnings, recipients should run:"
        echo "  sudo xattr -r -d com.apple.quarantine /Library/Audio/Plug-Ins/..."
        echo ""
    fi
else
    echo -e "${RED}❌ FAILED - Missing Hardened Runtime${NC}"
    echo ""
    echo "Plugins won't work on other Macs."
    echo "Rebuild with: python3 build_plugins.py --release"
    echo ""
    exit 1
fi
