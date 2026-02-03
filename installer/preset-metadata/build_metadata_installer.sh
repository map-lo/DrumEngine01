#!/bin/bash
# Build macOS preset metadata update installer for DrumEngine01
# This installer only updates preset.json files, leaving audio samples intact

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

echo -e "${GREEN}========================================${NC}"
echo -e "${GREEN}DrumEngine01 Preset Metadata Update Installer${NC}"
echo -e "${GREEN}========================================${NC}"
echo ""

# Get the script directory
SCRIPT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"
INSTALLER_ROOT="$SCRIPT_DIR/.."
PROJECT_ROOT="$INSTALLER_ROOT/.."
PRESETS_SOURCE_DIR="$PROJECT_ROOT/presets"
INSTALLER_DIR="$SCRIPT_DIR"
OUTPUT_DIR="$PROJECT_ROOT/dist/installer-metadata"
TEMP_DIR="$OUTPUT_DIR/temp"

# Get version from environment variable or default to 0.0.1
VERSION="${DRUMENGINE_VERSION:-0.0.1}"
METADATA_VERSION="${METADATA_VERSION:-$VERSION}"
METADATA_BUILD_NUMBER="${METADATA_BUILD_NUMBER:-0}"

INSTALLER_CODE_SIGN_IDENTITY="${INSTALLER_CODE_SIGN_IDENTITY:-}"
NOTARYTOOL_PROFILE="${NOTARYTOOL_PROFILE:-}"
APPLE_ID="${APPLE_ID:-}"
TEAM_ID="${TEAM_ID:-}"
APPLE_APP_SPECIFIC_PASSWORD="${APPLE_APP_SPECIFIC_PASSWORD:-}"
SKIP_PKG_SIGNING="${SKIP_PKG_SIGNING:-false}"
SKIP_NOTARIZATION="${SKIP_NOTARIZATION:-false}"

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

echo "Configuration:"
echo "  Metadata Version: $METADATA_VERSION"
echo "  Build Number: $METADATA_BUILD_NUMBER"
echo "  Source: $PRESETS_SOURCE_DIR"
echo ""

# Clean and create directories
echo -e "${YELLOW}Step 1: Setting up directories${NC}"
rm -rf "$OUTPUT_DIR"
mkdir -p "$TEMP_DIR"
mkdir -p "$OUTPUT_DIR"

# Create directory structure with only preset.json files
echo -e "${YELLOW}Step 2: Extracting preset.json files${NC}"
METADATA_ARCHIVE="$TEMP_DIR/metadata.tar.gz"
METADATA_ROOT="$TEMP_DIR/metadata-root"
METADATA_PAYLOAD_DIR="$METADATA_ROOT/com.marianplosch.drumengine01.presetmetadata"
mkdir -p "$METADATA_PAYLOAD_DIR"

# Create a tar.gz of all preset.json files
JSON_COUNT=0
cd "$PRESETS_SOURCE_DIR"
while IFS= read -r -d '' json_file; do
    ((JSON_COUNT++))
done < <(find . -name "preset.json" -type f -print0)

find . -name "preset.json" -type f -print0 | tar czf "$METADATA_ARCHIVE" --null -T -
cd "$SCRIPT_DIR"

echo "  Packaged $JSON_COUNT preset.json files"
echo ""

# Copy metadata archive into payload location for /tmp install
cp "$METADATA_ARCHIVE" "$METADATA_PAYLOAD_DIR/metadata.tar.gz"

# Create postinstall script that extracts and updates
echo -e "${YELLOW}Step 3: Creating postinstall script${NC}"
SCRIPTS_DIR="$TEMP_DIR/scripts"
mkdir -p "$SCRIPTS_DIR"

cat > "$SCRIPTS_DIR/postinstall" << 'POSTINSTALL_EOF'
#!/bin/bash
# Only update preset.json files that already exist

# Get the actual user's home directory
if [ -n "$USER" ]; then
    USER_HOME=$(eval echo ~$USER)
else
    USER_HOME="$HOME"
fi

FACTORY_DIR="$USER_HOME/Documents/DrumEngine01/Factory"
USER_DIR="$USER_HOME/Documents/DrumEngine01/User"
OLD_FACTORY_DIR="$USER_HOME/Documents/DrumEngine01/factory"
TEMP_EXTRACT="$TMPDIR/drumengine_metadata_$$"

# Metadata archive is installed by pkgbuild into /tmp (sandboxed to /private/tmp)
METADATA_ARCHIVE=""
for candidate in \
    "$3/private/tmp/com.marianplosch.drumengine01.presetmetadata/metadata.tar.gz" \
    "$3/tmp/com.marianplosch.drumengine01.presetmetadata/metadata.tar.gz" \
    "/private/tmp/com.marianplosch.drumengine01.presetmetadata/metadata.tar.gz" \
    "/tmp/com.marianplosch.drumengine01.presetmetadata/metadata.tar.gz"; do
    if [ -f "$candidate" ]; then
        METADATA_ARCHIVE="$candidate"
        break
    fi
done

# Migrate from old 'factory' to new 'Factory' naming
if [ -d "$OLD_FACTORY_DIR" ]; then
    echo "Migrating factory folder to Factory..."
    mv "$OLD_FACTORY_DIR" "$FACTORY_DIR"
fi

# Create User directory if it doesn't exist
if [ ! -d "$USER_DIR" ]; then
    echo "Creating User presets directory..."
    mkdir -p "$USER_DIR"
fi

echo "Updating existing preset metadata files..."

# Check if metadata archive exists
if [ -z "$METADATA_ARCHIVE" ] || [ ! -f "$METADATA_ARCHIVE" ]; then
    echo "Error: Metadata archive not found."
    echo "Checked /private/tmp and /tmp (sandboxed) paths."
    exit 1
fi

# Extract the metadata archive to temp directory
mkdir -p "$TEMP_EXTRACT"
tar xzf "$METADATA_ARCHIVE" -C "$TEMP_EXTRACT"

updated_count=0
skipped_count=0

# Find all preset.json files in the extracted archive
cd "$TEMP_EXTRACT"
while IFS= read -r -d '' json_file; do
    # Get relative path from temp directory
    rel_path="${json_file#./}"
    dest_path="$FACTORY_DIR/$rel_path"
    
    # Only copy if the destination file already exists
    if [ -f "$dest_path" ]; then
        cp "$json_file" "$dest_path"
        ((updated_count++))
    else
        ((skipped_count++))
    fi
done < <(find . -name "preset.json" -type f -print0)

echo "Updated: $updated_count preset files"
echo "Skipped (not present): $skipped_count preset files"

# Clean up temp directory
rm -rf "$TEMP_EXTRACT"

exit 0
POSTINSTALL_EOF

chmod +x "$SCRIPTS_DIR/postinstall"
echo "  Created postinstall script"
echo ""

# Build the component package with metadata payload
echo -e "${YELLOW}Step 4: Building metadata component package${NC}"
COMPONENT_PKG="$TEMP_DIR/component.pkg"
pkgbuild --root "$METADATA_ROOT" \
         --scripts "$SCRIPTS_DIR" \
         --identifier "com.marianplosch.drumengine01.presetmetadata" \
         --version "$METADATA_VERSION" \
         --install-location "/tmp" \
         "$COMPONENT_PKG"

echo "  Created component package"
echo ""

# Sign the component package
echo -e "${YELLOW}Step 5: Signing component package${NC}"
sign_pkg "$COMPONENT_PKG"
if [ -z "$INSTALLER_CODE_SIGN_IDENTITY" ]; then
    echo "  Skipped (no signing identity set)"
else
    echo "  Component package signed"
fi
echo ""

# Build the product archive (installer)
echo -e "${YELLOW}Step 6: Building final installer${NC}"
FINAL_INSTALLER="$OUTPUT_DIR/DrumEngine01_PresetMetadata_Update_${METADATA_VERSION}_${METADATA_BUILD_NUMBER}.pkg"

# Create distribution XML
DISTRIBUTION_XML="$TEMP_DIR/distribution.xml"
cat > "$DISTRIBUTION_XML" << EOF
<?xml version="1.0" encoding="utf-8"?>
<installer-gui-script minSpecVersion="2">
    <title>DrumEngine01 Preset Metadata Update ${METADATA_VERSION}</title>
    <welcome file="welcome.html"/>
    <conclusion file="conclusion.html"/>
    <background file="background.png" mime-type="image/png" alignment="bottomleft" scaling="none"/>
    <options customize="never" require-scripts="false" hostArchitectures="x86_64,arm64"/>
    
    <choices-outline>
        <line choice="default">
            <line choice="com.marianplosch.drumengine01.presetmetadata"/>
        </line>
    </choices-outline>
    
    <choice id="default"/>
    <choice id="com.marianplosch.drumengine01.presetmetadata" visible="false">
        <pkg-ref id="com.marianplosch.drumengine01.presetmetadata"/>
    </choice>
    
    <pkg-ref id="com.marianplosch.drumengine01.presetmetadata" version="$METADATA_VERSION" onConclusion="none">component.pkg</pkg-ref>
</installer-gui-script>
EOF

# Create welcome HTML
WELCOME_HTML="$TEMP_DIR/welcome.html"
cat > "$WELCOME_HTML" << EOF
<!DOCTYPE html>
<html>
<head>
    <meta charset="UTF-8">
    <style>
        body { font-family: -apple-system, BlinkMacSystemFont, sans-serif; font-size: 13px; }
        h1 { font-size: 18px; font-weight: 600; }
    </style>
</head>
<body>
    <h1>DrumEngine01 Preset Metadata Update</h1>
    <p>This installer will update preset metadata files (preset.json) in your DrumEngine01 Factory presets folder.</p>
    <p><strong>Version:</strong> $METADATA_VERSION (Build $METADATA_BUILD_NUMBER)</p>
    <p><strong>What this updates:</strong></p>
    <ul>
        <li>Fundamental frequency detection data</li>
        <li>Preset metadata and configuration</li>
    </ul>
    <p><strong>What remains unchanged:</strong></p>
    <ul>
        <li>All audio sample files</li>
        <li>Custom presets you've created</li>
    </ul>
    <p>Installation Location: ~/Documents/DrumEngine01/Factory</p>
</body>
</html>
EOF

# Create conclusion HTML
CONCLUSION_HTML="$TEMP_DIR/conclusion.html"
cat > "$CONCLUSION_HTML" << EOF
<!DOCTYPE html>
<html>
<head>
    <meta charset="UTF-8">
    <style>
        body { font-family: -apple-system, BlinkMacSystemFont, sans-serif; font-size: 13px; }
        h1 { font-size: 18px; font-weight: 600; }
    </style>
</head>
<body>
    <h1>Installation Complete</h1>
    <p>Preset metadata has been successfully updated.</p>
    <p>You can now use the Auto Hz pitch mode feature with these presets.</p>
    <p><strong>Next steps:</strong></p>
    <ul>
        <li>Reload any open instances of DrumEngine01 to see the updates</li>
        <li>Try the new Auto Hz pitch mode in the menu bar</li>
    </ul>
</body>
</html>
EOF

# Build the product
productbuild --distribution "$DISTRIBUTION_XML" \
             --resources "$TEMP_DIR" \
             --package-path "$TEMP_DIR" \
             "$FINAL_INSTALLER"

echo "  Created final installer"
echo ""

# Sign the installer
echo -e "${YELLOW}Step 7: Signing installer${NC}"
sign_pkg "$FINAL_INSTALLER"
if [ -z "$INSTALLER_CODE_SIGN_IDENTITY" ]; then
    echo "  Skipped (no signing identity set)"
else
    echo "  Installer signed"
fi
echo ""

# Notarize if requested
echo -e "${YELLOW}Step 8: Notarizing installer${NC}"
if [ -n "$NOTARYTOOL_PROFILE" ] || [ -n "$APPLE_ID" ]; then
    notarize_pkg "$FINAL_INSTALLER"
    echo "  Installer notarized and stapled"
else
    echo "  Skipped (notarization not configured)"
fi
echo ""

# Clean up temp directory
rm -rf "$TEMP_DIR"

echo -e "${GREEN}========================================${NC}"
echo -e "${GREEN}Build Complete!${NC}"
echo -e "${GREEN}========================================${NC}"
echo ""
echo "Output:"
echo "  Installer: $FINAL_INSTALLER"
echo "  Size: $(du -h "$FINAL_INSTALLER" | cut -f1)"
echo ""
echo "This installer will:"
echo "  - Update existing preset.json files only"
echo "  - Skip presets that were deleted by user"
echo "  - Update $JSON_COUNT preset files (if present)"
echo "  - Install to: ~/Documents/DrumEngine01/Factory"
echo "  - Leave all audio samples unchanged"
echo ""
