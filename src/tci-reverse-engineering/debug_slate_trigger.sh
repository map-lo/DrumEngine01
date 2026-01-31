#!/bin/bash
# Debug Slate Trigger 2 with LLDB
# This script helps you debug the TCI loading process

echo "================================================================================"
echo "Slate Trigger 2 - TCI Decompression Debugger"
echo "================================================================================"
echo ""

# Find Slate Trigger 2
APP_STANDALONE="/Applications/Slate Digital/Trigger 2.app/Contents/MacOS/Trigger 2"
PLUGIN_VST3="$HOME/Library/Audio/Plug-Ins/VST3/Slate Digital Trigger 2.vst3/Contents/MacOS/Slate Digital Trigger 2"
PLUGIN_AU="$HOME/Library/Audio/Plug-Ins/Components/Slate Digital Trigger 2.component/Contents/MacOS/Slate Digital Trigger 2"

BINARY=""
if [ -f "$APP_STANDALONE" ]; then
    BINARY="$APP_STANDALONE"
    echo "✓ Found standalone app: $APP_STANDALONE"
elif [ -f "$PLUGIN_VST3" ]; then
    BINARY="$PLUGIN_VST3"
    echo "✓ Found VST3 plugin: $PLUGIN_VST3"
elif [ -f "$PLUGIN_AU" ]; then
    BINARY="$PLUGIN_AU"
    echo "✓ Found AU plugin: $PLUGIN_AU"
else
    echo "✗ Slate Trigger 2 not found"
    echo "Please install Slate Trigger 2 or edit this script with the correct path"
    exit 1
fi

echo ""
echo "Binary: $BINARY"
echo ""

# Check if it's running
PID=$(ps aux | grep -i "trigger" | grep -v grep | grep -v "bash" | awk '{print $2}' | head -1)

if [ -z "$PID" ]; then
    echo "Slate Trigger 2 is not running."
    echo ""
    echo "Please start it:"
    if [ -f "$APP_STANDALONE" ]; then
        echo "  open \"/Applications/Slate Digital/Trigger 2.app\""
    else
        echo "  Open your DAW and load the Trigger 2 plugin"
    fi
    echo ""
    echo "Then run this script again."
    exit 1
fi

echo "✓ Found running process: PID $PID"
echo ""

# Create LLDB command file
LLDB_CMDS="/tmp/trigger_debug_commands.lldb"

cat > "$LLDB_CMDS" << 'EOF'
# Breakpoint on file operations
br set -n open -c 'strstr((char*)$arg1, ".tci") != 0'
br set -n fopen -c 'strstr((char*)$arg1, ".tci") != 0'
br set -n read
br set -n fread

# Breakpoint on potential decompression functions  
br set -r "decode|decompress|inflate|uncompress"

# Breakpoint on memory allocation (to catch decompressed data)
br set -n malloc -c '$arg0 > 500000'

# Commands to run when breakpoint hits
br command add 1
bt 5
register read rdi rsi rdx
memory read --size 16 --format x --count 16 $rdi
continue
DONE

br command add 2
bt 5
register read rdi rsi rdx
memory read --size 16 --format x --count 16 $rdi
continue
DONE

# Search for RIFF/WAVE in memory periodically
target stop-hook add -o "memory find -s 'RIFF' -- 0x0 0xFFFFFFFFFFFFFFFF"

# Continue execution
continue
EOF

echo "================================================================================"
echo "Starting LLDB debugger..."
echo "================================================================================"
echo ""
echo "The debugger will:"
echo "  1. Break when opening .tci files"
echo "  2. Break on decode/decompress functions"
echo "  3. Break on large memory allocations"
echo "  4. Search for RIFF/WAVE signatures in memory"
echo ""
echo "Now load a TCI file in Slate Trigger 2 to trigger breakpoints."
echo ""
echo "Useful LLDB commands:"
echo "  bt              - Show backtrace"
echo "  register read   - Show all registers"
echo "  memory read     - Read memory"
echo "  memory find     - Search memory"
echo "  c or continue   - Continue execution"
echo "  q or quit       - Quit debugger"
echo ""
echo "Press Enter to attach debugger..."
read

# Attach LLDB
sudo lldb -p "$PID" -s "$LLDB_CMDS"

echo ""
echo "================================================================================"
echo "Debugger detached"
echo "================================================================================"
