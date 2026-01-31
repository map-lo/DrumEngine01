#!/bin/bash
# Monitor Trigger 2 plugin while importing WAV files

echo "================================================================"
echo "Monitoring Trigger 2 WAV Import Process"
echo "================================================================"
echo ""

# Find Trigger 2 process
PID=$(pgrep -i "trigger" | head -1)

if [ -z "$PID" ]; then
    echo "❌ Trigger is not running!"
    echo ""
    echo "Please:"
    echo "  1. Open your DAW"
    echo "  2. Load Trigger 2 plugin"
    echo "  3. Run this script again"
    exit 1
fi

echo "✓ Found Trigger process (PID: $PID)"
echo ""

echo "================================================================"
echo "Monitoring file system activity..."
echo "================================================================"
echo ""
echo "Instructions:"
echo "  1. In Trigger plugin, drag or import a WAV file"
echo "  2. Watch the output below"
echo "  3. Press Ctrl+C when done"
echo ""
echo "Starting monitor in 3 seconds..."
sleep 3
echo ""

# Monitor file operations
sudo fs_usage -w -f filesys $PID 2>&1 | grep -i "\.tci\|\.wav\|write\|create" | while read line; do
    echo "$line"
done
