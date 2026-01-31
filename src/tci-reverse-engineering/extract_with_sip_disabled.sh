#!/bin/bash
# Extract Audio from Slate Trigger via Memory Dump
# This script will extract decompressed audio after you temporarily disable SIP

PID=19787

echo "================================================================"
echo "Memory Extraction for Trigger Instrument Editor (PID: $PID)"
echo "================================================================"
echo ""

# Check if we can attach
echo "Testing if we can attach debugger..."
sudo lldb -p $PID -o "detach" -o "quit" 2>&1 | grep -q "attach failed"

if [ $? -eq 0 ]; then
    echo ""
    echo "❌ Cannot attach debugger (SIP is enabled)"
    echo ""
    echo "TO PROCEED:"
    echo "  1. Restart Mac in Recovery Mode (⌘+R at boot)"
    echo "  2. Open Terminal from Utilities menu"
    echo "  3. Run: csrutil disable"
    echo "  4. Restart normally"
    echo "  5. Run this script again"
    echo "  6. After extraction, re-enable SIP:"
    echo "     - Boot to Recovery Mode again"
    echo "     - Run: csrutil enable"
    echo ""
    echo "ALTERNATIVE: Use task_for_pid-allow entitlement"
    echo "  OR just use the original WAV files!"
    echo ""
    exit 1
fi

echo "✓ Debugger can attach!"
echo ""

# Create LLDB script to search for RIFF headers
cat > /tmp/find_audio.lldb << 'EOF'
process attach -p 19787
memory find -s "RIFF" 0x0 0xFFFFFFFFFFFFFFFF
memory find -s "WAVEfmt " 0x0 0xFFFFFFFFFFFFFFFF
detach
quit
EOF

echo "Searching process memory for RIFF/WAVE headers..."
sudo lldb -s /tmp/find_audio.lldb > /tmp/audio_search.txt 2>&1

# Parse results
echo ""
echo "Results:"
grep -i "data found" /tmp/audio_search.txt || echo "No RIFF headers found yet"

echo ""
echo "Full output saved to: /tmp/audio_search.txt"
