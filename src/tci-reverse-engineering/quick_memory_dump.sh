#!/bin/bash
# Quick memory dump using proc filesystem

PID=$(pgrep "Pro Tools")

if [ -z "$PID" ]; then
    echo "❌ Pro Tools not running"
    exit 1
fi

echo "✓ Found Pro Tools (PID: $PID)"
echo ""

# Get a medium-sized heap region
region=$(sudo vmmap $PID | grep "MALLOC_LARGE" | head -1 | awk '{print $2}')

if [ -z "$region" ]; then
    echo "No MALLOC_LARGE, trying MALLOC_MEDIUM..."
    region=$(sudo vmmap $PID | grep "MALLOC_MEDIUM" | head -3 | tail -1 | awk '{print $2}')
fi

if [ -z "$region" ]; then
    echo "❌ No suitable region found"
    exit 1
fi

start=$(echo $region | cut -d'-' -f1)
end=$(echo $region | cut -d'-' -f2)

echo "Dumping region: $start - $end"

# Use gdb instead (faster than lldb for memory dumps)
cat > /tmp/gdb_dump.txt << EOF
attach $PID
dump binary memory /tmp/audio_memory.bin 0x$start 0x$end
detach
quit
EOF

sudo gdb -batch -x /tmp/gdb_dump.txt 2>&1 | grep -v "warning"

if [ -f "/tmp/audio_memory.bin" ]; then
    size=$(ls -lh /tmp/audio_memory.bin | awk '{print $5}')
    echo ""
    echo "✓ Dumped $size to /tmp/audio_memory.bin"
    echo ""
    echo "Analyzing..."
    
    # Check if it contains audio patterns
    hexdump -C /tmp/audio_memory.bin | head -20
    
    echo ""
    echo "Trying to extract as raw PCM..."
    
    # Convert to WAV (assume stereo 16-bit 48kHz)
    sox -r 48000 -e signed -b 16 -c 2 /tmp/audio_memory.bin /tmp/extracted_audio.wav 2>/dev/null
    
    if [ -f "/tmp/extracted_audio.wav" ]; then
        echo "✓ Created /tmp/extracted_audio.wav"
        echo "Play it: afplay /tmp/extracted_audio.wav"
    fi
else
    echo "❌ Memory dump failed"
fi
