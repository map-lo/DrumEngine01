#!/bin/bash
# Extract decompressed audio from Pro Tools memory after loading TCI

echo "================================================================"
echo "Memory Audio Extraction from Pro Tools + Trigger 2"
echo "================================================================"
echo ""

PID=$(pgrep "Pro Tools")

if [ -z "$PID" ]; then
    echo "❌ Pro Tools is not running!"
    exit 1
fi

echo "✓ Found Pro Tools (PID: $PID)"
echo ""
echo "Make sure you have:"
echo "  1. Trigger 2 plugin loaded"
echo "  2. TCI file loaded"
echo "  3. Played at least one note (to decompress audio)"
echo ""
echo "Press Enter to start memory search..."
read

echo ""
echo "Getting memory regions from Pro Tools..."

# Get heap memory regions first
sudo vmmap $PID | grep -E "MALLOC_LARGE|MALLOC_HUGE" | awk '{print $2}' > /tmp/regions.txt

if [ ! -s /tmp/regions.txt ]; then
    echo "Getting general heap regions..."
    sudo vmmap $PID | grep "MALLOC" | head -20 | awk '{print $2}' > /tmp/regions.txt
fi

echo "Found $(wc -l < /tmp/regions.txt) memory regions to search"
echo ""
echo "Searching for RIFF/WAVE headers in memory..."

# Search each region
found_addresses=""
while IFS= read -r region; do
    start=$(echo $region | cut -d'-' -f1)
    end=$(echo $region | cut -d'-' -f2)
    
    if [ -n "$start" ] && [ -n "$end" ]; then
        echo "Searching region $start - $end..."
        
        cat > /tmp/search_region.lldb << EOF
process attach -p $PID
memory find -s "RIFF" 0x$start 0x$end
detach
quit
EOF
        
        result=$(sudo lldb -s /tmp/search_region.lldb 2>&1 | grep "data found")
        if [ -n "$result" ]; then
            echo "  ✓ Found in this region!"
            echo "$result" >> /tmp/memory_search_result.txt
            found_addresses="$found_addresses $result"
        fi
    fi
done < /tmp/regions.txt

if [ -z "$found_addresses" ]; then
    echo ""
    echo "No RIFF headers found in heap. Trying raw PCM search..."
    echo "(This means audio might be in raw format without WAV headers)"
fi

echo ""
echo "================================================================"
echo "Parsing results..."
echo "================================================================"

# Extract addresses
addresses=$(grep "data found at location" /tmp/memory_search_result.txt | awk '{print $NF}' | sort -u)

if [ -z "$addresses" ]; then
    echo "❌ No RIFF/WAVE headers found in memory"
    echo ""
    echo "This could mean:"
    echo "  1. Audio hasn't been decompressed yet - try playing more notes"
    echo "  2. Audio is in raw PCM format without WAV headers"
    echo "  3. Need to search for raw PCM data patterns"
    exit 1
fi

echo "✓ Found potential audio data at:"
echo "$addresses"
echo ""
echo "Extracting audio samples..."

count=1
for addr in $addresses; do
    output="/tmp/extracted_sample_${count}.wav"
    
    # Calculate end address (assume ~700KB per sample)
    end_addr=$(printf "0x%X" $((addr + 700000)))
    
    echo "Dumping memory from $addr to $end_addr..."
    
    cat > /tmp/dump_sample.lldb << EOF
process attach -p $PID
memory read --outfile $output --binary $addr $end_addr
quit
EOF
    
    sudo lldb -s /tmp/dump_sample.lldb > /dev/null 2>&1
    
    if [ -f "$output" ]; then
        size=$(ls -lh "$output" | awk '{print $5}')
        echo "  ✓ Extracted: $output ($size)"
        
        # Verify it's a valid WAV
        file_type=$(file "$output")
        echo "  Type: $file_type"
        
        count=$((count + 1))
    fi
done

echo ""
echo "================================================================"
echo "Done! Extracted $((count - 1)) samples"
echo "================================================================"
echo ""
echo "Check the files in /tmp/extracted_sample_*.wav"
echo "Play them with: afplay /tmp/extracted_sample_1.wav"
