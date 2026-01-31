# Guide: Reverse Engineering TCI Audio Compression

## Key Findings

From analyzing `Vintage 70's Acrolite (Tight) - Close Mic.tci`:

1. **Compression Type**: The data contains signatures for **MP3** and **AAC** codecs
2. **Storage Format**: The TCI file contains **ALL 30 samples** in one file (9.8 MB total)
3. **Per-Sample Size**: ~328KB compressed vs ~664KB uncompressed (2:1 ratio per sample)
4. **Entropy**: 99.6% - highly compressed data

## Evidence of MP3/AAC Usage

Found codec signatures in the compressed data:

- **MP3 markers**: `0xFFFB`, `0xFFF3`, `0xFFF2` (MP3 frame headers)
- **AAC markers**: `0xFFF1`, `0xFFF9` (AAC frame headers)
- **ID3 tag**: Found at offset `0xC96EA` (MP3 metadata)

**Hypothesis**: Slate Digital is using **MP3 or AAC compression** for audio storage.

## Method 1: Extract MP3/AAC Frames (Fastest)

Since we found MP3/AAC signatures, try extracting them directly:

### Step 1: Search for MP3 Frames

```bash
python3 extract_mp3_frames.py "Vintage 70's Acrolite (Tight) - Close Mic.tci"
```

### Step 2: Decode with ffmpeg

```bash
ffmpeg -i extracted_frame.mp3 -acodec pcm_s24le output.wav
```

## Method 2: Dynamic Analysis with LLDB (Recommended for Full Understanding)

### Prerequisites

- Slate Trigger 2 installed
- Xcode command line tools (`xcode-select --install`)

### Step-by-Step

1. **Find Slate Trigger 2 executable**:

```bash
# For standalone app
APP="/Applications/Slate Digital/Trigger 2.app"
BINARY="$APP/Contents/MacOS/Trigger 2"

# For plugin (if VST3)
PLUGIN="$HOME/Library/Audio/Plug-Ins/VST3/Slate Digital Trigger 2.vst3"
BINARY="$PLUGIN/Contents/MacOS/Slate Digital Trigger 2"

# Check which exists
ls -la "$BINARY"
```

2. **Start Slate Trigger 2**:

```bash
open "/Applications/Slate Digital/Trigger 2.app"
# Or launch your DAW with the plugin
```

3. **Attach debugger**:

```bash
# Find process ID
ps aux | grep -i trigger

# Attach lldb
lldb -p <PID>
```

4. **Set breakpoints on file operations**:

```lldb
# Break when opening files
br set -n open
br set -n fopen
br set -n fread

# Break on potential audio decode functions
br set -r "decode|decompress|inflate"

# Continue execution
continue
```

5. **Load a TCI file in the app**, then check the breakpoints

6. **Examine memory when breakpoint hits**:

```lldb
# Print backtrace to see call stack
bt

# Show registers
register read

# Examine memory (look for RIFF/WAVE)
memory find -s "RIFF" -- 0x0 0xFFFFFFFFFFFFFFFF

# Dump memory region to file
memory read --outfile /tmp/audio_dump.bin --binary <address> <address+size>
```

## Method 3: Memory Dumping (No Debugger Required)

### Step 1: Install memory dump tool

```bash
brew install gdb
# Or use vmmap (built-in macOS)
```

### Step 2: Dump process memory

```bash
# Get PID
PID=$(ps aux | grep -i "Slate.*Trigger" | grep -v grep | awk '{print $2}')

# Dump all memory regions
sudo gcore -o trigger_dump $PID

# Or use vmmap
sudo vmmap $PID > trigger_memory_map.txt
```

### Step 3: Search for audio data

```bash
# Search for WAV headers in dump
strings trigger_dump.* | grep -i "RIFF\|WAVE"

# Or search for PCM pattern (24-bit audio has distinctive patterns)
hexdump -C trigger_dump.* | grep "00 00 00 00 00 00"
```

## Method 4: Static Binary Analysis

### Use Ghidra (Free, Powerful)

1. **Download Ghidra**: https://ghidra-sre.org/

2. **Create new project** and import Slate Trigger 2 binary

3. **Auto-analyze** the binary

4. **Search for strings**:
   - Search for: ".tci", "TRIGGER", "compress", "decode"
   - This will show you the file loading code

5. **Find decompression function**:
   - Look at xrefs (cross-references) to the ".tci" string
   - Follow the code flow to find where file data is processed
   - Look for function calls that transform the data

### Key Functions to Look For

Common function names in audio codecs:

- `*_decode`, `*_decompress`, `*_inflate`
- `mp3_decode`, `aac_decode`
- `read_audio`, `load_sample`

## Method 5: File Format Reverse Engineering

### Create a parser script

Run the experimental MP3 extractor:

```bash
python3 extract_mp3_frames.py "file.tci" --output-dir extracted
```

## Practical Next Steps

### Quick Wins (Try First):

1. **Extract MP3/AAC frames** using the tool I'll create next
2. **Try ffmpeg** to decode the extracted frames
3. **Memory dump** while Slate Trigger 2 is running

### Deep Dive (If Quick Wins Fail):

1. **Attach debugger** and trace file loading
2. **Disassemble** with Ghidra to find decompression code
3. **Reverse engineer** the exact algorithm

## Tools Created

1. `analyze_compression.py` - Detailed compression analysis ✓
2. `extract_mp3_frames.py` - Extract MP3/AAC frames (creating next)
3. `debug_tci.md` - This guide
4. `memory_search.py` - Search memory dumps for audio (creating next)

## Expected Outcome

Based on the signatures found, you should be able to:

1. **Extract** individual MP3/AAC encoded samples from TCI
2. **Decode** them using ffmpeg or similar tools
3. **Convert** to WAV for your plugin

The TCI format likely stores:

```
[128-byte header]
[Sample 1: MP3/AAC data]
[Sample 2: MP3/AAC data]
...
[Sample 30: MP3/AAC data]
```

Each sample is probably preceded by a small header indicating its size.

## Legal Note

This reverse engineering is for **interoperability** purposes (loading samples you own in your own plugin). Ensure you:

- Own or have licensed the samples
- Don't redistribute Slate Digital's code or algorithms
- Use extracted samples only in your own projects
