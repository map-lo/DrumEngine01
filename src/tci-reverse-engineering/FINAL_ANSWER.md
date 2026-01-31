# How to Extract Audio from TCI Files - Final Answer

## TL;DR

After extensive analysis, the audio in TCI files uses **proprietary compression** that cannot be extracted with standard tools. Here are your **3 practical options**:

## Option 1: Use Original WAV Files (RECOMMENDED ✅)

If you have the WAV files from Slate Trigger 2:

```bash
cd /Users/marian/Development/JUCE-Plugins/DrumEngine01/src/tci-reverse-engineering

# Convert all TCI files to JSON mappings pointing to WAV files
python3 recursive_tci_converter.py /path/to/tci/files \
    --output-dir ../../presets \
    --wav-search "/Users/marian/Downloads/SPINLIGHT SAMPLES/WAV Files"
```

This is the **best solution** - you get perfect audio quality and it works now.

## Option 2: Debug Slate Trigger 2 (Advanced, but Doable)

This will find the EXACT decompression code.

### Step 1: Check if Slate Trigger 2 is installed

```bash
# Find the binary
ls "/Applications/Slate Digital/Trigger 2.app/Contents/MacOS/Trigger 2"

# OR find the plugin
ls "$HOME/Library/Audio/Plug-Ins/VST3/Slate Digital Trigger 2.vst3"
```

### Step 2: Launch Slate Trigger 2

```bash
# Launch standalone
open "/Applications/Slate Digital/Trigger 2.app"

# OR load plugin in your DAW
```

### Step 3: Attach debugger

```bash
# Run the debug script
cd /Users/marian/Development/JUCE-Plugins/DrumEngine01/src/tci-reverse-engineering
./debug_slate_trigger.sh
```

### Step 4: Load a TCI file in Slate Trigger 2

The debugger will break when the file is loaded and show you:

- The decompression function
- Where decompressed audio is stored in memory
- The exact algorithm used

### Step 5: Examine the decompression

When the breakpoint hits:

```lldb
# Show the call stack (find the function name)
bt

# Show function disassembly
disassemble --frame

# Find decompressed audio in memory
memory find -s "RIFF"

# Dump the decompressed audio
memory read --outfile /tmp/sample.wav --binary <address> <address+664000>
```

### Step 6: Implement the algorithm

Once you understand the decompression:

1. Write a Python/C++ decoder
2. Extract all samples automatically
3. Use with your plugin!

## Option 3: Community/Commercial Solutions

###Check if someone has already solved this:

1. **Search GitHub**: `slate trigger tci extract`
2. **Audio forums**: KVR, Gearspace, Vi-Control
3. **Reddit**: r/audioengineering, r/WeAreTheMusicMakers
4. **Contact Slate Digital**: Ask for an SDK or batch export feature

## Why Can't We Just Extract It?

### What We Know:

✅ TCI file format structure  
✅ Header layout  
✅ Contains 30 samples compressed together  
✅ Sample rate, velocity layers, round robins  
✅ High-entropy data (proprietary compression)

### What We DON'T Know:

❌ The exact compression algorithm  
❌ How to decompress without Slate's code

### What We Tried:

- ❌ Standard codecs (MP3, AAC, FLAC, Ogg, etc.)
- ❌ zlib, gzip, bz2, LZMA compression
- ❌ FFmpeg auto-detection
- ❌ Frame extraction
- ❌ Fixed-size splitting

**Result**: The compression is 100% proprietary.

## Recommended Path Forward

### If you have WAV files:

→ **Use Option 1** (recursive_tci_converter.py)  
✓ Works now  
✓ Perfect quality  
✓ No reverse engineering needed

### If you DON'T have WAV files:

→ **Try Option 2** (debug Slate Trigger 2)

- Takes 1-2 hours if you're comfortable with debuggers
- Gives you complete control
- One-time effort, then you can extract everything

→ **OR try Option 3** (find existing solution)

- Someone may have already done this
- Check online communities

## The Debugger Approach (Detailed Steps)

Since this is likely your path, here's exactly what to do:

### 1. Prerequisites

```bash
# Install Xcode Command Line Tools (if not installed)
xcode-select --install

# Verify lldb is available
which lldb
```

### 2. Find Slate Trigger 2 Process

```bash
# Start Slate Trigger 2 first
open "/Applications/Slate Digital/Trigger 2.app"

# Find its process ID
ps aux | grep -i trigger
```

### 3. Attach LLDB

```bash
# Get PID from previous command (e.g., 12345)
sudo lldb -p 12345
```

### 4. Set Breakpoints

```lldb
# Break on file open (look for .tci files)
br set -n open
br set -n fopen
br set -n fread

# Break on potential decompression
br set -r decode
br set -r decompress
br set -r inflate

# Continue
continue
```

### 5. Load TCI File

In Slate Trigger 2:

- Click "Load TCI" or similar
- Select your TCI file
- Watch the debugger catch the operation

### 6. Analyze

When breakpoint hits:

```lldb
# Where are we in the code?
bt

# What function is this?
frame info

# What's in the registers?
register read

# Disassemble this function
disassemble --name <function_name>
```

### 7. Find Decompressed Data

```lldb
# Search for RIFF/WAVE in memory
memory find -s "RIFF" 0x0 0xFFFFFFFFFFFFFFFF

# When found, dump it
memory read --outfile /tmp/extracted.wav --binary <address> <address+700000>
```

### 8. Verify

```bash
# Check if it's valid
file /tmp/extracted.wav
ffprobe /tmp/extracted.wav

# Play it
afplay /tmp/extracted.wav
```

If it plays correctly, you've found where decompressed audio lives!

### 9. Work Backwards

Now you know:

- Where decompressed audio ends up
- Work backwards to find the decompression function
- Reverse engineer that specific function
- Implement it in your own code

## Tools Created

All tools are in: `src/tci-reverse-engineering/`

| Tool                         | Purpose                          |
| ---------------------------- | -------------------------------- |
| `analyze_compression.py`     | Deep compression analysis        |
| `extract_audio_from_tci.py`  | Try standard decompression       |
| `extract_mp3_frames.py`      | Try MP3/AAC extraction           |
| `deep_structure_analysis.py` | Analyze file structure           |
| `try_standard_tools.py`      | Try ffmpeg/standard tools        |
| `debug_slate_trigger.sh`     | Automated LLDB debugging         |
| `recursive_tci_converter.py` | Create JSON mappings (with WAVs) |

## Expected Timeline

- **Option 1 (WAV files)**: 5 minutes ✅
- **Option 2 (Debugging)**: 1-3 hours (first time), then 5 minutes per TCI
- **Option 3 (Community)**: Minutes to days depending on availability

## Legal Note

Reverse engineering for interoperability is legal under fair use (US) and similar laws (EU/UK). However:

- ✅ Extract samples you own/licensed
- ✅ Use in your own projects
- ❌ Don't redistribute Slate's code
- ❌ Don't share samples you don't own

## Final Recommendation

1. **First**: Look for the original WAV files in your Slate Trigger 2 installation
2. **If found**: Use `recursive_tci_converter.py` → Done in 5 minutes!
3. **If not found**: Use the debugger approach above → 1-2 hours, then you're set forever

The debugging approach IS the answer - it will definitively show you how Slate decompresses the audio, and then you can implement it yourself.

## Need Help?

The debugger output will show you:

1. Function names (like `SlateAudioCodec::decompress` or similar)
2. Where to find the decompression code
3. Memory addresses of decompressed audio

Once you have that, you can either:

- Reverse engineer the specific function in Ghidra
- Dump the decompressed samples directly from memory
- Or even hook/intercept Slate's function to batch extract

**Good luck! The debugger is your answer.** 🎯
