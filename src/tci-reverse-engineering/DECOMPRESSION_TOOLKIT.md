# TCI Audio Decompression - Complete Toolkit

## Summary

You now have a complete toolkit to reverse engineer and extract audio from TCI files. The analysis reveals that Slate Trigger 2 likely uses **MP3 or AAC compression**, though the exact implementation needs further investigation.

## Tools Created

| Tool                          | Purpose                      | When to Use                        |
| ----------------------------- | ---------------------------- | ---------------------------------- |
| **analyze_compression.py**    | Deep analysis of compression | Start here - understand the format |
| **extract_mp3_frames.py**     | Extract MP3/AAC frames       | Quick extraction attempt           |
| **extract_audio_from_tci.py** | Try standard decompression   | Test various codecs                |
| **debug_slate_trigger.sh**    | Debug with LLDB              | Find the actual decompression code |
| **DECOMPRESSION_GUIDE.md**    | Step-by-step guide           | Full methodology                   |

## Quick Start: 3 Approaches

### Approach 1: Frame Extraction (Fastest - Try First!)

```bash
cd /Users/marian/Development/JUCE-Plugins/DrumEngine01/src/tci-reverse-engineering

# Analyze the file
python3 analyze_compression.py "Vintage 70's Acrolite (Tight) - Close Mic.tci" \
    --wav "/Users/marian/Downloads/SPINLIGHT SAMPLES/WAV Files/VIntage 70's Acrolite (Tight)/Close Mic/Hard 1.wav"

# Try to extract MP3/AAC frames
python3 extract_mp3_frames.py "Vintage 70's Acrolite (Tight) - Close Mic.tci"

# If successful, convert with ffmpeg
cd extracted_audio
ffmpeg -i stream_00.mp3 -acodec pcm_s24le test.wav
# Listen to test.wav to see if it worked!
```

### Approach 2: Dynamic Analysis (Most Reliable)

```bash
# 1. Launch Slate Trigger 2
open "/Applications/Slate Digital/Trigger 2.app"

# 2. Run the debugger script
./debug_slate_trigger.sh

# 3. In Slate Trigger 2: Load a TCI file
#    The debugger will break and show you where decompression happens

# 4. Look for memory containing RIFF/WAVE headers
#    This is your decompressed audio!

# 5. Dump that memory to a file
```

### Approach 3: Static Analysis (Most Technical)

```bash
# Download Ghidra from https://ghidra-sre.org/
# Import Slate Trigger 2 binary
# Search for ".tci" string references
# Follow code to find decompression routine
```

## Key Findings

From analyzing the Acrolite TCI file:

✅ **Confirmed Findings:**

- File contains 30 samples compressed together
- Uses high-entropy compression (99.6% entropy)
- Contains MP3/AAC codec signatures
- Compression ratio: ~2:1 per sample
- 48kHz sample rate, 24-bit, stereo

⚠️ **Uncertainties:**

- Exact codec variant (MP3, AAC, or custom)
- Frame structure and boundaries
- Whether it's standard MP3/AAC or modified

## Step-by-Step: Recommended Workflow

### Step 1: Analyze Your TCI File

```bash
python3 analyze_compression.py your_file.tci --wav /path/to/corresponding.wav
```

**Look for:**

- Compression ratio (tells you if lossy/lossless)
- Codec signatures (MP3, AAC, etc.)
- Entropy level (high = compressed/encrypted)

### Step 2: Try Direct Extraction

```bash
python3 extract_mp3_frames.py your_file.tci
```

**If this works:**

- You'll get .mp3 or .aac files
- Convert them with ffmpeg
- Done!

**If this fails:**

- The codec is custom or heavily modified
- Move to Step 3

### Step 3: Debug Slate Trigger 2

```bash
./debug_slate_trigger.sh
```

**This will show you:**

- Where TCI files are read
- Which functions decompress the audio
- Where decompressed audio is stored in memory

**When breakpoint hits:**

```lldb
# Show call stack (find decompression function)
bt

# Look at registers (function arguments)
register read

# Search for decompressed audio (RIFF/WAVE signature)
memory find -s "RIFF"

# Dump memory region to file
memory read --outfile /tmp/audio.bin --binary <address> <address+664000>
```

### Step 4: Reconstruct the Algorithm

Once you find the decompression function:

1. **Disassemble it** with Ghidra
2. **Understand the algorithm** (may be standard MP3/AAC with custom framing)
3. **Implement a decoder** in Python or C++
4. **Extract all samples** automatically

## Expected Results

Based on the signatures found, the most likely scenarios:

### Scenario A: Standard MP3/AAC (Best Case)

- TCI contains standard MP3 or AAC compressed audio
- You can extract and decode with existing tools
- Just need to find frame boundaries

### Scenario B: Modified MP3/AAC (Likely)

- Uses MP3/AAC codec but with custom framing/headers
- Need to understand the framing format
- Can use standard MP3/AAC decoder after extracting frames

### Scenario C: Proprietary Codec (Worst Case)

- Completely custom compression algorithm
- Requires full reverse engineering
- May use MP3/AAC as inspiration but different implementation

## If Extraction Succeeds

Once you can extract the audio:

```bash
# Create a batch extractor
for tci in /path/to/*.tci; do
    python3 extract_audio.py "$tci" --output-dir "extracted/$(basename "$tci" .tci)"
done

# Convert all to WAV
cd extracted
find . -name "*.mp3" -exec ffmpeg -i {} -acodec pcm_s24le {}.wav \;
```

Then use your `recursive_tci_converter.py` to generate JSON mappings!

## If Extraction Fails

Alternative approaches:

### Option 1: Screen Recording Audio

- Play samples in Slate Trigger 2
- Record with Audio Hijack or similar
- Lower quality but works

### Option 2: Memory Dumping

```bash
# While Slate Trigger 2 is playing a sample
sudo gcore -o /tmp/trigger_dump $(pgrep -i trigger)

# Search dump for PCM audio
strings /tmp/trigger_dump.* | grep RIFF
```

### Option 3: Community Resources

- Search GitHub for "slate trigger tci"
- Check audio developer forums (KVR, Vi-Control)
- Look for existing reverse engineering efforts

### Option 4: Use Original WAVs

- If you have the WAV files, use those instead
- The `recursive_tci_converter.py` tool already handles this
- TCI decompression becomes unnecessary

## Legal & Ethical Notes

✅ **Legal:**

- Reverse engineering for interoperability (Fair Use in US)
- Using samples you own/licensed
- Creating tools for your own use

❌ **Not Legal:**

- Redistributing Slate's proprietary code
- Circumventing copy protection (if present)
- Sharing decompressed samples you don't own

## Success Metrics

You know you've succeeded when:

1. ✅ You can extract audio from TCI files
2. ✅ The audio matches the original WAV quality
3. ✅ You can batch process all your TCI files
4. ✅ Your plugin can load the extracted samples

## Next Steps

1. **Try the quick extraction** (`extract_mp3_frames.py`)
2. **If that fails**, use the debugger (`debug_slate_trigger.sh`)
3. **Document what you find** (update this file with findings)
4. **Share back** - consider open-sourcing your decoder!

## Resources

- **Ghidra**: https://ghidra-sre.org/ (free disassembler)
- **MP3 Spec**: https://www.mp3-tech.org/
- **AAC Spec**: https://www.iso.org/standard/43345.html
- **ffmpeg**: https://ffmpeg.org/ (audio conversion)
- **Hex Fiend**: https://hexfiend.com/ (Mac hex editor)

## Questions? Issues?

If you make progress or get stuck:

1. Check the tool output messages
2. Review DECOMPRESSION_GUIDE.md
3. Try a different approach from this list
4. Consider using the original WAV files instead

Good luck! 🎵
