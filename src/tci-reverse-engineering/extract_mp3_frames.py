#!/usr/bin/env python3
"""
Extract MP3/AAC Frames from TCI Files
Based on finding codec signatures in the compressed data
"""

import struct
import sys
from pathlib import Path

class MP3AAC_Extractor:
    def __init__(self, tci_path):
        self.tci_path = Path(tci_path)
        self.data = self.tci_path.read_bytes()
        
    def find_all_mp3_frames(self):
        """Find all MP3 frame sync markers"""
        markers = []
        
        # MP3 frame sync: 0xFF followed by 0xFB, 0xFA, 0xF3, 0xF2
        # AAC frame sync: 0xFF followed by 0xF1, 0xF9
        sync_bytes = [0xFB, 0xFA, 0xF3, 0xF2, 0xF1, 0xF9]
        
        i = 0x80  # Start after header
        while i < len(self.data) - 1:
            if self.data[i] == 0xFF and self.data[i+1] in sync_bytes:
                # Found potential frame
                codec_type = 'MP3' if self.data[i+1] in [0xFB, 0xFA, 0xF3, 0xF2] else 'AAC'
                
                # Try to parse frame header to get size
                frame_info = self.parse_mp3_aac_header(i, codec_type)
                if frame_info:
                    markers.append(frame_info)
                    i += frame_info['size']  # Skip to next potential frame
                else:
                    i += 1
            else:
                i += 1
        
        return markers
    
    def parse_mp3_aac_header(self, offset, codec_type):
        """Parse MP3/AAC frame header to determine frame size"""
        if offset + 4 > len(self.data):
            return None
        
        try:
            if codec_type == 'MP3':
                return self.parse_mp3_header(offset)
            else:
                return self.parse_aac_header(offset)
        except:
            return None
    
    def parse_mp3_header(self, offset):
        """Parse MP3 frame header"""
        # MP3 frame header is 4 bytes
        header = struct.unpack('>I', self.data[offset:offset+4])[0]
        
        # Check sync word (11 bits set)
        if (header & 0xFFE00000) != 0xFFE00000:
            return None
        
        # Extract fields
        version = (header >> 19) & 0x3
        layer = (header >> 17) & 0x3
        bitrate_index = (header >> 12) & 0xF
        sample_rate_index = (header >> 10) & 0x3
        padding = (header >> 9) & 0x1
        
        # Bitrate table (MPEG1, Layer III)
        bitrates = [0, 32, 40, 48, 56, 64, 80, 96, 112, 128, 160, 192, 224, 256, 320, 0]
        sample_rates = [44100, 48000, 32000, 0]
        
        if bitrate_index >= len(bitrates) or sample_rate_index >= len(sample_rates):
            return None
        
        bitrate = bitrates[bitrate_index] * 1000
        sample_rate = sample_rates[sample_rate_index]
        
        if bitrate == 0 or sample_rate == 0:
            return None
        
        # Calculate frame size
        # For Layer III: FrameSize = 144 * BitRate / SampleRate + Padding
        frame_size = int((144 * bitrate) / sample_rate) + padding
        
        if frame_size < 100 or frame_size > 10000:  # Sanity check
            return None
        
        return {
            'offset': offset,
            'size': frame_size,
            'type': 'MP3',
            'bitrate': bitrate,
            'sample_rate': sample_rate
        }
    
    def parse_aac_header(self, offset):
        """Parse AAC ADTS frame header"""
        if offset + 7 > len(self.data):
            return None
        
        # AAC ADTS header is 7 or 9 bytes
        header = self.data[offset:offset+7]
        
        # Check sync word
        if header[0] != 0xFF or (header[1] & 0xF0) != 0xF0:
            return None
        
        # Extract frame length (13 bits at offset 30)
        frame_length = ((header[3] & 0x03) << 11) | (header[4] << 3) | ((header[5] & 0xE0) >> 5)
        
        if frame_length < 7 or frame_length > 10000:  # Sanity check
            return None
        
        return {
            'offset': offset,
            'size': frame_length,
            'type': 'AAC',
            'bitrate': 0,  # Variable
            'sample_rate': 48000  # Assumed
        }
    
    def extract_audio_stream(self, output_path):
        """Extract continuous audio stream"""
        frames = self.find_all_mp3_frames()
        
        if not frames:
            print("No MP3/AAC frames found")
            return False
        
        print(f"Found {len(frames)} potential audio frames")
        
        # Group frames by type and proximity
        streams = self.group_frames_into_streams(frames)
        
        print(f"Identified {len(streams)} audio streams")
        
        output_path = Path(output_path)
        output_path.mkdir(parents=True, exist_ok=True)
        
        for idx, stream in enumerate(streams):
            frame_type = stream[0]['type']
            ext = 'mp3' if frame_type == 'MP3' else 'aac'
            output_file = output_path / f"stream_{idx:02d}.{ext}"
            
            # Extract all frames in this stream
            with open(output_file, 'wb') as f:
                for frame in stream:
                    frame_data = self.data[frame['offset']:frame['offset'] + frame['size']]
                    f.write(frame_data)
            
            total_size = sum(frame['size'] for frame in stream)
            print(f"  Stream {idx}: {len(stream)} frames, {total_size:,} bytes -> {output_file}")
        
        return True
    
    def group_frames_into_streams(self, frames, max_gap=1000):
        """Group frames into continuous streams"""
        if not frames:
            return []
        
        streams = []
        current_stream = [frames[0]]
        
        for i in range(1, len(frames)):
            prev_frame = frames[i-1]
            curr_frame = frames[i]
            
            # Check if frames are contiguous (same type, close together)
            gap = curr_frame['offset'] - (prev_frame['offset'] + prev_frame['size'])
            
            if curr_frame['type'] == prev_frame['type'] and gap < max_gap:
                current_stream.append(curr_frame)
            else:
                # Start new stream
                if len(current_stream) > 10:  # Only save streams with enough frames
                    streams.append(current_stream)
                current_stream = [curr_frame]
        
        # Add last stream
        if len(current_stream) > 10:
            streams.append(current_stream)
        
        return streams
    
    def analyze_frame_distribution(self):
        """Analyze how frames are distributed in the file"""
        print("=" * 80)
        print("MP3/AAC Frame Analysis")
        print("=" * 80)
        print(f"File: {self.tci_path.name}")
        print()
        
        frames = self.find_all_mp3_frames()
        
        if not frames:
            print("✗ No MP3/AAC frames found")
            return
        
        print(f"✓ Found {len(frames)} potential frames")
        print()
        
        # Count by type
        mp3_frames = [f for f in frames if f['type'] == 'MP3']
        aac_frames = [f for f in frames if f['type'] == 'AAC']
        
        print(f"Frame Types:")
        print(f"  MP3: {len(mp3_frames)} frames")
        print(f"  AAC: {len(aac_frames)} frames")
        print()
        
        # Show first few frames
        print("First 10 frames:")
        for i, frame in enumerate(frames[:10]):
            print(f"  {i+1}. Offset: 0x{frame['offset']:X}, "
                  f"Size: {frame['size']} bytes, "
                  f"Type: {frame['type']}")
        
        # Analyze streams
        streams = self.group_frames_into_streams(frames)
        print(f"\nIdentified {len(streams)} continuous streams:")
        for i, stream in enumerate(streams):
            total_size = sum(f['size'] for f in stream)
            start_offset = stream[0]['offset']
            end_offset = stream[-1]['offset'] + stream[-1]['size']
            duration_est = total_size / (stream[0].get('bitrate', 128000) / 8) if stream[0].get('bitrate') else 0
            
            print(f"  Stream {i+1}: {len(stream)} frames, "
                  f"{total_size:,} bytes, "
                  f"0x{start_offset:X}-0x{end_offset:X}")
            if duration_est > 0:
                print(f"           Estimated duration: {duration_est:.2f} seconds")

def main():
    import argparse
    
    parser = argparse.ArgumentParser(
        description='Extract MP3/AAC audio frames from TCI files',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Analyze frame distribution
  python3 extract_mp3_frames.py file.tci --analyze
  
  # Extract audio streams
  python3 extract_mp3_frames.py file.tci --output-dir extracted
  
  # Decode extracted MP3 with ffmpeg
  ffmpeg -i extracted/stream_00.mp3 -acodec pcm_s24le output.wav
        """
    )
    
    parser.add_argument('tci_file', help='TCI file to process')
    parser.add_argument('--output-dir', '-o', default='extracted_audio',
                       help='Output directory for extracted audio')
    parser.add_argument('--analyze', action='store_true',
                       help='Only analyze, do not extract')
    
    args = parser.parse_args()
    
    if not Path(args.tci_file).exists():
        print(f"Error: File not found: {args.tci_file}")
        sys.exit(1)
    
    extractor = MP3AAC_Extractor(args.tci_file)
    
    if args.analyze:
        extractor.analyze_frame_distribution()
    else:
        extractor.analyze_frame_distribution()
        print("\n" + "=" * 80)
        print("Extracting Audio Streams...")
        print("=" * 80)
        
        success = extractor.extract_audio_stream(args.output_dir)
        
        if success:
            print("\n✓ Extraction complete!")
            print(f"\nNext steps:")
            print(f"1. Try playing the extracted files with VLC or ffmpeg")
            print(f"2. Convert to WAV:")
            print(f"   cd {args.output_dir}")
            print(f"   for f in *.mp3; do ffmpeg -i \"$f\" -acodec pcm_s24le \"${{f%.mp3}}.wav\"; done")
            print(f"   for f in *.aac; do ffmpeg -i \"$f\" -acodec pcm_s24le \"${{f%.aac}}.wav\"; done")
        else:
            print("\n✗ No audio frames found")
            print("\nThe TCI file may use a different compression method.")
            print("See DECOMPRESSION_GUIDE.md for more approaches.")

if __name__ == "__main__":
    main()
