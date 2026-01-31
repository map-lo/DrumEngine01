#!/usr/bin/env python3
"""Decode TCI using CWaveData::decompressToFloatData logic."""

import io
import os
import struct
import sys
import wave
import zlib
import xml.etree.ElementTree as ET

SIGNATURES = [
    b"TRIGGER COMPRESSED INSTRUMENT\x00",
    b"TRIGGER COMPRESSED INSTRUMENT 2\x00",
    b"TRIGGER COMPRESSED INSTRUMENT 2",
    b"TRIGGER COMPRESSED INSTRUMENT",
]
DEFAULT_BLOCK_SIZE = 0xC9


def read_u32le(f):
    data = f.read(4)
    if len(data) < 4:
        return None
    return struct.unpack('<I', data)[0]


def read_u32le(data, offset):
    if offset + 4 > len(data):
        return None
    return struct.unpack_from('<I', data, offset)[0]


def find_tlv_start(data):
    sig_index = -1
    sig_value = None
    for sig in SIGNATURES:
        sig_index = data.find(sig)
        if sig_index != -1:
            sig_value = sig
            break

    if sig_index == -1:
        return None

    scan_start = sig_index + len(sig_value)
    scan_end = min(scan_start + 0x100, len(data) - 32)

    for offset in range(scan_start, scan_end):
        v1 = read_u32le(data, offset)
        v2 = read_u32le(data, offset + 4)
        v3 = read_u32le(data, offset + 8)
        v4 = read_u32le(data, offset + 12)
        v5 = read_u32le(data, offset + 16)
        v6 = read_u32le(data, offset + 20)
        v7 = read_u32le(data, offset + 24)
        v8 = read_u32le(data, offset + 28)
        if None in (v1, v2, v3, v4, v5, v6, v7, v8):
            continue
        if v1 == 1 and v3 == 4 and v4 == 0x15 and v6 == 0 and v7 == 2:
            return offset + 32

    return None


def parse_tci_waves(path):
    with open(path, 'rb') as f:
        data = f.read()

    start = find_tlv_start(data)
    if start is None:
        return None

    offset = start
    chunks = []
    current_sample_rate = 44100

    while offset + 8 <= len(data):
        tag = read_u32le(data, offset)
        size = read_u32le(data, offset + 4)
        if tag is None or size is None:
            break

        offset += 8
        payload_end = offset + size
        if payload_end > len(data):
            break

        if tag == 0x14 and size >= 4:
            current_sample_rate = read_u32le(data, offset) or current_sample_rate

        if tag == 5 and size >= 9:
            channels = data[offset]
            bit_len = read_u32le(data, offset + 1)
            sample_count = read_u32le(data, offset + 5)
            payload_len = size - 9
            payload_start = offset + 9
            payload = data[payload_start:payload_start + payload_len]

            chunks.append(
                {
                    "offset": offset,
                    "wave_id": tag,
                    "channels": channels,
                    "bit_len": bit_len,
                    "sample_count": sample_count,
                    "payload_len": payload_len,
                    "payload": payload,
                    "sample_rate": current_sample_rate,
                }
            )

        offset = payload_end

    return chunks


def find_zlib_xml(data):
    for offset in range(len(data) - 2):
        if data[offset:offset + 2] not in (b"\x78\x9C", b"\x78\xDA"):
            continue
        try:
            out = zlib.decompress(data[offset:])
        except Exception:
            continue
        text = out.decode("utf-8", errors="ignore")
        start = text.find("<")
        end = text.rfind(">")
        if start == -1 or end == -1:
            continue
        xml_text = text[start:end + 1]
        try:
            root = ET.fromstring(xml_text)
        except ET.ParseError:
            continue
        return offset, root
    return None, None


def parse_tci2_waves(path):
    with open(path, 'rb') as f:
        data = f.read()

    zoff, root = find_zlib_xml(data)
    if root is None:
        return None

    data_count = int(root.attrib.get("data_count", "0"))
    if data_count == 0:
        return None

    comp_bits = []
    sample_counts = []
    stereo_flags = []

    for i in range(data_count):
        comp = root.attrib.get(f"wd{i}comp1")
        samples = root.attrib.get(f"wd{i}samples")
        stereo = root.attrib.get(f"wd{i}stereo", "0")
        if comp is None or samples is None:
            return None
        comp_bits.append(int(comp))
        sample_counts.append(int(samples))
        stereo_flags.append(int(stereo))

    total_bytes = sum((c + 7) // 8 for c in comp_bits)
    blob_start = zoff - total_bytes
    if blob_start < 0:
        return None

    sample_rate = int(root.attrib.get("sample_rate", "48000"))
    chunks = []
    cursor = blob_start
    for i in range(data_count):
        bit_len = comp_bits[i]
        payload_len = (bit_len + 7) // 8
        payload = data[cursor:cursor + payload_len]
        cursor += payload_len

        channels = 2 if stereo_flags[i] else 1
        chunks.append(
            {
                "offset": cursor - payload_len,
                "wave_id": i,
                "channels": channels,
                "bit_len": bit_len,
                "sample_count": sample_counts[i],
                "payload_len": payload_len,
                "payload": payload,
                "sample_rate": sample_rate,
            }
        )

    return chunks


def find_wave_chunks(path):
    with open(path, 'rb') as f:
        data = f.read()

    if not any(data.startswith(sig) for sig in SIGNATURES):
        raise ValueError("Not a TCI file")

    # Scan for wave chunk headers: [wave_id][data_len][channels][bit_len][sample_count]
    chunks = []
    for offset in range(0, len(data) - 20):
        wave_id = struct.unpack_from('<I', data, offset)[0]
        data_len = struct.unpack_from('<I', data, offset + 4)[0]
        if data_len < 16 or data_len > 10_000_000:
            continue
        channels = data[offset + 8]
        if channels not in (1, 2):
            continue
        bit_len = struct.unpack_from('<I', data, offset + 9)[0]
        sample_count = struct.unpack_from('<I', data, offset + 13)[0]
        if sample_count == 0 or sample_count > 1_000_000:
            continue
        payload_len = data_len - 9
        if payload_len <= 0 or offset + 8 + data_len > len(data):
            continue
        if bit_len > payload_len * 8 + 32:
            continue

        payload_start = offset + 17
        payload = data[payload_start:payload_start + payload_len]
        chunks.append(
            {
                "offset": offset,
                "wave_id": wave_id,
                "channels": channels,
                "bit_len": bit_len,
                "sample_count": sample_count,
                "payload_len": payload_len,
                "payload": payload,
                "sample_rate": 44100,
            }
        )

    return chunks


def decompress_bitstream(payload, bit_len, sample_count, block_size=8):
    """Implement CWaveData::decompressToFloatData with param_1=0."""
    if sample_count == 0 or bit_len <= 8:
        return []

    # Constants inferred from decompilation
    # scale factors likely +/- 1.0 / (1<<23)
    scale_pos = 1.0 / (1 << 23)
    scale_neg = -1.0 / (1 << 23)

    out = []

    uVar9 = payload[0]  # initial bit width
    bit_pos = 8
    block_count = 0

    for idx in range(sample_count):
        if (bit_pos >> 3) + 4 > len(payload):
            break
        # Read 32-bit word aligned to bit_pos
        word = struct.unpack('>I', payload[bit_pos >> 3: (bit_pos >> 3) + 4])[0]
        bVar8 = bit_pos & 7
        shifted = (word << bVar8) & 0xFFFFFFFF
        magnitude = (shifted & 0x7FFFFFFF) >> ((32 - uVar9) & 0x1F)
        scale = scale_pos if (shifted & 0x80000000) == 0 else scale_neg
        out.append(magnitude * scale)

        block_count += 1
        bit_pos += uVar9

        if block_count >= block_size:
            # Read next block bit width (8 bits)
            byte_index = bit_pos >> 3
            if byte_index + 2 > len(payload):
                break
            uVar9 = ((payload[byte_index + 1] << 16) | (payload[byte_index] << 24))
            uVar9 = ((uVar9 << (bit_pos & 7)) & 0xFFFFFFFF) >> 24
            bit_pos += 8
            block_count = 0

        if bit_pos >= bit_len:
            break

    return out


def count_decoded_samples(payload, bit_len, sample_count, block_size):
    if sample_count == 0 or bit_len <= 8:
        return 0

    uVar9 = payload[0]
    bit_pos = 8
    block_count = 0
    count = 0

    while count < sample_count:
        if (bit_pos >> 3) + 4 > len(payload):
            break

        count += 1
        block_count += 1
        bit_pos += uVar9

        if block_count >= block_size:
            byte_index = bit_pos >> 3
            if byte_index + 2 > len(payload):
                break
            uVar9 = ((payload[byte_index + 1] << 16) | (payload[byte_index] << 24))
            uVar9 = ((uVar9 << (bit_pos & 7)) & 0xFFFFFFFF) >> 24
            bit_pos += 8
            block_count = 0

        if bit_pos >= bit_len:
            break

    return count


def find_best_block_size(payload, bit_len, sample_count, candidates=None):
    if candidates is None:
        candidates = range(1, 256)

    best_size = None
    best_count = -1

    for size in candidates:
        decoded_count = count_decoded_samples(payload, bit_len, sample_count, size)
        if decoded_count > best_count:
            best_count = decoded_count
            best_size = size
        if decoded_count == sample_count:
            break

    decoded = decompress_bitstream(payload, bit_len, sample_count, block_size=best_size)
    return best_size, decoded


def write_wav(path, samples, sample_rate=44100, channels=1, sample_width=3):
    if sample_width == 2:
        int_samples = [max(-32768, min(32767, int(s * 32767))) for s in samples]
        raw = struct.pack('<' + 'h' * len(int_samples), *int_samples)
    elif sample_width == 3:
        int_samples = [max(-(1 << 23), min((1 << 23) - 1, int(s * ((1 << 23) - 1)))) for s in samples]
        raw = bytearray()
        for val in int_samples:
            raw.extend(int(val).to_bytes(3, byteorder='little', signed=True))
        raw = bytes(raw)
    else:
        raise ValueError(f'Unsupported sample_width: {sample_width}')

    with wave.open(path, 'wb') as wav:
        wav.setnchannels(channels)
        wav.setsampwidth(sample_width)
        wav.setframerate(sample_rate)
        wav.writeframes(raw)


def main():
    input_path = sys.argv[1] if len(sys.argv) > 1 else 'tci/sine_440hz.tci'
    output_dir = sys.argv[2] if len(sys.argv) > 2 else 'output'

    chunks = parse_tci_waves(input_path)
    if not chunks:
        chunks = parse_tci2_waves(input_path)
    if not chunks:
        chunks = find_wave_chunks(input_path)
    if not chunks:
        print('No wave chunk found')
        return

    os.makedirs(output_dir, exist_ok=True)
    base_name = os.path.splitext(os.path.basename(input_path))[0]

    print(f'Found {len(chunks)} wave chunks')

    for index, chunk in enumerate(chunks, start=1):
        print(
            f'Wave {index} info:',
            {
                'offset': chunk['offset'],
                'wave_id': chunk['wave_id'],
                'channels': chunk['channels'],
                'bit_len': chunk['bit_len'],
                'sample_count': chunk['sample_count'],
                'payload_len': chunk['payload_len'],
                'sample_rate': chunk['sample_rate'],
            },
        )

        block_size = DEFAULT_BLOCK_SIZE
        samples = decompress_bitstream(
            chunk['payload'],
            chunk['bit_len'],
            chunk['sample_count'],
            block_size=block_size,
        )

        if len(samples) < chunk['sample_count']:
            samples.extend([0.0] * (chunk['sample_count'] - len(samples)))

        print(f'Using block size: {block_size}')

        channels = chunk['channels']
        if channels > 1 and len(samples) % channels != 0:
            samples = samples[: len(samples) - (len(samples) % channels)]

        frames = len(samples) // channels if channels else 0
        print(f'Decoded {len(samples)} samples ({frames} frames)')

        wave_id = chunk['wave_id'] if chunk['wave_id'] is not None else index
        out_name = f"{base_name}_chunk{index}_wave{wave_id}_v3.wav"
        out_path = os.path.join(output_dir, out_name)
        write_wav(
            out_path,
            samples,
            sample_rate=chunk['sample_rate'],
            channels=channels,
            sample_width=3,
        )
        print(f'Wrote {out_path}')


if __name__ == '__main__':
    main()
