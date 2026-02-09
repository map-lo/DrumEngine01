#!/usr/bin/env python3
import struct
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


def read_u32le(data, offset):
    if offset + 4 > len(data):
        return None
    return struct.unpack_from("<I", data, offset)[0]


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
        v = [read_u32le(data, offset + i * 4) for i in range(8)]
        if None in v:
            continue
        v1, v2, v3, v4, v5, v6, v7, v8 = v
        if v1 == 1 and v3 == 4 and v4 == 0x15 and v6 == 0 and v7 == 2:
            return offset + 32

    return None


def read_u8_bits(payload, start_bit):
    value = 0
    for j in range(8):
        bit_index = start_bit + j
        byte_index = bit_index >> 3
        shift = 7 - (bit_index & 7)
        bit = (payload[byte_index] >> shift) & 1
        value = (value << 1) | bit
    return value


def normalize_uvar9(value):
    if value < 1 or value > 25:
        return None
    return value


def find_valid_start_bit(payload, start_bit, bit_len, max_scan_bytes=16):
    if bit_len <= start_bit + 8:
        return None

    base_byte = start_bit // 8
    for offset in range(max_scan_bytes + 1):
        byte_index = base_byte + offset
        if byte_index >= len(payload):
            break
        u_var9 = normalize_uvar9(payload[byte_index])
        if u_var9 is not None:
            return start_bit + offset * 8
    return None


def trim_leading_padding(payload, bit_len):
    if bit_len <= 8:
        return payload, 0

    start_bit = find_valid_start_bit(payload, 0, bit_len)
    if start_bit is None:
        return payload, 0

    byte_offset = start_bit // 8
    if byte_offset <= 0:
        return payload, 0

    return payload[byte_offset:], byte_offset


def decode_bitstream(payload, bit_len, sample_count, block_size=DEFAULT_BLOCK_SIZE, start_bit=0):
    if sample_count == 0 or bit_len <= start_bit + 8:
        return [], start_bit

    scale_pos = 1.0 / (1 << 23)
    scale_neg = -1.0 / (1 << 23)

    out = []
    start_bit = find_valid_start_bit(payload, start_bit, bit_len)
    if start_bit is None:
        return [], start_bit

    u_var9 = read_u8_bits(payload, start_bit)
    u_var9 = normalize_uvar9(u_var9)
    if u_var9 is None:
        return [], start_bit

    bit_pos = start_bit + 8
    block_count = 0

    for _ in range(sample_count):
        if (bit_pos >> 3) + 4 > len(payload):
            break
        word = struct.unpack(">I", payload[bit_pos >> 3:(bit_pos >> 3) + 4])[0]
        b_var8 = bit_pos & 7
        shifted = (word << b_var8) & 0xFFFFFFFF
        magnitude = (shifted & 0x7FFFFFFF) >> ((32 - u_var9) & 0x1F)
        scale = scale_pos if (shifted & 0x80000000) == 0 else scale_neg
        out.append(magnitude * scale)

        block_count += 1
        bit_pos += u_var9

        if block_count >= block_size:
            byte_index = bit_pos >> 3
            if byte_index + 2 > len(payload):
                break
            u_var9 = ((payload[byte_index + 1] << 16) | (payload[byte_index] << 24))
            u_var9 = ((u_var9 << (bit_pos & 7)) & 0xFFFFFFFF) >> 24
            u_var9 = normalize_uvar9(u_var9)
            if u_var9 is None:
                break
            bit_pos += 8
            block_count = 0

        if bit_pos >= bit_len:
            break

    if len(out) < sample_count:
        out.extend([0.0] * (sample_count - len(out)))

    return out, bit_pos


def decompress_bitstream(payload, bit_len, sample_count, block_size=DEFAULT_BLOCK_SIZE, channels=1):
    if sample_count == 0 or bit_len <= 8:
        return []

    samples, _ = decode_bitstream(payload, bit_len, sample_count, block_size=block_size, start_bit=0)
    return samples


def write_wav(path, samples, sample_rate, channels, sample_width=3):
    if sample_width == 2:
        int_samples = [max(-32768, min(32767, int(s * 32767))) for s in samples]
        raw = struct.pack("<" + "h" * len(int_samples), *int_samples)
    elif sample_width == 3:
        int_samples = [
            max(-(1 << 23), min((1 << 23) - 1, int(s * ((1 << 23) - 1))))
            for s in samples
        ]
        raw = bytearray()
        for val in int_samples:
            raw.extend(int(val).to_bytes(3, byteorder="little", signed=True))
        raw = bytes(raw)
    else:
        raise ValueError(f"Unsupported sample_width: {sample_width}")

    with wave.open(path, "wb") as wav:
        wav.setnchannels(channels)
        wav.setsampwidth(sample_width)
        wav.setframerate(sample_rate)
        wav.writeframes(raw)


TLV_TAGS = {0x14, 5, 7, 8, 0x0b, 0x0c, 0x0f, 0x12, 0x13}


def parse_tci1_at(data, tlv_start):
    cursor = tlv_start
    chunks = []
    sample_rate = 44100
    mapping = {"sample_rate": sample_rate, "wave_chunks": 0, "articulations": []}
    current_art = None
    current_layer = 0
    current_rr = 0

    def ensure_layer(art, idx):
        while len(art["layers"]) <= idx:
            art["layers"].append({"velocity": None, "waves": []})
        return art["layers"][idx]

    while cursor + 8 <= len(data):
        tag = read_u32le(data, cursor)
        size = read_u32le(data, cursor + 4)
        if tag is None or size is None:
            break
        cursor += 8
        payload = data[cursor:cursor + size]

        if tag == 0x14 and size >= 4:
            sr = read_u32le(payload, 0)
            if sr:
                sample_rate = sr

        elif tag == 5 and size >= 9:
            channels = payload[0]
            bit_len = read_u32le(payload, 1)
            sample_count = read_u32le(payload, 5)
            payload_len = size - 9
            payload_start = cursor + 9
            chunk_payload = data[payload_start:payload_start + payload_len]
            chunks.append(
                {
                    "wave_id": len(chunks),
                    "channels": channels,
                    "bit_len": bit_len,
                    "sample_count": sample_count,
                    "payload": chunk_payload,
                    "sample_rate": sample_rate,
                }
            )

        elif tag == 7:
            if current_art is None:
                current_art = {"name": None, "layers": []}
                mapping["articulations"].append(current_art)
            current_layer = 0
            current_rr = 0

        elif tag == 8:
            if current_art is None:
                current_art = {"name": None, "layers": []}
                mapping["articulations"].append(current_art)
            current_art["name"] = payload.decode("utf-8", errors="ignore").rstrip("\x00")

        elif tag == 0x0b:
            current_rr = 0

        elif tag == 0x0c and size >= 4:
            if current_art is None:
                current_art = {"name": None, "layers": []}
                mapping["articulations"].append(current_art)
            velocity = read_u32le(payload, 0)
            layer = ensure_layer(current_art, current_layer)
            layer["velocity"] = velocity

        elif tag == 0x0f and size >= 4:
            if current_art is None:
                current_art = {"name": None, "layers": []}
                mapping["articulations"].append(current_art)
            wave_index = read_u32le(payload, 0)
            layer = ensure_layer(current_art, current_layer)
            while len(layer["waves"]) <= current_rr:
                layer["waves"].append(None)
            layer["waves"][current_rr] = wave_index
            current_rr += 1

        elif tag == 0x12:
            current_layer += 1
            current_rr = 0

        elif tag == 0x13:
            current_layer = 0
            current_rr = 0
            current_art = None

        cursor += size
        if cursor >= len(data):
            break

    mapping["sample_rate"] = sample_rate
    mapping["wave_chunks"] = len(chunks)
    return {"chunks": chunks, "mapping": mapping}


def parse_tci1(data):
    tlv_start = find_tlv_start(data)
    if tlv_start is None:
        return None
    return parse_tci1_at(data, tlv_start)


def find_tlv_start_bruteforce(data, scan_limit=2_000_000):
    scan_end = min(len(data) - 8, scan_limit)
    for offset in range(0, scan_end):
        tag = read_u32le(data, offset)
        size = read_u32le(data, offset + 4)
        if tag is None or size is None:
            continue
        if tag not in TLV_TAGS:
            continue
        if size <= 0 or offset + 8 + size > len(data):
            continue
        if tag == 5:
            if size < 9:
                continue
            channels = data[offset + 8]
            bit_len = read_u32le(data, offset + 9)
            sample_count = read_u32le(data, offset + 13)
            if channels not in (1, 2):
                continue
            if bit_len is None or sample_count is None:
                continue
            if bit_len <= 0 or bit_len > 50_000_000:
                continue
            if sample_count <= 0 or sample_count > 50_000_000:
                continue

        # verify a short TLV sequence
        cursor = offset
        valid = 0
        for _ in range(12):
            t = read_u32le(data, cursor)
            s = read_u32le(data, cursor + 4)
            if t is None or s is None:
                break
            if t not in TLV_TAGS:
                break
            if s <= 0 or cursor + 8 + s > len(data):
                break
            valid += 1
            cursor += 8 + s
        if valid >= 3:
            return offset
    return None


def is_valid_zlib_header(data, offset):
    if offset + 2 > len(data):
        return False
    cmf = data[offset]
    flg = data[offset + 1]
    if (cmf & 0x0F) != 8:
        return False
    return ((cmf << 8) + flg) % 31 == 0


def try_parse_xml(out):
    text = out.decode("utf-8", errors="ignore")
    start = text.find("<")
    end = text.rfind(">")
    if start == -1 or end == -1:
        return None
    xml_text = text[start:end + 1]
    try:
        return ET.fromstring(xml_text)
    except ET.ParseError:
        return None


def find_zlib_xml(data):
    for offset in range(len(data) - 2):
        if data[offset:offset + 2] == b"\x1f\x8b" and offset + 3 <= len(data):
            if data[offset + 2] != 0x08:
                continue
            try:
                out = zlib.decompress(data[offset:], 16 + zlib.MAX_WBITS)
            except Exception:
                continue
            root = try_parse_xml(out)
            if root is not None:
                return offset, root
            continue

        if not is_valid_zlib_header(data, offset):
            continue
        try:
            out = zlib.decompress(data[offset:])
        except Exception:
            continue
        root = try_parse_xml(out)
        if root is not None:
            return offset, root
    return None, None


def count_decoded_samples(payload, bit_len, sample_count, block_size=DEFAULT_BLOCK_SIZE):
    if sample_count == 0 or bit_len <= 8:
        return 0

    start_bit = find_valid_start_bit(payload, 0, bit_len)
    if start_bit is None:
        return -1

    u_var9 = read_u8_bits(payload, start_bit)
    u_var9 = normalize_uvar9(u_var9)
    if u_var9 is None:
        return -1
    bit_pos = start_bit + 8
    block_count = 0
    count = 0

    while count < sample_count:
        if (bit_pos >> 3) + 4 > len(payload):
            break

        count += 1
        block_count += 1
        bit_pos += u_var9

        if block_count >= block_size:
            byte_index = bit_pos >> 3
            if byte_index + 2 > len(payload):
                break
            u_var9 = ((payload[byte_index + 1] << 16) | (payload[byte_index] << 24))
            u_var9 = ((u_var9 << (bit_pos & 7)) & 0xFFFFFFFF) >> 24
            u_var9 = normalize_uvar9(u_var9)
            if u_var9 is None:
                return -1
            bit_pos += 8
            block_count = 0

        if bit_pos >= bit_len:
            break

    return count


def decode_head_energy(payload, bit_len, sample_count, max_samples=64, block_size=DEFAULT_BLOCK_SIZE):
    if sample_count == 0 or bit_len <= 8 or max_samples <= 0:
        return 0.0

    scale_pos = 1.0 / (1 << 23)
    scale_neg = -1.0 / (1 << 23)

    start_bit = find_valid_start_bit(payload, 0, bit_len)
    if start_bit is None:
        return 0.0

    u_var9 = read_u8_bits(payload, start_bit)
    u_var9 = normalize_uvar9(u_var9)
    if u_var9 is None:
        return 0.0
    bit_pos = start_bit + 8
    block_count = 0
    energy = 0.0
    count = 0

    target = min(sample_count, max_samples)
    while count < target:
        if (bit_pos >> 3) + 4 > len(payload):
            break
        word = struct.unpack(">I", payload[bit_pos >> 3:(bit_pos >> 3) + 4])[0]
        b_var8 = bit_pos & 7
        shifted = (word << b_var8) & 0xFFFFFFFF
        magnitude = (shifted & 0x7FFFFFFF) >> ((32 - u_var9) & 0x1F)
        scale = scale_pos if (shifted & 0x80000000) == 0 else scale_neg
        energy += abs(magnitude * scale)

        count += 1
        block_count += 1
        bit_pos += u_var9

        if block_count >= block_size:
            byte_index = bit_pos >> 3
            if byte_index + 2 > len(payload):
                break
            u_var9 = ((payload[byte_index + 1] << 16) | (payload[byte_index] << 24))
            u_var9 = ((u_var9 << (bit_pos & 7)) & 0xFFFFFFFF) >> 24
            bit_pos += 8
            block_count = 0

        if bit_pos >= bit_len:
            break

    return energy


def refine_blob_start(data, blob_start, payload_len, bit_len, sample_count):
    if payload_len <= 0:
        return blob_start

    best_start = blob_start
    best_diff = sample_count if sample_count else 0
    best_energy = None
    best_offset = None

    best_any_start = blob_start
    best_any_diff = sample_count if sample_count else 0
    best_any_energy = None

    for offset in range(blob_start - 64, blob_start + 65):
        if offset < 0 or offset + payload_len > len(data):
            continue
        first_byte = data[offset]
        payload = data[offset:offset + payload_len]
        decoded = count_decoded_samples(payload, bit_len, sample_count)
        if decoded < 0:
            continue
        diff = abs(decoded - sample_count)
        if diff < best_any_diff:
            best_any_diff = diff
            best_any_start = offset
            best_any_energy = None
        elif diff == best_any_diff:
            energy = decode_head_energy(payload, bit_len, sample_count)
            if best_any_energy is None:
                best_any_payload = data[best_any_start:best_any_start + payload_len]
                best_any_energy = decode_head_energy(best_any_payload, bit_len, sample_count)
            if energy < best_any_energy:
                best_any_start = offset
                best_any_energy = energy

        if not (0 <= first_byte <= 25):
            continue

        if diff < best_diff:
            best_diff = diff
            best_start = offset
            best_energy = None
            best_offset = None
        elif diff == best_diff:
            energy = decode_head_energy(payload, bit_len, sample_count)
            if best_energy is None:
                best_payload = data[best_start:best_start + payload_len]
                best_energy = decode_head_energy(best_payload, bit_len, sample_count)
            if energy < best_energy:
                best_start = offset
                best_energy = energy
                best_offset = None
            elif energy == best_energy:
                if best_offset is None:
                    best_offset = best_start
                if offset < best_offset:
                    best_start = offset
                    best_offset = offset

    if best_diff <= 12:
        return best_start
    if best_any_diff <= 4:
        return best_any_start
    return blob_start


def find_blob_start_global(data, blob_start, comp_bits, sample_counts, window=512):
    total_payload = sum((bit_len + 7) // 8 for bit_len in comp_bits)
    if total_payload <= 0:
        return None

    search_start = max(0, blob_start - window)
    search_end = min(len(data) - total_payload, blob_start + window)
    if search_start > search_end:
        return None

    best = None
    best_energy = None

    for start in range(search_start, search_end + 1):
        cursor = start
        total_diff = 0
        energy_sum = 0.0
        for bit_len, sample_count in zip(comp_bits, sample_counts):
            payload_len = (bit_len + 7) // 8
            payload = data[cursor:cursor + payload_len]
            decoded = count_decoded_samples(payload, bit_len, sample_count)
            diff = abs(decoded - sample_count)
            if diff > 2:
                total_diff = None
                break
            total_diff += diff
            energy_sum += decode_head_energy(payload, bit_len, sample_count)
            cursor += payload_len

        if total_diff is None:
            continue

        if best is None or total_diff < best[0] or (total_diff == best[0] and energy_sum < best_energy):
            best = (total_diff, start)
            best_energy = energy_sum
            if total_diff == 0:
                return start

    return best[1] if best else None


def find_blob_start_first_chunk(data, blob_start, bit_len, sample_count, window=128):
    payload_len = (bit_len + 7) // 8
    best_start = None
    best_diff = None
    best_energy = None

    for offset in range(blob_start - window, blob_start + window + 1):
        if offset < 0 or offset + payload_len > len(data):
            continue
        first_byte = data[offset]
        if not (0 <= first_byte <= 25):
            continue
        payload = data[offset:offset + payload_len]
        decoded = count_decoded_samples(payload, bit_len, sample_count)
        if decoded < 0:
            continue
        diff = abs(decoded - sample_count)
        if best_diff is None or diff < best_diff:
            best_diff = diff
            best_start = offset
            best_energy = None
        elif diff == best_diff:
            energy = decode_head_energy(payload, bit_len, sample_count)
            if best_energy is None:
                best_payload = data[best_start:best_start + payload_len]
                best_energy = decode_head_energy(best_payload, bit_len, sample_count)
            if energy < best_energy:
                best_start = offset
                best_energy = energy

    return best_start


def parse_tci2(data, debug=False, fast=False):
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
    debug_chunks = []
    if comp_bits:
        first_len = (comp_bits[0] + 7) // 8
        first_start = find_blob_start_first_chunk(
            data,
            blob_start,
            comp_bits[0],
            sample_counts[0],
        )
        if first_start is not None:
            blob_start = first_start
        else:
            global_start = find_blob_start_global(data, blob_start, comp_bits, sample_counts)
            if global_start is not None:
                blob_start = global_start
            else:
                blob_start = refine_blob_start(
                    data,
                    blob_start,
                    first_len,
                    comp_bits[0],
                    sample_counts[0],
                )

    cursor = blob_start
    sequential_ok = True
    if not fast:
        for i in range(data_count):
            bit_len = comp_bits[i]
            payload_len = (bit_len + 7) // 8
            payload = data[cursor:cursor + payload_len]
            decoded = count_decoded_samples(payload, bit_len, sample_counts[i])
            if decoded < 0:
                sequential_ok = False
                break
            if abs(decoded - sample_counts[i]) > 12:
                sequential_ok = False
                break
            cursor += payload_len

        if any(stereo_flags):
            sequential_ok = False

        if not sequential_ok:
            cursor = blob_start

    for i in range(data_count):
        bit_len = comp_bits[i]
        payload_len = (bit_len + 7) // 8
        if sequential_ok:
            payload = data[cursor:cursor + payload_len]
            cursor += payload_len
        else:
            cursor = refine_blob_start(
                data,
                cursor,
                payload_len,
                bit_len,
                sample_counts[i],
            )
            payload = data[cursor:cursor + payload_len]
            cursor += payload_len

        payload, header_off = trim_leading_padding(payload, bit_len)
        bit_shift = 0

        if debug:
            start_bit = find_valid_start_bit(payload, 0, bit_len)
            if start_bit is None:
                header_byte_offset = None
                u_var9 = None
            else:
                header_byte_offset = start_bit // 8
                u_var9 = read_u8_bits(payload, start_bit)
            debug_chunks.append(
                {
                    "wave_id": i,
                    "start_byte": cursor - payload_len,
                    "bit_shift": bit_shift,
                    "header_byte_offset": header_off if header_off is not None else header_byte_offset,
                    "u_var9": u_var9,
                }
            )

        channels = 2 if stereo_flags[i] else 1
        chunks.append(
            {
                "wave_id": i,
                "channels": channels,
                "bit_len": bit_len,
                "sample_count": sample_counts[i],
                "payload": payload,
                "sample_rate": sample_rate,
            }
        )

    art_count = int(root.attrib.get("articulation_count", "0"))
    articulations = []
    for art_idx in range(art_count):
        art_name = root.attrib.get(f"art_Idx_{art_idx}artName")
        layers_count = int(root.attrib.get(f"art_Idx_{art_idx}layers_count", "0"))
        art = {"name": art_name, "layers": []}
        for layer_idx in range(layers_count):
            velocity = int(root.attrib.get(f"art_Idx_{art_idx}_layer_Idx_{layer_idx}velo", "0"))
            rr_count = int(root.attrib.get(
                f"art_Idx_{art_idx}_layer_Idx_{layer_idx}multy_wave_count", "0"
            ))
            waves = []
            for rr_idx in range(rr_count):
                wave = root.attrib.get(
                    f"art_Idx_{art_idx}_layer_Idx_{layer_idx}multy_wave_Idx_{rr_idx}wave_Idx_0"
                )
                waves.append(int(wave) if wave is not None else None)
            art["layers"].append({"velocity": velocity, "waves": waves})
        articulations.append(art)

    mapping = {
        "sample_rate": sample_rate,
        "wave_chunks": len(chunks),
        "articulations": articulations,
    }
    if debug and debug_chunks:
        mapping["debug_chunks"] = debug_chunks
    return {"chunks": chunks, "mapping": mapping}


def scan_header_markers(data, max_hits=8):
    zlib_hits = []
    gzip_hits = []
    limit = len(data) - 2
    for offset in range(limit):
        if len(zlib_hits) < max_hits and is_valid_zlib_header(data, offset):
            zlib_hits.append(offset)
        if len(gzip_hits) < max_hits and data[offset:offset + 2] == b"\x1f\x8b":
            gzip_hits.append(offset)
        if len(zlib_hits) >= max_hits and len(gzip_hits) >= max_hits:
            break
    return zlib_hits, gzip_hits


def diagnose_tci_data(data):
    tlv_start = find_tlv_start(data)
    zlib_off = find_zlib_xml(data)[0]
    zlib_hits, gzip_hits = scan_header_markers(data)
    header_fields = {}
    if data.startswith(SIGNATURES[0]) or data.startswith(SIGNATURES[1]) or data.startswith(SIGNATURES[2]) or data.startswith(SIGNATURES[3]):
        for off in (64, 68, 72, 76, 80):
            if off + 4 <= len(data):
                header_fields[off] = read_u32le(data, off)
    return {
        "tlv_start": tlv_start,
        "zlib_xml": zlib_off,
        "zlib_hits": zlib_hits,
        "gzip_hits": gzip_hits,
        "hdr": header_fields,
        "size": len(data),
    }


def diagnose_tci(path):
    with open(path, "rb") as f:
        data = f.read()
    return diagnose_tci_data(data)


def decode_tci(path, debug=False, fast=False, diagnose=False):
    with open(path, "rb") as f:
        data = f.read()

    if not any(data.startswith(sig) for sig in SIGNATURES):
        raise ValueError("Not a TCI file")

    parsed = parse_tci1(data)
    if parsed is None:
        tlv_bruteforce = find_tlv_start_bruteforce(data)
        if tlv_bruteforce is not None:
            parsed = parse_tci1_at(data, tlv_bruteforce)
    if parsed is None:
        parsed = parse_tci2(data, debug=debug, fast=fast)
    if parsed is None:
        if diagnose:
            diag = diagnose_tci_data(data)
            raise ValueError(
                "Unsupported TCI format"
                f" (tlv_start={diag['tlv_start']}, zlib_xml={diag['zlib_xml']}, "
                f"zlib_hits={diag['zlib_hits'][:4]}, gzip_hits={diag['gzip_hits'][:4]}, "
                f"hdr={diag['hdr']})"
            )
        raise ValueError("Unsupported TCI format")

    return parsed
