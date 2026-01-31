#!/usr/bin/env python3
import json
import os
import struct
import sys

SIGNATURE = b"TRIGGER COMPRESSED INSTRUMENT\x00"


def read_u32le(data, offset):
    if offset + 4 > len(data):
        return None
    return struct.unpack_from('<I', data, offset)[0]


def read_f32le(data, offset):
    if offset + 4 > len(data):
        return None
    return struct.unpack_from('<f', data, offset)[0]


def find_tlv_start(data):
    sig_index = data.find(SIGNATURE)
    if sig_index == -1:
        return None
    scan_start = sig_index + len(SIGNATURE)
    for offset in range(scan_start, scan_start + 0x100):
        v = [read_u32le(data, offset + i * 4) for i in range(8)]
        if None in v:
            continue
        v1, v2, v3, v4, v5, v6, v7, v8 = v
        if v1 == 1 and v3 == 4 and v4 == 0x15 and v6 == 0 and v7 == 2:
            return offset + 32
    return None


def ensure_layer(articulation, layer_index):
    layers = articulation["layers"]
    while len(layers) <= layer_index:
        layers.append({"velocity": None, "waves": []})
    return layers[layer_index]


def main():
    input_path = sys.argv[1] if len(sys.argv) > 1 else (
        "/Users/marian/Downloads/SPINLIGHT SAMPLES/Trigger TCI/Vintage 70's Acrolite (Tight)/"
        "Vintage 70's Acrolite (Tight) - Close Mic.tci"
    )

    with open(input_path, 'rb') as f:
        data = f.read()

    tlv_start = find_tlv_start(data)
    if tlv_start is None:
        print("TLV start not found")
        return

    articulations = []
    current_art = None
    current_layer = 0
    current_rr = 0
    wave_chunks = []
    sample_rate = 44100

    cursor = tlv_start
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
            wave_chunks.append({"index": len(wave_chunks)})

        elif tag == 7:
            if current_art is None:
                current_art = {"name": None, "layers": []}
                articulations.append(current_art)
            current_layer = 0
            current_rr = 0

        elif tag == 8:
            if current_art is None:
                current_art = {"name": None, "layers": []}
                articulations.append(current_art)
            name = payload.decode('utf-8', errors='ignore').rstrip('\x00')
            current_art["name"] = name

        elif tag == 0x0b:
            current_rr = 0

        elif tag == 0x0c and size >= 4:
            if current_art is None:
                current_art = {"name": None, "layers": []}
                articulations.append(current_art)
            velocity = read_u32le(payload, 0)
            layer = ensure_layer(current_art, current_layer)
            layer["velocity"] = velocity

        elif tag == 0x0f and size >= 4:
            if current_art is None:
                current_art = {"name": None, "layers": []}
                articulations.append(current_art)
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

    output = {
        "sample_rate": sample_rate,
        "wave_chunks": len(wave_chunks),
        "articulations": articulations,
    }

    out_path = os.path.join(
        os.path.dirname(__file__),
        "output",
        f"{os.path.splitext(os.path.basename(input_path))[0]}_mapping.json",
    )
    os.makedirs(os.path.dirname(out_path), exist_ok=True)
    with open(out_path, "w", encoding="utf-8") as f:
        json.dump(output, f, indent=2)

    print(f"Wrote {out_path}")


if __name__ == "__main__":
    main()
