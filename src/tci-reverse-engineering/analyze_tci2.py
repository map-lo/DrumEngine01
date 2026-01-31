#!/usr/bin/env python3
import io
import os
import sys
import zlib
import xml.etree.ElementTree as ET


def find_zlib_stream(data):
    # naive: find first successful zlib decompression
    for offset in range(len(data) - 2):
        if data[offset:offset+2] not in (b"\x78\x9C", b"\x78\xDA"):
            continue
        try:
            out = zlib.decompress(data[offset:])
            return offset, out
        except Exception:
            continue
    return None, None


def main():
    path = sys.argv[1]
    with open(path, 'rb') as f:
        data = f.read()

    zoff, xml_bytes = find_zlib_stream(data)
    if xml_bytes is None:
        print("No zlib stream found")
        return

    print(f"zlib offset: 0x{zoff:X} ({zoff}) len={len(xml_bytes)}")
    xml_text = xml_bytes.decode("utf-8", errors="ignore")
    start = xml_text.find("<")
    end = xml_text.rfind(">")
    if start == -1 or end == -1:
        print("XML markers not found")
        return
    xml_text = xml_text[start:end + 1]
    root = ET.fromstring(xml_text)

    data_count = int(root.attrib.get("data_count", "0"))
    print(f"data_count={data_count}")

    comp_sizes = []
    for i in range(data_count):
        comp = root.attrib.get(f"wd{i}comp1")
        if comp is not None:
            comp_sizes.append(int(comp))

    sum_bits = sum(comp_sizes)
    sum_bytes = sum((c + 7) // 8 for c in comp_sizes)
    print(f"sum_bits={sum_bits}")
    print(f"sum_bytes={sum_bytes}")

    # Guess data blob starts after 0x40
    for start in (0x40, 0x60, 0x80, 0x100):
        blob_len = zoff - start
        print(f"start=0x{start:X} blob_len={blob_len}")


if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: analyze_tci2.py <path>")
        sys.exit(1)
    main()
