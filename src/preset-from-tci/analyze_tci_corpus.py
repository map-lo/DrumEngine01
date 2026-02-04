#!/usr/bin/env python3
import argparse
import csv
import json
import os
from datetime import datetime
from collections import Counter, defaultdict

from tci_decoder import (
    decode_tci,
    diagnose_tci_data,
    find_tlv_start,
    find_tlv_start_bruteforce,
    find_zlib_xml,
    parse_tci1,
    parse_tci2,
)


def iter_tci_files(root):
    for dirpath, _, filenames in os.walk(root):
        for filename in filenames:
            if filename.lower().endswith(".tci"):
                yield os.path.join(dirpath, filename)


def safe_read(path):
    with open(path, "rb") as f:
        return f.read()


def summarize_tci(path, data):
    summary = {
        "path": path,
        "size": len(data),
        "tlv_start": find_tlv_start(data),
        "tlv_bruteforce": None,
        "zlib_xml": None,
        "format": None,
        "chunk_count": None,
        "sample_rate": None,
        "articulation_count": None,
    }

    if summary["tlv_start"] is None:
        summary["tlv_bruteforce"] = find_tlv_start_bruteforce(data)

    zoff, _ = find_zlib_xml(data)
    summary["zlib_xml"] = zoff

    parsed = parse_tci1(data)
    if parsed is None:
        parsed = parse_tci2(data, debug=False, fast=True)
        if parsed is not None:
            summary["format"] = "tci2"
    else:
        summary["format"] = "tci1"

    if parsed is None:
        try:
            decoded = decode_tci(path, fast=True)
            parsed = decoded
            summary["format"] = "tci2" if zoff is not None else "tci1"
        except Exception:
            parsed = None

    if parsed is not None:
        mapping = parsed.get("mapping", {})
        summary["chunk_count"] = len(parsed.get("chunks", []))
        summary["sample_rate"] = mapping.get("sample_rate")
        summary["articulation_count"] = len(mapping.get("articulations", []))

    return summary


def build_histograms(rows):
    hist = {
        "tlv_start": Counter(),
        "tlv_bruteforce": Counter(),
        "zlib_xml": Counter(),
        "size": Counter(),
        "sample_rate": Counter(),
        "chunk_count": Counter(),
        "articulation_count": Counter(),
        "format": Counter(),
    }
    for row in rows:
        for key in hist:
            value = row.get(key)
            if value is None:
                continue
            hist[key][value] += 1
    return {k: dict(v.most_common()) for k, v in hist.items()}


def write_csv(path, rows):
    fieldnames = [
        "path",
        "size",
        "format",
        "tlv_start",
        "tlv_bruteforce",
        "zlib_xml",
        "chunk_count",
        "sample_rate",
        "articulation_count",
    ]
    with open(path, "w", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=fieldnames)
        writer.writeheader()
        for row in rows:
            writer.writerow({k: row.get(k) for k in fieldnames})


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--inputRoot", required=True)
    parser.add_argument("--outputRoot", default=os.path.join("analysis", "tci"))
    parser.add_argument(
        "--runId",
        default=None,
        help="Optional run id for output subfolder (default: timestamp).",
    )
    args = parser.parse_args()

    input_root = args.inputRoot
    run_id = args.runId or datetime.now().strftime("%Y%m%d_%H%M%S")
    output_root = os.path.join(args.outputRoot, run_id)
    os.makedirs(output_root, exist_ok=True)

    rows = []
    for path in iter_tci_files(input_root):
        data = safe_read(path)
        summary = summarize_tci(path, data)
        rows.append(summary)

    histograms = build_histograms(rows)

    csv_path = os.path.join(output_root, "tci_summary.csv")
    json_path = os.path.join(output_root, "tci_summary.json")
    hist_path = os.path.join(output_root, "tci_histograms.json")

    write_csv(csv_path, rows)
    with open(json_path, "w", encoding="utf-8") as handle:
        json.dump(rows, handle, indent=2)
    with open(hist_path, "w", encoding="utf-8") as handle:
        json.dump(histograms, handle, indent=2)

    print(f"Wrote {len(rows)} summaries")
    print(f"CSV: {csv_path}")
    print(f"JSON: {json_path}")
    print(f"Histograms: {hist_path}")


if __name__ == "__main__":
    main()
