#!/usr/bin/env python3
import argparse
import csv
import json
import os
import hashlib
import signal
import sys
import multiprocessing as mp
import functools
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
    count_decoded_samples,
)


def iter_tci_files(root):
    for dirpath, _, filenames in os.walk(root):
        for filename in filenames:
            if filename.lower().endswith(".tci"):
                yield os.path.join(dirpath, filename)


def safe_read(path):
    with open(path, "rb") as f:
        return f.read()


def summarize_tci_path(path, validate_chunks=False):
    data = safe_read(path)
    return summarize_tci(path, data, validate_chunks=validate_chunks)


def summarize_tci(path, data, validate_chunks=False):
    summary = {
        "path": path,
        "size": len(data),
        "tlv_start": find_tlv_start(data),
        "tlv_bruteforce": None,
        "zlib_xml": None,
        "xml_data_count": None,
        "xml_sample_rate": None,
        "xml_comp_bits": None,
        "xml_samples": None,
        "xml_stereo": None,
        "total_compressed_bytes": None,
        "blob_start": None,
        "blob_from_end": None,
        "zlib_window_hash": None,
        "blob_window_hash": None,
        "format": None,
        "chunk_count": None,
        "sample_rate": None,
        "articulation_count": None,
        "chunk_decode_total": None,
        "chunk_decode_valid": None,
        "chunk_decode_invalid": None,
    }

    if summary["tlv_start"] is None:
        summary["tlv_bruteforce"] = find_tlv_start_bruteforce(data)

    zoff, root = find_zlib_xml(data)
    summary["zlib_xml"] = zoff

    if root is not None:
        try:
            data_count = int(root.attrib.get("data_count", "0"))
        except ValueError:
            data_count = 0
        summary["xml_data_count"] = data_count
        try:
            summary["xml_sample_rate"] = int(root.attrib.get("sample_rate", "0"))
        except ValueError:
            summary["xml_sample_rate"] = None

        comp_bits = []
        samples = []
        stereo = []
        for i in range(data_count):
            comp_val = root.attrib.get(f"wd{i}comp1")
            samples_val = root.attrib.get(f"wd{i}samples")
            stereo_val = root.attrib.get(f"wd{i}stereo", "0")
            if comp_val is not None:
                try:
                    comp_bits.append(int(comp_val))
                except ValueError:
                    comp_bits.append(None)
            if samples_val is not None:
                try:
                    samples.append(int(samples_val))
                except ValueError:
                    samples.append(None)
            try:
                stereo.append(int(stereo_val))
            except ValueError:
                stereo.append(None)

        summary["xml_comp_bits"] = comp_bits or None
        summary["xml_samples"] = samples or None
        summary["xml_stereo"] = stereo or None

        if comp_bits:
            total_bytes = 0
            for bit_len in comp_bits:
                if bit_len is None:
                    continue
                total_bytes += (bit_len + 7) // 8
            summary["total_compressed_bytes"] = total_bytes
            if zoff is not None:
                summary["blob_start"] = zoff - total_bytes
                summary["blob_from_end"] = len(data) - (zoff - total_bytes)

    if zoff is not None:
        window_start = max(0, zoff - 32)
        window = data[window_start:window_start + 64]
        summary["zlib_window_hash"] = hashlib.sha1(window).hexdigest()

    if summary.get("blob_start") is not None:
        blob_start = summary["blob_start"]
        if 0 <= blob_start < len(data):
            window_start = max(0, blob_start - 32)
            window = data[window_start:window_start + 64]
            summary["blob_window_hash"] = hashlib.sha1(window).hexdigest()

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

        if validate_chunks and summary.get("chunk_decode_total") is None:
            chunks = parsed.get("chunks", [])
            total = len(chunks)
            invalid = 0
            for chunk in chunks:
                decoded = count_decoded_samples(
                    chunk["payload"],
                    chunk["bit_len"],
                    chunk["sample_count"],
                )
                if decoded < 0:
                    invalid += 1
            summary["chunk_decode_total"] = total
            summary["chunk_decode_invalid"] = invalid
            summary["chunk_decode_valid"] = total - invalid

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
        "xml_data_count",
        "xml_sample_rate",
        "xml_comp_bits",
        "xml_samples",
        "xml_stereo",
        "total_compressed_bytes",
        "blob_start",
        "blob_from_end",
        "zlib_window_hash",
        "blob_window_hash",
        "chunk_count",
        "sample_rate",
        "articulation_count",
        "chunk_decode_total",
        "chunk_decode_valid",
        "chunk_decode_invalid",
    ]
    with open(path, "w", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=fieldnames)
        writer.writeheader()
        for row in rows:
            writer.writerow({k: row.get(k) for k in fieldnames})


def write_csv_header(handle):
    fieldnames = [
        "path",
        "size",
        "format",
        "tlv_start",
        "tlv_bruteforce",
        "zlib_xml",
        "xml_data_count",
        "xml_sample_rate",
        "xml_comp_bits",
        "xml_samples",
        "xml_stereo",
        "total_compressed_bytes",
        "blob_start",
        "blob_from_end",
        "zlib_window_hash",
        "blob_window_hash",
        "chunk_count",
        "sample_rate",
        "articulation_count",
        "chunk_decode_total",
        "chunk_decode_valid",
        "chunk_decode_invalid",
    ]
    writer = csv.DictWriter(handle, fieldnames=fieldnames)
    writer.writeheader()
    return writer, fieldnames


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--inputRoot", required=True)
    parser.add_argument("--outputRoot", default=os.path.join("analysis", "tci"))
    parser.add_argument(
        "--runId",
        default=None,
        help="Optional run id for output subfolder (default: timestamp).",
    )
    parser.add_argument(
        "--progressEvery",
        type=int,
        default=25,
        help="Print progress every N files.",
    )
    parser.add_argument(
        "--stream",
        action="store_true",
        help="Write CSV/JSONL incrementally while scanning.",
    )
    parser.add_argument(
        "--validateChunks",
        action="store_true",
        help="Validate each chunk bitstream and count invalid decodes.",
    )
    parser.add_argument(
        "--workers",
        type=int,
        default=1,
        help="Number of parallel worker processes.",
    )
    parser.add_argument(
        "--limit",
        type=int,
        default=0,
        help="Limit the number of files processed (0 = no limit).",
    )
    args = parser.parse_args()

    input_root = args.inputRoot
    run_id = args.runId or datetime.now().strftime("%Y%m%d_%H%M%S")
    output_root = os.path.join(args.outputRoot, run_id)
    os.makedirs(output_root, exist_ok=True)

    all_paths = list(iter_tci_files(input_root))
    if args.limit and args.limit > 0:
        all_paths = all_paths[:args.limit]
    total = len(all_paths)
    print(f"Scanning {total} .tci files...")

    rows = []
    csv_path = os.path.join(output_root, "tci_summary.csv")
    json_path = os.path.join(output_root, "tci_summary.json")
    hist_path = os.path.join(output_root, "tci_histograms.json")
    jsonl_path = os.path.join(output_root, "tci_summary.jsonl")

    csv_handle = None
    jsonl_handle = None
    csv_writer = None
    csv_fields = None
    if args.stream and args.workers > 1:
        print("--stream disabled when --workers > 1")
        args.stream = False

    if args.stream:
        csv_handle = open(csv_path, "w", newline="")
        csv_writer, csv_fields = write_csv_header(csv_handle)
        jsonl_handle = open(jsonl_path, "w", encoding="utf-8")

    interrupted = False

    def finalize_partial():
        histograms = build_histograms(rows)
        if not args.stream:
            write_csv(csv_path, rows)
        with open(json_path, "w", encoding="utf-8") as handle:
            json.dump(rows, handle, indent=2)
        with open(hist_path, "w", encoding="utf-8") as handle:
            json.dump(histograms, handle, indent=2)
        if csv_handle:
            csv_handle.close()
        if jsonl_handle:
            jsonl_handle.close()

    def handle_interrupt(_sig, _frame):
        nonlocal interrupted
        interrupted = True
        print("\nInterrupted. Writing partial results...")
        finalize_partial()
        sys.exit(130)

    signal.signal(signal.SIGINT, handle_interrupt)

    if args.workers <= 1:
        for idx, path in enumerate(all_paths, start=1):
            if idx == 1 or (args.progressEvery and idx % args.progressEvery == 0):
                print(f"[{idx}/{total}] {path}")
            summary = summarize_tci_path(path, validate_chunks=args.validateChunks)
            rows.append(summary)

            if args.stream and csv_writer and csv_fields and jsonl_handle:
                csv_writer.writerow({k: summary.get(k) for k in csv_fields})
                jsonl_handle.write(json.dumps(summary, ensure_ascii=False) + "\n")
                csv_handle.flush()
                jsonl_handle.flush()
    else:
        workers = max(1, args.workers)
        worker_fn = functools.partial(summarize_tci_path, validate_chunks=args.validateChunks)
        with mp.Pool(processes=workers) as pool:
            for idx, summary in enumerate(
                pool.imap_unordered(worker_fn, all_paths),
                start=1,
            ):
                rows.append(summary)
                if idx == 1 or (args.progressEvery and idx % args.progressEvery == 0):
                    print(f"[{idx}/{total}] processed")

    finalize_partial()

    print(f"Wrote {len(rows)} summaries")
    print(f"CSV: {csv_path}")
    print(f"JSON: {json_path}")
    print(f"Histograms: {hist_path}")
    if args.stream:
        print(f"JSONL: {jsonl_path}")


if __name__ == "__main__":
    main()
