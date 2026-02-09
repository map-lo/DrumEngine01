#!/usr/bin/env python3
import argparse
import json
import os
from collections import Counter, defaultdict


def load_rows(input_path):
    if input_path.endswith(".jsonl"):
        rows = []
        with open(input_path, "r", encoding="utf-8") as handle:
            for line in handle:
                line = line.strip()
                if not line:
                    continue
                rows.append(json.loads(line))
        return rows
    with open(input_path, "r", encoding="utf-8") as handle:
        return json.load(handle)


def discover_summary_files(root):
    summary_files = []
    for dirpath, _, filenames in os.walk(root):
        if "tci_summary.json" in filenames:
            summary_files.append(os.path.join(dirpath, "tci_summary.json"))
    return sorted(summary_files)


def build_hist(rows, key):
    counter = Counter()
    for row in rows:
        value = row.get(key)
        if value is None:
            continue
        counter[value] += 1
    return counter


def build_derived_hists(rows):
    zlib_from_end = Counter()
    zlib_mod_4096 = Counter()
    blob_from_end = Counter()
    total_compressed_bytes = Counter()
    xml_data_count = Counter()
    xml_sample_rate = Counter()
    for row in rows:
        size = row.get("size")
        zlib_xml = row.get("zlib_xml")
        blob_end = row.get("blob_from_end")
        total_bytes = row.get("total_compressed_bytes")
        data_count = row.get("xml_data_count")
        xml_sr = row.get("xml_sample_rate")
        if size is not None and zlib_xml is not None:
            zlib_from_end[size - zlib_xml] += 1
            zlib_mod_4096[zlib_xml % 4096] += 1
        if blob_end is not None:
            blob_from_end[blob_end] += 1
        if total_bytes is not None:
            total_compressed_bytes[total_bytes] += 1
        if data_count is not None:
            xml_data_count[data_count] += 1
        if xml_sr is not None:
            xml_sample_rate[xml_sr] += 1
    return {
        "zlib_from_end": dict(zlib_from_end.most_common()),
        "zlib_mod_4096": dict(zlib_mod_4096.most_common()),
        "blob_from_end": dict(blob_from_end.most_common()),
        "total_compressed_bytes": dict(total_compressed_bytes.most_common()),
        "xml_data_count": dict(xml_data_count.most_common()),
        "xml_sample_rate": dict(xml_sample_rate.most_common()),
    }


def group_by_parent(rows, levels):
    grouped = defaultdict(list)
    for row in rows:
        path = row.get("path") or ""
        parts = path.split(os.sep)
        if levels <= 0 or len(parts) <= levels:
            key = os.path.dirname(path)
        else:
            key = os.sep.join(parts[:levels])
        grouped[key].append(row)
    return grouped


def group_by_key(rows, key):
    grouped = defaultdict(list)
    for row in rows:
        value = row.get(key)
        grouped[str(value)].append(row)
    return grouped


def summarize_group(rows):
    summary = {
        "count": len(rows),
        "format": dict(build_hist(rows, "format")),
        "sample_rate": dict(build_hist(rows, "sample_rate")),
        "chunk_count": dict(build_hist(rows, "chunk_count")),
        "tlv_start": dict(build_hist(rows, "tlv_start")),
        "zlib_xml": dict(build_hist(rows, "zlib_xml")),
        "blob_start": dict(build_hist(rows, "blob_start")),
    }
    summary.update(build_derived_hists(rows))
    return summary


def write_markdown(path, global_summary, grouped_summary, top_n=10):
    with open(path, "w", encoding="utf-8") as handle:
        handle.write("# TCI Analysis Summary\n\n")
        handle.write(f"Total files: {global_summary['count']}\n\n")

        def write_hist(title, hist):
            handle.write(f"## {title}\n")
            for value, count in list(hist.items())[:top_n]:
                handle.write(f"- {value}: {count}\n")
            handle.write("\n")

        write_hist("Format", global_summary["format"])
        write_hist("Sample Rate", global_summary["sample_rate"])
        write_hist("Chunk Count", global_summary["chunk_count"])
        write_hist("TLV Start", global_summary["tlv_start"])
        write_hist("Zlib XML", global_summary["zlib_xml"])
        write_hist("Blob Start", global_summary.get("blob_start", {}))
        write_hist("Zlib From End (size - zlib_xml)", global_summary.get("zlib_from_end", {}))
        write_hist("Zlib Mod 4096", global_summary.get("zlib_mod_4096", {}))
        write_hist("Blob From End", global_summary.get("blob_from_end", {}))
        write_hist("Total Compressed Bytes", global_summary.get("total_compressed_bytes", {}))
        write_hist("XML Data Count", global_summary.get("xml_data_count", {}))
        write_hist("XML Sample Rate", global_summary.get("xml_sample_rate", {}))

        handle.write("## Groups\n\n")
        for group, summary in grouped_summary.items():
            handle.write(f"### {group}\n")
            handle.write(f"- count: {summary['count']}\n")
            handle.write(f"- formats: {summary['format']}\n")
            handle.write(f"- sample_rate: {summary['sample_rate']}\n")
            handle.write(f"- chunk_count: {summary['chunk_count']}\n")
            handle.write(f"- tlv_start: {summary['tlv_start']}\n")
            handle.write(f"- zlib_xml: {summary['zlib_xml']}\n\n")
            handle.write(f"- blob_start: {summary.get('blob_start', {})}\n")
            handle.write(f"- zlib_from_end: {summary.get('zlib_from_end', {})}\n")
            handle.write(f"- zlib_mod_4096: {summary.get('zlib_mod_4096', {})}\n\n")
            handle.write(f"- blob_from_end: {summary.get('blob_from_end', {})}\n")
            handle.write(f"- total_compressed_bytes: {summary.get('total_compressed_bytes', {})}\n")
            handle.write(f"- xml_data_count: {summary.get('xml_data_count', {})}\n")
            handle.write(f"- xml_sample_rate: {summary.get('xml_sample_rate', {})}\n\n")


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--input",
        help="Path to tci_summary.json/.jsonl or a directory containing analysis runs",
    )
    parser.add_argument(
        "--analysisRoot",
        default=os.path.join("analysis", "tci"),
        help="Root folder to scan when --input is omitted",
    )
    parser.add_argument("--outputRoot", default=os.path.join("analysis", "tci"))
    parser.add_argument("--groupLevels", type=int, default=6, help="Group by leading path levels")
    parser.add_argument("--top", type=int, default=10, help="Top-N values per histogram")
    args = parser.parse_args()

    input_path = args.input
    summary_files = []
    if input_path:
        if os.path.isdir(input_path):
            summary_files = discover_summary_files(input_path)
        else:
            summary_files = [input_path]
    else:
        summary_files = discover_summary_files(args.analysisRoot)

    if not summary_files:
        raise SystemExit("No tci_summary.json files found.")

    rows = []
    for path in summary_files:
        rows.extend(load_rows(path))
    global_summary = summarize_group(rows)
    grouped = group_by_parent(rows, args.groupLevels)
    grouped_summary = {k: summarize_group(v) for k, v in grouped.items()}
    chunk_grouped = group_by_key(rows, "chunk_count")
    chunk_grouped_summary = {k: summarize_group(v) for k, v in chunk_grouped.items()}

    os.makedirs(args.outputRoot, exist_ok=True)
    summary_json = os.path.join(args.outputRoot, "tci_results_summary.json")
    summary_md = os.path.join(args.outputRoot, "tci_results_summary.md")

    with open(summary_json, "w", encoding="utf-8") as handle:
        json.dump(
            {
                "global": global_summary,
                "groups": grouped_summary,
                "chunk_groups": chunk_grouped_summary,
            },
            handle,
            indent=2,
        )

    write_markdown(summary_md, global_summary, grouped_summary, top_n=args.top)

    with open(summary_md, "a", encoding="utf-8") as handle:
        handle.write("\n## Chunk Count Groups\n\n")
        for group, summary in chunk_grouped_summary.items():
            handle.write(f"### chunk_count={group}\n")
            handle.write(f"- count: {summary['count']}\n")
            handle.write(f"- formats: {summary['format']}\n")
            handle.write(f"- sample_rate: {summary['sample_rate']}\n")
            handle.write(f"- tlv_start: {summary['tlv_start']}\n")
            handle.write(f"- zlib_xml: {summary['zlib_xml']}\n")
            handle.write(f"- blob_start: {summary.get('blob_start', {})}\n")
            handle.write(f"- zlib_from_end: {summary.get('zlib_from_end', {})}\n")
            handle.write(f"- zlib_mod_4096: {summary.get('zlib_mod_4096', {})}\n\n")
            handle.write(f"- blob_from_end: {summary.get('blob_from_end', {})}\n")
            handle.write(f"- total_compressed_bytes: {summary.get('total_compressed_bytes', {})}\n")
            handle.write(f"- xml_data_count: {summary.get('xml_data_count', {})}\n")
            handle.write(f"- xml_sample_rate: {summary.get('xml_sample_rate', {})}\n\n")

    print(f"Wrote summary JSON: {summary_json}")
    print(f"Wrote summary MD: {summary_md}")


if __name__ == "__main__":
    main()
