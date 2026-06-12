#!/usr/bin/env python3
"""
Batch analysis runner for DroidForensix.

Runs the full pipeline on all pending samples and updates metadata.
"""

import csv
import json
import os
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

from analysis.pipeline import run_pipeline

SAMPLES_DIR = Path(__file__).parent.parent / "samples"
META_PATH = Path(__file__).parent.parent / "sample_metadata.csv"
WORK_DIR = Path(__file__).parent.parent / "analysis" / "work"


def load_metadata():
    if not META_PATH.exists():
        return []
    with open(META_PATH, "r", newline="", encoding="utf-8") as f:
        return list(csv.DictReader(f))


def save_metadata(records):
    fieldnames = [
        "sample_name", "sha256", "md5", "family", "source",
        "type", "tags", "file_size_bytes", "status", "vt_detections",
        "collection_date",
    ]
    with open(META_PATH, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        for r in records:
            writer.writerow({k: r.get(k, "") for k in fieldnames})


def main():
    records = load_metadata()
    pending = [r for r in records if r.get("status") == "pending"]
    print(f"[*] Found {len(pending)} pending samples to analyze")

    for i, record in enumerate(pending, start=1):
        sample_name = record["sample_name"]
        sample_path = SAMPLES_DIR / "malware" / "androzoo_drebin" / sample_name
        if not sample_path.exists():
            print(f"[!] Sample not found: {sample_path}")
            continue

        print(f"\n[*] Analyzing {i}/{len(pending)}: {sample_name}")
        try:
            result = run_pipeline(str(sample_path), str(WORK_DIR))
            record["status"] = "analyzed"
            record["vt_detections"] = ""
            print(f"  [+] Done. Encodings: {len(result.get('encodings', []))}, "
                  f"Payloads: {len(result.get('payloads', []))}, "
                  f"C2s: {len(result.get('c2_infrastructure', []))}, "
                  f"Chains: {len(result.get('threat_chains', []))}")
        except Exception as e:
            record["status"] = f"error: {e}"
            print(f"  [!] Error: {e}")

        save_metadata(records)

    print(f"\n[+] Batch analysis complete. Total samples: {len(records)}")


if __name__ == "__main__":
    main()
