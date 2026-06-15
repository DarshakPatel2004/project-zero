"""
Batch analysis runner for DroidForensix.

Runs the full pipeline on all pending samples and updates metadata.
Supports per-sample timeouts based on APK size.
"""

import argparse
import csv
import multiprocessing
import os
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

from analysis.pipeline import run_pipeline
from backend.config import settings

SAMPLES_DIR = settings.SAMPLES_DIR
META_PATH = Path(__file__).parent.parent / "sample_metadata.csv"
WORK_DIR = settings.WORK_DIR

# Default timeout per APK size tier (seconds)
DEFAULT_SMALL_TIMEOUT = 180   # 3 minutes for APKs < 10 MB
DEFAULT_LARGE_TIMEOUT = 600   # 10 minutes for APKs >= 10 MB
SIZE_THRESHOLD_BYTES = 10 * 1024 * 1024


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


def _run_pipeline_worker(sample_path: str, work_dir: str, queue: multiprocessing.Queue):
    """Worker function that runs pipeline and puts result or exception on queue."""
    try:
        result = run_pipeline(sample_path, work_dir)
        queue.put(("ok", result))
    except Exception as e:
        queue.put(("error", str(e)))


def run_with_timeout(sample_path: Path, work_dir: Path, timeout: int) -> dict:
    """Run pipeline in a separate process with a timeout."""
    queue = multiprocessing.Queue()
    process = multiprocessing.Process(
        target=_run_pipeline_worker,
        args=(str(sample_path), str(work_dir), queue),
    )
    process.start()
    process.join(timeout=timeout)

    if process.is_alive():
        process.terminate()
        process.join(timeout=5)
        if process.is_alive():
            process.kill()
            process.join(timeout=5)
        raise TimeoutError(f"Analysis exceeded {timeout} seconds timeout")

    if process.exitcode != 0:
        raise RuntimeError(f"Pipeline process exited with code {process.exitcode}")

    try:
        status, payload = queue.get(timeout=5)
    except Exception as e:
        raise RuntimeError(f"Failed to read pipeline result: {e}")

    if status == "error":
        raise RuntimeError(payload)

    return payload


def main():
    parser = argparse.ArgumentParser(description="Batch analysis runner for DroidForensix")
    parser.add_argument("--small-timeout", type=int, default=DEFAULT_SMALL_TIMEOUT,
                        help=f"Timeout for APKs < 10 MB (default {DEFAULT_SMALL_TIMEOUT}s)")
    parser.add_argument("--large-timeout", type=int, default=DEFAULT_LARGE_TIMEOUT,
                        help=f"Timeout for APKs >= 10 MB (default {DEFAULT_LARGE_TIMEOUT}s)")
    parser.add_argument("--max-samples", type=int, default=0,
                        help="Limit number of pending samples to analyze (0 = all)")
    args = parser.parse_args()

    records = load_metadata()
    pending = [r for r in records if r.get("status") == "pending"]
    print(f"[*] Found {len(pending)} pending samples to analyze")

    if args.max_samples > 0:
        pending = pending[:args.max_samples]
        print(f"[*] Limited to first {len(pending)} samples")

    for i, record in enumerate(pending, start=1):
        sample_name = record["sample_name"]
        candidates = list(SAMPLES_DIR.rglob(sample_name))
        if not candidates:
            print(f"\n[!] Sample not found: {sample_name}")
            record["status"] = "error: file not found"
            save_metadata(records)
            continue
        sample_path = candidates[0]

        size = sample_path.stat().st_size
        timeout = args.large_timeout if size >= SIZE_THRESHOLD_BYTES else args.small_timeout
        size_mb = size / (1024 * 1024)

        print(f"\n[*] Analyzing {i}/{len(pending)}: {sample_name} ({size_mb:.1f} MB, timeout={timeout}s)")
        start = time.time()
        try:
            result = run_with_timeout(sample_path, WORK_DIR, timeout)
            elapsed = time.time() - start
            record["status"] = "analyzed"
            record["vt_detections"] = ""
            print(f"  [+] Done in {elapsed:.1f}s. Encodings: {len(result.get('encodings', []))}, "
                  f"Payloads: {len(result.get('payloads', []))}, "
                  f"C2s: {len(result.get('c2_infrastructure', []))}, "
                  f"Chains: {len(result.get('threat_chains', []))}")
        except TimeoutError as e:
            elapsed = time.time() - start
            record["status"] = f"error: timeout after {timeout}s"
            print(f"  [!] Timeout after {elapsed:.1f}s (limit {timeout}s): {e}")
        except Exception as e:
            elapsed = time.time() - start
            record["status"] = f"error: {e}"
            print(f"  [!] Error after {elapsed:.1f}s: {e}")

        save_metadata(records)

    print(f"\n[+] Batch analysis complete. Total samples: {len(records)}")


if __name__ == "__main__":
    main()
