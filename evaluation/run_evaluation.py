"""
Full evaluation: compare pipeline results against ground truth,
including pendrive samples.

Revised: uses llm_assessment.severity (not overall_severity).
"""
import json
import csv
from pathlib import Path

WORK_DIR = Path("analysis/work")
TEST_SET_FILE = Path("ground_truth_test_set.json")
DREBIN_HASHES_FILE = Path("evaluation/drebin_hashes.txt")
METADATA_FILE = Path("sample_metadata.csv")
OUTPUT_FILE = Path("evaluation/evaluation_report.json")

# Load all pipeline results + family IDs
results = []
for d in sorted(WORK_DIR.iterdir()):
    if not d.is_dir():
        continue
    pr_file = d / "pipeline_result.json"
    fm_file = d / "family.json"
    if not pr_file.exists():
        continue
    pr = json.loads(pr_file.read_text())
    llm = pr.get("llm_assessment") or {}
    fm = json.loads(fm_file.read_text()) if fm_file.exists() else {"family": "unknown", "confidence": 0, "method": ""}
    results.append({
        "sha256": d.name,
        "family": fm.get("family", "unknown"),
        "family_confidence": fm.get("confidence", 0),
        "family_method": fm.get("method", ""),
        "severity": llm.get("severity", "unknown"),
        "risk_score": llm.get("risk_score", 0) or 0,
    })

# Load ground truth test set
test_set = {}
if TEST_SET_FILE.exists():
    for s in json.loads(TEST_SET_FILE.read_text()):
        test_set[s["sha256"]] = s

# Load Drebin hashes
drebin_hashes = set()
if DREBIN_HASHES_FILE.exists():
    for line in DREBIN_HASHES_FILE.read_text().strip().splitlines():
        h = line.strip()
        if h:
            drebin_hashes.add(h)

# Load pendrive hashes from metadata
pendrive_hashes = set()
if METADATA_FILE.exists():
    with open(METADATA_FILE, "r", encoding="utf-8") as f:
        for row in csv.DictReader(f):
            if row.get("source", "").strip() == "pendrive":
                pendrive_hashes.add(row["sha256"].strip())

# Infer pendrive hashes from the directory — anything not in the test set
# and not an original sample is probably pendrive. Let's figure out the full
# set of original 262 from the test set + anything else is pendrive.
# The original samples had apk_path starting with samples\malware or samples\legitimate
# But simpler: the test set covers 100 samples. The original 262 also includes
# samples from the same dirs. Let's look at what metadata.csv says.

# Also try to derive from family.json presence (watcher only ran on pendrive samples)
# Actually: watcher ran on pendrive samples. So samples with family.json == pendrive.
# But some originals might also have family.json from earlier processing.
# Let's be smart: check the pipeline_result metadata for source info.

orig_hashes = set()
pend_hashes2 = set()
for d in sorted(WORK_DIR.iterdir()):
    if not d.is_dir():
        continue
    pr_file = d / "pipeline_result.json"
    if not pr_file.exists():
        continue
    pr = json.loads(pr_file.read_text())
    meta = pr.get("metadata") or {}
    apk_path = meta.get("apk_path", "")
    if "pendrive" in apk_path.lower() or "PENDRIVE" in apk_path:
        pend_hashes2.add(d.name)
    else:
        orig_hashes.add(d.name)

print(f"Pipeline results total: {len(results)}")
print(f"From apk_path: Original={len(orig_hashes)} Pendrive={len(pend_hashes2)}")
print(f"From metadata.csv: Pendrive={len(pendrive_hashes)}")
print(f"Ground truth entries: {len(test_set)}")
print(f"Drebin test hashes: {len(drebin_hashes)}")
print()

by_hash = {r["sha256"]: r for r in results}

# ─── 1. Drebin detection ───────────────────────────────────────────────
drebin_results = [by_hash[h] for h in drebin_hashes if h in by_hash]
print("=== DREBIN MALWARE DETECTION ===")
if drebin_results:
    detected = sum(1 for r in drebin_results if r["risk_score"] >= 50)
    print(f"Total Drebin in pipeline: {len(drebin_results)}")
    print(f"Detected (risk >= 50): {detected}/{len(drebin_results)} ({detected/len(drebin_results)*100:.1f}%)")
    print(f"Undetected: {len(drebin_results)-detected} ({(len(drebin_results)-detected)/len(drebin_results)*100:.1f}%)")
    # Per-family breakdown
    fam_stats = {}
    for r in drebin_results:
        gt = test_set.get(r["sha256"], {})
        gt_fam = gt.get("family", "unknown")
        fam_stats.setdefault(gt_fam, {"total": 0, "detected": 0})
        fam_stats[gt_fam]["total"] += 1
        if r["risk_score"] >= 50:
            fam_stats[gt_fam]["detected"] += 1
    print("\nPer-family detection:")
    for fam, st in sorted(fam_stats.items(), key=lambda x: -x[1]["total"]):
        pct = st["detected"] / st["total"] * 100
        print(f"  {fam}: {st['detected']}/{st['total']} ({pct:.0f}%)")
    print()
else:
    print("(none found in pipeline results)")
    print()

# ─── 2. F-Droid false positives ───────────────────────────────────────
fdroid_hashes = [s["sha256"] for s in test_set.values() if s["ground_truth"] == "benign"]
fdroid_results = [by_hash[h] for h in fdroid_hashes if h in by_hash]
print("=== F-DROID BENIGN FALSE POSITIVES ===")
if fdroid_results:
    fp = sum(1 for r in fdroid_results if r["risk_score"] >= 50)
    print(f"Total F-Droid in pipeline: {len(fdroid_results)}")
    print(f"False positives (risk >= 50): {fp}/{len(fdroid_results)} ({fp/len(fdroid_results)*100:.1f}%)")
    print(f"Correctly benign: {len(fdroid_results)-fp} ({(len(fdroid_results)-fp)/len(fdroid_results)*100:.1f}%)")
    if fp > 0:
        print("\nFalse positives detail:")
        for r in fdroid_results:
            if r["risk_score"] >= 50:
                gt = test_set.get(r["sha256"], {})
                print(f"  {r['sha256'][:16]}... risk={r['risk_score']} pkg={gt.get('package','?')}")
else:
    print("(none found in pipeline results)")
print()

# ─── 3. Pendrive results ──────────────────────────────────────────────
pendrive_results = [r for r in results if r["sha256"] in pend_hashes2]
print("=== PENDRIVE SAMPLES ===")
print(f"Total: {len(pendrive_results)}")
if pendrive_results:
    for sev in ["high", "medium", "low"]:
        n = sum(1 for r in pendrive_results if r["severity"] == sev)
        print(f"  {sev}: {n} ({n/len(pendrive_results)*100:.1f}%)")
    fam_dist = {}
    for r in pendrive_results:
        f = r["family"]
        fam_dist[f] = fam_dist.get(f, 0) + 1
    print("\nFamily distribution:")
    for f, c in sorted(fam_dist.items(), key=lambda x: -x[1]):
        print(f"  {f}: {c}")
print()

# ─── 4. Original 262 results ──────────────────────────────────────────
orig_results = [r for r in results if r["sha256"] in orig_hashes]
print("=== ORIGINAL 262 SAMPLES ===")
print(f"Total: {len(orig_results)}")
if orig_results:
    for sev in ["high", "medium", "low"]:
        n = sum(1 for r in orig_results if r["severity"] == sev)
        print(f"  {sev}: {n} ({n/len(orig_results)*100:.1f}%)")
print()

# ─── 5. Overall ───────────────────────────────────────────────────────
print("=== OVERALL ===")
print(f"Total samples: {len(results)}")
for sev in ["high", "medium", "low"]:
    n = sum(1 for r in results if r["severity"] == sev)
    print(f"  {sev}: {n} ({n/len(results)*100:.1f}%)")

# Save report
report = {
    "total_samples": len(results),
    "original_count": len(orig_results),
    "pendrive_count": len(pendrive_results),
    "drebin": {
        "total": len(drebin_results),
        "detected": sum(1 for r in drebin_results if r["risk_score"] >= 50) if drebin_results else 0,
    },
    "fdroid": {
        "total": len(fdroid_results),
        "false_positives": sum(1 for r in fdroid_results if r["risk_score"] >= 50) if fdroid_results else 0,
    },
    "severity_original": {
        sev: sum(1 for r in orig_results if r["severity"] == sev)
        for sev in ["high", "medium", "low"]
    },
    "severity_pendrive": {
        sev: sum(1 for r in pendrive_results if r["severity"] == sev)
        for sev in ["high", "medium", "low"]
    } if pendrive_results else {},
    "severity_all": {
        sev: sum(1 for r in results if r["severity"] == sev)
        for sev in ["high", "medium", "low"]
    },
    "pendrive_families": {
        f: c for f, c in sorted(fam_dist.items(), key=lambda x: -x[1])
    } if pendrive_results else {},
}
OUTPUT_FILE.parent.mkdir(parents=True, exist_ok=True)
OUTPUT_FILE.write_text(json.dumps(report, indent=2))
print(f"\nReport saved to: {OUTPUT_FILE}")
