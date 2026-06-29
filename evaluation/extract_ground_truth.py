"""
Extract ground truth labels from pipeline results + test set definition.

Output: evaluation/ground_truth.json
Format: {sha256: {family, is_malware, detected_by_pipeline, risk_score}}
"""

import json
from pathlib import Path

HASHES_FILE = Path("evaluation/drebin_hashes.txt")
TEST_SET_FILE = Path("ground_truth_test_set.json")
WORK_DIR = Path("analysis/work")
OUTPUT_FILE = Path("evaluation/ground_truth.json")

# Read hashes
hashes = [line.strip() for line in HASHES_FILE.read_text().strip().splitlines() if line.strip()]

# Build lookup from test set
test_set = {}
if TEST_SET_FILE.exists():
    samples = json.loads(TEST_SET_FILE.read_text())
    for s in samples:
        test_set[s["sha256"]] = s

ground_truth = {}
for sha in hashes:
    pipeline_file = WORK_DIR / sha / "pipeline_result.json"
    if not pipeline_file.exists():
        print(f"  [SKIP] {sha}: no pipeline result")
        continue

    result = json.loads(pipeline_file.read_text())
    llm = result.get("llm_assessment", {}) or {}
    risk_score = llm.get("risk_score", 0) or 0

    entry = test_set.get(sha, {})
    ground_truth[sha] = {
        "family": entry.get("family", "unknown"),
        "is_malware": True,
        "detected_by_pipeline": risk_score >= 50,
        "risk_score": risk_score,
    }

OUTPUT_FILE.parent.mkdir(parents=True, exist_ok=True)
OUTPUT_FILE.write_text(json.dumps(ground_truth, indent=2))

detected = sum(1 for v in ground_truth.values() if v["detected_by_pipeline"])
total = len(ground_truth)
print(f"\nExtracted ground truth for {total} APKs")
print(f"Detected:   {detected}/{total} ({detected/total*100:.0f}%)")
print(f"Undetected: {total-detected}/{total} ({(total-detected)/total*100:.0f}%)")
print(f"Saved to:   {OUTPUT_FILE}")
