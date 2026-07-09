"""
Evaluate pipeline detection on modern (2024-2025) Android malware samples.

Loads ground_truth_modern.json, scans pipeline results, computes recall
by confidence tier, categorizes false negatives by root cause.

Usage:
  python evaluation/eval_modern.py
  python evaluation/eval_modern.py --threshold 50 --verbose
"""

import json
import sys
from pathlib import Path

WORK_DIR = Path(__file__).parent.parent / "analysis" / "work"
GT_PATH = Path(__file__).parent.parent / "evaluation" / "ground_truth_modern.json"
OUTPUT_PATH = Path(__file__).parent.parent / "evaluation" / "modern_report.json"

DREBIN_RECALL_BASELINE = 0.9  # published Drebin detection rate on Drebin dataset


def total_string_count(strings: dict) -> int:
    """Count total string entries across all categories."""
    if not isinstance(strings, dict):
        return 0
    total = 0
    for v in strings.values():
        if isinstance(v, list):
            total += len(v)
    return total


def categorize_fn(pr: dict) -> str:
    """Categorize a false negative by root cause."""
    obf = pr.get("obfuscation_analysis", {}) or {}
    obf_score = obf.get("obfuscation_score", 0) or 0
    obf_level = obf.get("obfuscation_level", "") or ""

    c2 = pr.get("c2_infrastructure", []) or []
    chains = pr.get("threat_chains", []) or []
    strings = pr.get("strings", {}) or {}
    str_count = total_string_count(strings)

    if obf_score >= 70 and obf_level == "high":
        return "heavy_obfuscation"
    if len(c2) == 0 and len(chains) == 0:
        return "no_c2"
    if str_count < 10:
        return "low_signal"
    return "other"


def main():
    import argparse

    parser = argparse.ArgumentParser(description="Evaluate pipeline on modern samples")
    parser.add_argument("--threshold", type=int, default=50, help="Risk score threshold for detection (default: 50)")
    parser.add_argument("--verbose", action="store_true", help="Print per-sample breakdown")
    args = parser.parse_args()

    print("=" * 60)
    print("DroidForensix Modern Evaluation")
    print(f"Threshold: risk_score >= {args.threshold}")
    print("=" * 60)

    if not GT_PATH.exists():
        print(f"[!] Ground truth file not found: {GT_PATH}")
        print("[!] Run scripts/fetch_modern_samples.py first")
        sys.exit(1)

    gt = json.loads(GT_PATH.read_text())
    print(f"[*] Loaded {len(gt)} ground truth entries")

    # Scan pipeline results
    results = []
    missing = 0
    for sha, entry in gt.items():
        pr_path = WORK_DIR / sha / "pipeline_result.json"
        if not pr_path.exists():
            missing += 1
            if args.verbose:
                print(f"[!] No pipeline result for {sha}")
            continue
        try:
            pr = json.loads(pr_path.read_text())
        except (json.JSONDecodeError, Exception) as e:
            print(f"[!] Invalid JSON for {sha}: {e}")
            missing += 1
            continue

        llm = pr.get("llm_assessment", {}) or {}
        risk_score = llm.get("risk_score", 0) or 0
        obf = pr.get("obfuscation_analysis", {}) or {}
        obf_score = obf.get("obfuscation_score", 0) or 0
        fam_id = pr.get("family_identification", {}) or {}
        family = fam_id.get("family") or entry.get("family")
        severity = llm.get("severity", "unknown")

        results.append({
            "sha256": sha,
            "confidence": entry.get("confidence", "medium"),
            "source": entry.get("source", "unknown"),
            "risk_score": risk_score,
            "detected": risk_score >= args.threshold,
            "severity": severity,
            "obfuscation_score": obf_score,
            "family": family,
            "c2_count": len(pr.get("c2_infrastructure", []) or []),
            "chain_count": len(pr.get("threat_chains", []) or []),
            "string_count": total_string_count(pr.get("strings", {}) or {}),
            "vt_detections": entry.get("vt_detections", 0),
            "gt_reason": entry.get("gt_reason", ""),
        })

    if missing:
        print(f"[!] {missing} samples missing pipeline results (skipped)")

    if not results:
        print("[!] No evaluatable samples")
        sys.exit(1)

    total = len(results)
    detected = sum(1 for r in results if r["detected"])
    false_negatives = [r for r in results if not r["detected"]]

    print(f"\n[*] Total evaluatable: {total}")
    print(f"[*] Detected: {detected}/{total} ({detected / total * 100:.1f}%)")
    print(f"[*] False negatives (undetected): {len(false_negatives)}")

    # By confidence tier
    by_confidence = {}
    for tier in ("high", "medium"):
        tier_results = [r for r in results if r["confidence"] == tier]
        if not tier_results:
            continue
        tier_detected = sum(1 for r in tier_results if r["detected"])
        tier_total = len(tier_results)
        recall = round(tier_detected / tier_total, 3) if tier_total else 0
        by_confidence[tier] = {
            "total": tier_total,
            "detected": tier_detected,
            "recall": recall,
        }
        pct = tier_detected / tier_total * 100
        print(f"\n  {tier}-confidence: {tier_detected}/{tier_total} ({pct:.1f}%)")

    overall_recall = round(detected / total, 3) if total else 0
    print(f"\n  Overall recall: {detected}/{total} ({overall_recall:.3f})")

    # Categorize false negatives
    fn_categories = {}
    fn_details = []
    for r in false_negatives:
        # Re-read pipeline result for full categorization
        pr_path = WORK_DIR / r["sha256"] / "pipeline_result.json"
        try:
            pr = json.loads(pr_path.read_text())
        except Exception:
            pr = {}
        category = categorize_fn(pr)
        fn_categories[category] = fn_categories.get(category, 0) + 1
        fn_details.append({
            "sha256": r["sha256"],
            "confidence": r["confidence"],
            "risk_score": r["risk_score"],
            "category": category,
            "obfuscation_score": r["obfuscation_score"],
            "family": r["family"],
            "c2_count": r["c2_count"],
            "chain_count": r["chain_count"],
            "string_count": r["string_count"],
        })

    print(f"\n--- Failure Categorization ({len(false_negatives)} FNs) ---")
    for cat in ["heavy_obfuscation", "no_c2", "low_signal", "other"]:
        count = fn_categories.get(cat, 0)
        print(f"  {cat}: {count}")

    # Build report
    report = {
        "total_samples": total,
        "by_confidence": by_confidence,
        "overall_recall": overall_recall,
        "false_negatives": len(false_negatives),
        "failure_categorization": fn_categories,
        "fn_details": fn_details,
        "comparison_to_drebin": {
            "drebin_recall": DREBIN_RECALL_BASELINE,
            "modern_recall": overall_recall,
            "delta": round(overall_recall - DREBIN_RECALL_BASELINE, 3),
        },
    }

    OUTPUT_PATH.parent.mkdir(parents=True, exist_ok=True)
    OUTPUT_PATH.write_text(json.dumps(report, indent=2))
    print(f"\n[+] Report saved to: {OUTPUT_PATH}")

    # Verbose per-sample breakdown
    if args.verbose and false_negatives:
        print(f"\n--- False Negative Detail ---")
        for r in fn_details:
            print(f"  {r['sha256'][:16]}... conf={r['confidence']} "
                  f"risk={r['risk_score']} cat={r['category']} "
                  f"obf={r['obfuscation_score']} fam={r['family']} "
                  f"c2={r['c2_count']} chains={r['chain_count']} "
                  f"strs={r['string_count']}")


if __name__ == "__main__":
    main()
