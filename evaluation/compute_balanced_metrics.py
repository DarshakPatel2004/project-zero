"""
DroidForensix Balanced Evaluation Metrics
==========================================
Computes precision, recall, F1, specificity, and sensitivity analysis
on combined malware + benign test sets.

Usage:
  python3 evaluation/compute_balanced_metrics.py [--threshold 50] [--sensitivity] [--verbose]
"""

import json
import sys
from pathlib import Path

EVAL_DIR = Path(__file__).parent
WORK_DIR = EVAL_DIR.parent / "analysis" / "work"
MALWARE_GT = EVAL_DIR / "ground_truth_modern.json"
BENIGN_GT = EVAL_DIR / "ground_truth_benign.json"

OUTPUT_ON = EVAL_DIR / "balanced_metrics_rule_ON.json"
OUTPUT_OFF = EVAL_DIR / "balanced_metrics_rule_OFF.json"


def get_risk(sha: str) -> int:
    """Return risk_score from pipeline_result.json, or None if missing."""
    pr_path = WORK_DIR / sha / "pipeline_result.json"
    if not pr_path.exists():
        return None
    try:
        data = json.loads(pr_path.read_text())
        llm = data.get("llm_assessment", {}) or {}
        return llm.get("risk_score", 0) or 0
    except Exception:
        return None


def compute(threshold: int, gt_file: Path, label: str, verbose: bool = False) -> dict:
    """Compute detection metrics for one ground truth file."""
    gt = json.loads(gt_file.read_text())
    results = []
    skipped = 0
    for sha, entry in gt.items():
        risk = get_risk(sha)
        if risk is None:
            skipped += 1
            continue
        results.append({
            "sha256": sha[:16],
            "risk_score": risk,
            "label": entry.get("label", label),
            "detected": risk >= threshold,
        })

    detected = sum(1 for r in results if r["detected"])
    total = len(results)
    return {
        "label": label,
        "source": label.capitalize(),
        "total": total,
        "skipped": skipped,
        "detected": detected,
        "missed": total - detected,
        "recall": detected / total if total else 0,
        "fpr": 1 - (total - detected) / total if total else None,
        "detail": results if verbose else None,
    }


def print_results(mal: dict, ben: dict, threshold: int):
    tp = mal["detected"]
    fn = mal["missed"]
    tn = ben["total"] - ben["detected"]
    fp = ben["detected"]

    recall = tp / (tp + fn) if (tp + fn) else 0
    precision = tp / (tp + fp) if (tp + fp) else 0
    f1 = 2 * precision * recall / (precision + recall) if (precision + recall) else 0
    accuracy = (tp + tn) / (tp + tn + fp + fn) if (tp + tn + fp + fn) else 0
    specificity = tn / (tn + fp) if (tn + fp) else 0

    print()
    print("=" * 70)
    print(f"  DroidForensix Balanced Evaluation (Threshold: {threshold})")
    print("=" * 70)

    print(f"\n  Malware Detection (Positive Class):")
    print(f"    Evaluated: {mal['total']}  | Skipped: {mal['skipped']}")
    print(f"    TP: {tp}  |  FN: {fn}")
    print(f"    Recall (TPR):    {recall:.1%}")
    print(f"    Miss Rate (FNR): {1-recall:.1%}")

    print(f"\n  Benign Classification (Negative Class):")
    print(f"    Evaluated: {ben['total']}  | Skipped: {ben['skipped']}")
    print(f"    TN: {tn}  |  FP: {fp}")
    print(f"    Specificity (TNR): {specificity:.1%}")
    fpr_str = f"{fp}/{ben['total']} ({fp/ben['total']*100:.1f}%)" if ben['total'] else "N/A (no benign samples)"
    print(f"    False Positive Rate: {fpr_str}")

    print(f"\n  Balanced Metrics:")
    print(f"    Precision:    {precision:.1%}")
    print(f"    Recall:       {recall:.1%}")
    print(f"    F1-Score:     {f1:.3f}")
    print(f"    Accuracy:     {accuracy:.1%}")

    print(f"\n  Confusion Matrix:")
    print(f"                    Predicted Malware  Predicted Benign")
    print(f"    Actual Malware         {tp:3d}               {fn:3d}")
    print(f"    Actual Benign          {fp:3d}               {tn:3d}")
    print()
    print("=" * 70)
    print()

    return {
        "threshold": threshold,
        "confusion_matrix": {"tp": tp, "fn": fn, "fp": fp, "tn": tn},
        "recall": recall,
        "precision": precision,
        "f1": f1,
        "specificity": specificity,
        "accuracy": accuracy,
        "malware_evaluated": mal["total"],
        "malware_skipped": mal["skipped"],
        "benign_evaluated": ben["total"],
        "benign_skipped": ben["skipped"],
    }


def main():
    import argparse
    parser = argparse.ArgumentParser()
    parser.add_argument("--threshold", type=int, default=50)
    parser.add_argument("--sensitivity", action="store_true")
    parser.add_argument("--verbose", action="store_true")
    parser.add_argument("--output", type=str)
    args = parser.parse_args()

    if not MALWARE_GT.exists():
        print(f"[!] Malware ground truth not found: {MALWARE_GT}")
        sys.exit(1)
    if not BENIGN_GT.exists():
        print(f"[!] Benign ground truth not found: {BENIGN_GT}")
        print("[!] Run scripts/curate_benign.py first")
        sys.exit(1)

    mal = compute(args.threshold, MALWARE_GT, "malware", args.verbose)
    ben = compute(args.threshold, BENIGN_GT, "benign", args.verbose)

    if mal["total"] == 0:
        print("[!] No malware results found — run pipeline first")
        sys.exit(1)
    if ben["total"] == 0:
        print("[!] No benign results found — run pipeline first")
        # Still run with just malware for debugging
        print("   (malware-only mode)")

    if args.sensitivity:
        rows = []
        for t in [40, 50, 60]:
            m = compute(t, MALWARE_GT, "malware")
            b = compute(t, BENIGN_GT, "benign")
            r = print_results(m, b, t)
            rows.append(r)
        output = {"sensitivity_analysis": rows}
    else:
        output = print_results(mal, ben, args.threshold)

    out_path = args.output or str(OUTPUT_ON)
    open(out_path, "w").write(json.dumps(output, indent=2))
    print(f"[+] Saved to {out_path}")


if __name__ == "__main__":
    main()
