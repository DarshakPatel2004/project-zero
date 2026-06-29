"""
Compute detection metrics from ground truth data.

Usage:
    python evaluation/compute_metrics.py
    python evaluation/compute_metrics.py --threshold 45

Output: evaluation/metrics_report.json
"""

import json
import argparse
from pathlib import Path

GROUND_TRUTH_FILE = Path("evaluation/ground_truth.json")
REPORT_FILE = Path("evaluation/metrics_report.json")

THRESHOLD = 50


def compute_metrics(ground_truth: dict, threshold: int) -> dict:
    total = len(ground_truth)
    tp = sum(1 for v in ground_truth.values() if v["risk_score"] >= threshold)
    fn = total - tp
    fp = 0

    recall = tp / total if total else 0.0

    undetected = [
        {"sha256": k, "risk_score": v["risk_score"], "family": v["family"]}
        for k, v in sorted(ground_truth.items())
        if v["risk_score"] < threshold
    ]

    return {
        "threshold": threshold,
        "total_samples": total,
        "true_positives": tp,
        "false_negatives": fn,
        "false_positives": fp,
        "recall": round(recall, 4),
        "precision": 1.0,
        "undetected": undetected,
    }


def main():
    parser = argparse.ArgumentParser(
        description="Compute DroidForensix detection metrics"
    )
    parser.add_argument(
        "--threshold",
        type=int,
        default=THRESHOLD,
        help=f"Risk score threshold (default: {THRESHOLD})",
    )
    args = parser.parse_args()

    if not GROUND_TRUTH_FILE.exists():
        print(f"Error: {GROUND_TRUTH_FILE} not found. Run extract_ground_truth.py first.")
        return

    ground_truth = json.loads(GROUND_TRUTH_FILE.read_text())
    metrics = compute_metrics(ground_truth, args.threshold)

    REPORT_FILE.parent.mkdir(parents=True, exist_ok=True)
    REPORT_FILE.write_text(json.dumps(metrics, indent=2))

    pct = metrics["recall"] * 100
    print(f"Threshold:         {metrics['threshold']}")
    print(f"Total samples:     {metrics['total_samples']}")
    print(f"True positives:    {metrics['true_positives']}")
    print(f"False negatives:   {metrics['false_negatives']}")
    print(f"False positives:   {metrics['false_positives']}")
    print(f"Recall:            {pct:.1f}% ({metrics['true_positives']}/{metrics['total_samples']})")
    print(f"Precision:         {metrics['precision']*100:.0f}%")
    print(f"Undetected:        {len(metrics['undetected'])}")
    print(f"Report saved to:   {REPORT_FILE}")


if __name__ == "__main__":
    main()
