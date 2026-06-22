#!/usr/bin/env python3
"""
Validation harness for the DroidForensix 100-sample ground-truth test set.

Loads per-sample pipeline_result.json files and computes classification metrics
against the labels in ground_truth_test_set.json.

Usage:
    venv/Scripts/python compute_validation_metrics.py
"""

import json
import os
from pathlib import Path
from typing import Dict, List, Tuple

def load_ground_truth(path: str = "ground_truth_test_set.json") -> List[Dict]:
    with open(path, "r", encoding="utf-8") as f:
        return json.load(f)


def _fmt_table(rows: List[List[str]], headers: List[str]) -> str:
    col_widths = [max(len(str(row[i])) for row in [headers] + rows) for i in range(len(headers))]
    lines = []
    lines.append(" | ".join(str(h).ljust(col_widths[i]) for i, h in enumerate(headers)))
    lines.append("-" * (sum(col_widths) + 3 * (len(headers) - 1)))
    for row in rows:
        lines.append(" | ".join(str(row[i]).ljust(col_widths[i]) for i in range(len(row))))
    return "\n".join(lines)


def load_pipeline_result(sha256: str, work_dir: str = "analysis/work") -> Dict:
    result_path = Path(work_dir) / sha256 / "pipeline_result.json"
    if not result_path.exists():
        return {}
    with open(result_path, "r", encoding="utf-8") as f:
        return json.load(f)


def get_malware_score(result: Dict) -> Tuple[float, str]:
    """Return (score, source_label)."""
    llm = result.get("llm_assessment", {}) or {}
    score = llm.get("risk_score", 0) or 0
    source = "post_process" if result.get("post_process_notes") else "fallback"
    return score, source


def classify(score: float, threshold: float) -> str:
    return "malware" if score >= threshold else "benign"


def compute_metrics(records: List[Dict], threshold: float) -> Dict:
    tp = fp = tn = fn = 0
    for r in records:
        actual = r["label"]
        predicted = classify(r["score"], threshold)
        if actual == "malware" and predicted == "malware":
            tp += 1
        elif actual == "benign" and predicted == "malware":
            fp += 1
        elif actual == "benign" and predicted == "benign":
            tn += 1
        elif actual == "malware" and predicted == "benign":
            fn += 1

    precision = tp / (tp + fp) if (tp + fp) else 0.0
    recall = tp / (tp + fn) if (tp + fn) else 0.0
    specificity = tn / (tn + fp) if (tn + fp) else 0.0
    f1 = 2 * precision * recall / (precision + recall) if (precision + recall) else 0.0
    accuracy = (tp + tn) / len(records) if records else 0.0

    return {
        "threshold": threshold,
        "tp": tp,
        "fp": fp,
        "tn": tn,
        "fn": fn,
        "precision": precision,
        "recall": recall,
        "specificity": specificity,
        "f1": f1,
        "accuracy": accuracy,
    }


def main():
    samples = load_ground_truth()
    records = []
    missing = []

    for sample in samples:
        sha = sample["sha256"]
        result = load_pipeline_result(sha)
        if not result:
            missing.append(sample)
            continue
        score, source = get_malware_score(result)
        records.append({
            "sha256": sha,
            "name": sample.get("name", ""),
            "label": sample.get("ground_truth", sample.get("label", "unknown")),
            "score": score,
            "source": source,
            "result": result,
        })

    print(f"Loaded {len(records)}/{len(samples)} results")
    if missing:
        print(f"Missing results for {len(missing)} samples:")
        for m in missing:
            print(f"  - {m.get('name', '')}: {m['sha256']}")
        return

    print("\n=== Threshold sweep ===")
    thresholds = [45, 50, 55, 60, 65, 70, 75, 80]
    sweep = [compute_metrics(records, t) for t in thresholds]
    print(_fmt_table(
        [
            [
                str(m["threshold"]),
                str(m["tp"]), str(m["fp"]), str(m["tn"]), str(m["fn"]),
                f"{m['precision']:.3f}",
                f"{m['recall']:.3f}",
                f"{m['specificity']:.3f}",
                f"{m['f1']:.3f}",
                f"{m['accuracy']:.3f}",
            ]
            for m in sweep
        ],
        ["Threshold", "TP", "FP", "TN", "FN", "Precision", "Recall", "Specificity", "F1", "Accuracy"],
    ))

    # Best by F1
    best_f1 = max(sweep, key=lambda m: (m["f1"], m["accuracy"]))
    print(f"\nBest F1: threshold={best_f1['threshold']}, F1={best_f1['f1']:.3f}, Acc={best_f1['accuracy']:.3f}")

    # Failure analysis
    print("\n=== Failure analysis ===")
    print(f"\nFalse Positives at threshold={best_f1['threshold']}:")
    fps = [r for r in records if r["label"] == "benign" and classify(r["score"], best_f1["threshold"]) == "malware"]
    if fps:
        print(_fmt_table(
            [[r["name"], str(r["score"]), r["source"]] for r in fps],
            ["Name", "Score", "Source"],
        ))
    else:
        print("  None")

    print(f"\nFalse Negatives at threshold={best_f1['threshold']}:")
    fns = [r for r in records if r["label"] == "malware" and classify(r["score"], best_f1["threshold"]) == "benign"]
    if fns:
        print(_fmt_table(
            [[r["name"], str(r["score"]), r["source"]] for r in fns],
            ["Name", "Score", "Source"],
        ))
    else:
        print("  None")

    # Save detailed report
    report = {
        "total_samples": len(records),
        "best_threshold": best_f1["threshold"],
        "metrics": best_f1,
        "threshold_sweep": sweep,
        "false_positives": [
            {"name": r["name"], "sha256": r["sha256"], "score": r["score"], "source": r["source"]}
            for r in fps
        ],
        "false_negatives": [
            {"name": r["name"], "sha256": r["sha256"], "score": r["score"], "source": r["source"]}
            for r in fns
        ],
    }
    with open("validation_metrics_report.json", "w", encoding="utf-8") as f:
        json.dump(report, f, indent=2)
    print("\nSaved report to validation_metrics_report.json")


if __name__ == "__main__":
    main()
