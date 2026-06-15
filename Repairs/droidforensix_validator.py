#!/usr/bin/env python3
"""
DroidForensix Validation Framework
==================================
Measures true-positive rate, false-positive rate, and confidence calibration
against labeled ground truth (Drebin, F-Droid, custom malware corpus).

Usage:
  python droidforensix_validator.py --ground-truth drebin_samples.json --results output.txt
"""

import json
import csv
from dataclasses import dataclass, field
from typing import List, Dict, Tuple, Optional
from pathlib import Path
from enum import Enum
import sys


class Severity(Enum):
    """Risk severity levels."""
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"


class ThreatType(Enum):
    """Threat classification."""
    MALWARE = "malware"
    BENIGN = "benign"


@dataclass
class Sample:
    """A single APK sample with ground truth."""
    name: str
    sha256: str
    package: str
    ground_truth: ThreatType
    family: Optional[str] = None  # Malware family (e.g., "Metasploit", "jRPN")


@dataclass
class DetectionResult:
    """Output from DroidForensix pipeline."""
    sample_name: str
    sha256: str
    risk_score: float  # 0-100
    severity: Severity
    primary_threat: str
    confidence: float  # 0-1
    c2_count: int
    payload_count: int
    threat_chain_count: int
    obfuscation_score: float
    reflection_count: int
    dynamic_loading_count: int


@dataclass
class ValidationMetrics:
    """Per-sample validation metrics."""
    sample: Sample
    result: DetectionResult
    ground_truth_label: str
    predicted_label: str
    
    # Classification metrics
    is_true_positive: bool = False
    is_false_positive: bool = False
    is_true_negative: bool = False
    is_false_negative: bool = False
    
    # Confidence analysis
    confidence_correct: bool = False  # High confidence on correct predictions
    confidence_wrong: bool = False    # High confidence on wrong predictions
    
    # Detailed audit trail
    audit_notes: List[str] = field(default_factory=list)


class ValidationHarness:
    """Main evaluation engine."""
    
    def __init__(self, verbose: bool = True):
        self.verbose = verbose
        self.ground_truth: Dict[str, Sample] = {}
        self.results: Dict[str, DetectionResult] = {}
        self.metrics: List[ValidationMetrics] = []
    
    def load_ground_truth(self, filepath: str) -> None:
        """Load labeled samples (JSON format)."""
        with open(filepath, 'r') as f:
            data = json.load(f)
        
        for entry in data:
            sample = Sample(
                name=entry['name'],
                sha256=entry['sha256'],
                package=entry['package'],
                ground_truth=ThreatType(entry['ground_truth']),
                family=entry.get('family')
            )
            self.ground_truth[sample.sha256] = sample
        
        if self.verbose:
            print(f"[+] Loaded {len(self.ground_truth)} ground-truth samples")
    
    def load_pipeline_results(self, filepath: str) -> None:
        """Load DroidForensix output (JSON or CSV format)."""
        if filepath.endswith('.json'):
            with open(filepath, 'r') as f:
                data = json.load(f)
        elif filepath.endswith('.csv'):
            data = []
            with open(filepath, 'r') as f:
                reader = csv.DictReader(f)
                data = list(reader)
        else:
            raise ValueError("Unsupported format; use JSON or CSV")
        
        for entry in data:
            result = DetectionResult(
                sample_name=entry['sample_name'],
                sha256=entry['sha256'],
                risk_score=float(entry['risk_score']),
                severity=Severity(entry['severity']),
                primary_threat=entry['primary_threat'],
                confidence=float(entry['confidence']),
                c2_count=int(entry.get('c2_count', 0)),
                payload_count=int(entry.get('payload_count', 0)),
                threat_chain_count=int(entry.get('threat_chain_count', 0)),
                obfuscation_score=float(entry.get('obfuscation_score', 0)),
                reflection_count=int(entry.get('reflection_count', 0)),
                dynamic_loading_count=int(entry.get('dynamic_loading_count', 0))
            )
            self.results[result.sha256] = result
        
        if self.verbose:
            print(f"[+] Loaded {len(self.results)} pipeline results")
    
    def validate(self, threshold: float = 0.5) -> None:
        """Compare pipeline results against ground truth."""
        matched = 0
        unmatched_gt = []
        unmatched_results = []
        
        for sha256, sample in self.ground_truth.items():
            if sha256 not in self.results:
                unmatched_gt.append(sample)
                continue
            
            result = self.results[sha256]
            
            # Determine predicted label (threshold-based)
            predicted_malware = result.risk_score >= (threshold * 100)
            actual_malware = sample.ground_truth == ThreatType.MALWARE
            
            predicted_label = "malware" if predicted_malware else "benign"
            ground_truth_label = "malware" if actual_malware else "benign"
            
            # Classification outcomes
            is_tp = actual_malware and predicted_malware
            is_fp = (not actual_malware) and predicted_malware
            is_tn = (not actual_malware) and (not predicted_malware)
            is_fn = actual_malware and (not predicted_malware)
            
            # Confidence analysis
            high_confidence = result.confidence >= 0.7
            correct_prediction = predicted_label == ground_truth_label
            
            metric = ValidationMetrics(
                sample=sample,
                result=result,
                ground_truth_label=ground_truth_label,
                predicted_label=predicted_label,
                is_true_positive=is_tp,
                is_false_positive=is_fp,
                is_true_negative=is_tn,
                is_false_negative=is_fn,
                confidence_correct=(high_confidence and correct_prediction),
                confidence_wrong=(high_confidence and not correct_prediction)
            )
            
            # Add audit notes
            if is_fp:
                metric.audit_notes.append(
                    f"FALSE POSITIVE: Benign {sample.package} scored {result.risk_score} "
                    f"(C2s={result.c2_count}, chains={result.threat_chain_count})"
                )
            elif is_fn:
                metric.audit_notes.append(
                    f"FALSE NEGATIVE: Malware {sample.package} scored {result.risk_score} "
                    f"(C2s={result.c2_count}, chains={result.threat_chain_count})"
                )
            
            self.metrics.append(metric)
            matched += 1
        
        # Report unmatched samples
        if unmatched_gt:
            print(f"\n[!] {len(unmatched_gt)} ground-truth samples missing from results:")
            for s in unmatched_gt[:5]:
                print(f"    - {s.name} ({s.sha256[:16]}...)")
        
        if unmatched_results:
            print(f"\n[!] {len(unmatched_results)} pipeline results not in ground truth:")
            for r in unmatched_results[:5]:
                print(f"    - {r.sample_name} ({r.sha256[:16]}...)")
        
        if self.verbose:
            print(f"[+] Validated {matched} samples")
    
    def compute_metrics(self) -> Dict[str, float]:
        """Compute precision, recall, F1, FPR, FNR."""
        tp = sum(1 for m in self.metrics if m.is_true_positive)
        fp = sum(1 for m in self.metrics if m.is_false_positive)
        tn = sum(1 for m in self.metrics if m.is_true_negative)
        fn = sum(1 for m in self.metrics if m.is_false_negative)
        
        total = tp + fp + tn + fn
        
        # Avoid division by zero
        precision = tp / (tp + fp) if (tp + fp) > 0 else 0
        recall = tp / (tp + fn) if (tp + fn) > 0 else 0
        f1 = 2 * (precision * recall) / (precision + recall) if (precision + recall) > 0 else 0
        
        fpr = fp / (fp + tn) if (fp + tn) > 0 else 0  # False-positive rate
        fnr = fn / (fn + tp) if (fn + tp) > 0 else 0  # False-negative rate
        
        confidence_correct = sum(1 for m in self.metrics if m.confidence_correct)
        confidence_wrong = sum(1 for m in self.metrics if m.confidence_wrong)
        
        return {
            'total_samples': total,
            'true_positives': tp,
            'false_positives': fp,
            'true_negatives': tn,
            'false_negatives': fn,
            'precision': precision,
            'recall': recall,
            'f1': f1,
            'false_positive_rate': fpr,
            'false_negative_rate': fnr,
            'accuracy': (tp + tn) / total if total > 0 else 0,
            'high_confidence_correct': confidence_correct,
            'high_confidence_wrong': confidence_wrong,
        }
    
    def print_report(self) -> None:
        """Print detailed validation report."""
        metrics = self.compute_metrics()
        
        print("\n" + "="*70)
        print("DROIDFORENSIX VALIDATION REPORT")
        print("="*70)
        
        print("\n[SUMMARY]")
        print(f"  Total Samples:           {metrics['total_samples']}")
        print(f"  True Positives:          {metrics['true_positives']}")
        print(f"  False Positives:         {metrics['false_positives']}")
        print(f"  True Negatives:          {metrics['true_negatives']}")
        print(f"  False Negatives:         {metrics['false_negatives']}")
        
        print("\n[PERFORMANCE METRICS]")
        print(f"  Accuracy:                {metrics['accuracy']:.2%}")
        print(f"  Precision:               {metrics['precision']:.2%}")
        print(f"  Recall (TP Rate):        {metrics['recall']:.2%}")
        print(f"  F1 Score:                {metrics['f1']:.3f}")
        print(f"  False-Positive Rate:     {metrics['false_positive_rate']:.2%}")
        print(f"  False-Negative Rate:     {metrics['false_negative_rate']:.2%}")
        
        print("\n[CONFIDENCE CALIBRATION]")
        print(f"  High-confidence correct: {metrics['high_confidence_correct']}")
        print(f"  High-confidence wrong:   {metrics['high_confidence_wrong']}")
        
        # Audit trail: print all FP and FN
        print("\n[FALSE POSITIVES (Benign flagged as malware)]")
        fps = [m for m in self.metrics if m.is_false_positive]
        if not fps:
            print("  None ✓")
        else:
            for m in fps:
                print(f"  • {m.sample.name}")
                print(f"    Predicted: {m.result.severity.value} severity, score={m.result.risk_score}")
                print(f"    Ground truth: {m.ground_truth_label}")
                print(f"    Details: {m.result.primary_threat} (C2={m.result.c2_count}, chains={m.result.threat_chain_count})")
                if m.audit_notes:
                    for note in m.audit_notes:
                        print(f"    → {note}")
        
        print("\n[FALSE NEGATIVES (Malware flagged as benign)]")
        fns = [m for m in self.metrics if m.is_false_negative]
        if not fns:
            print("  None ✓")
        else:
            for m in fns:
                print(f"  • {m.sample.name}")
                print(f"    Predicted: {m.result.severity.value} severity, score={m.result.risk_score}")
                print(f"    Ground truth: {m.ground_truth_label} ({m.sample.family})")
                print(f"    Details: {m.result.primary_threat} (C2={m.result.c2_count}, chains={m.result.threat_chain_count})")
                if m.audit_notes:
                    for note in m.audit_notes:
                        print(f"    → {note}")
        
        print("\n" + "="*70)
    
    def export_csv(self, filepath: str) -> None:
        """Export detailed results to CSV."""
        with open(filepath, 'w', newline='') as f:
            writer = csv.DictWriter(f, fieldnames=[
                'sample_name', 'sha256', 'ground_truth', 'predicted',
                'correct', 'risk_score', 'confidence', 'c2_count',
                'threat_chain_count', 'obfuscation_score'
            ])
            writer.writeheader()
            for m in self.metrics:
                writer.writerow({
                    'sample_name': m.sample.name,
                    'sha256': m.sample.sha256,
                    'ground_truth': m.ground_truth_label,
                    'predicted': m.predicted_label,
                    'correct': m.ground_truth_label == m.predicted_label,
                    'risk_score': m.result.risk_score,
                    'confidence': m.result.confidence,
                    'c2_count': m.result.c2_count,
                    'threat_chain_count': m.result.threat_chain_count,
                    'obfuscation_score': m.result.obfuscation_score,
                })
        print(f"[+] Exported results to {filepath}")


def main():
    import argparse
    
    parser = argparse.ArgumentParser(description="Validate DroidForensix against ground truth")
    parser.add_argument('--ground-truth', required=True, help='JSON file with labeled samples')
    parser.add_argument('--results', required=True, help='JSON/CSV with pipeline output')
    parser.add_argument('--threshold', type=float, default=0.5, help='Risk threshold for malware classification (0-1)')
    parser.add_argument('--export-csv', help='Export detailed metrics to CSV')
    
    args = parser.parse_args()
    
    harness = ValidationHarness(verbose=True)
    harness.load_ground_truth(args.ground_truth)
    harness.load_pipeline_results(args.results)
    harness.validate(threshold=args.threshold)
    harness.print_report()
    
    if args.export_csv:
        harness.export_csv(args.export_csv)


if __name__ == '__main__':
    main()
