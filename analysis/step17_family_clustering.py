"""
Step 17: Method Signature Similarity Index.

Hashes method signatures using SHA-256, builds a fingerprint-based
similarity index using Jaccard similarity over expanded hash sets,
compares against known-family database of previously analyzed samples.
Visualizable as a force-directed graph.

This is a method signature similarity index (SHA-256 fingerprinting +
Jaccard over expanded hash sets), NOT a MinHash-based clustering.
The Jaccard metric over expanded hashes is influenced by method count —
large samples have more set elements and may read as less similar to
smaller ones. This is a known property of the approach.
"""

import hashlib
import logging
import re
from pathlib import Path
from typing import Dict, List, Any, Optional, Set, Tuple

from backend.config import settings
from analysis.cross_sample_index import load_index, add_to_index

logger = logging.getLogger(__name__)


def hash_method_signature(full_signature: str) -> str:
    return hashlib.sha256(full_signature.encode("utf-8")).hexdigest()


def extract_methods_from_source(extracted_path: str) -> List[Dict[str, Any]]:
    methods = []
    base = Path(extracted_path)
    source_dirs = [d for d in [base / "sources", base / "smali", base / "jadx_output"] if d.is_dir()]

    method_pattern = re.compile(r'\.method\s+(?:public|private|protected|static|final)?\s*(.+?)$', re.MULTILINE)
    class_pattern = re.compile(r'\.class\s+(?:public|private|protected|static|final)?\s*(.+?)$', re.MULTILINE)

    for src_dir in source_dirs:
        for fpath in src_dir.rglob("*.smali"):
            try:
                text = fpath.read_text("utf-8", errors="ignore")
                current_class = ""
                for match in class_pattern.finditer(text):
                    current_class = match.group(1).strip()
                for match in method_pattern.finditer(text):
                    sig = match.group(1).strip()
                    if sig and len(sig) > 3:
                        methods.append({
                            "class": current_class or str(fpath.stem),
                            "method": sig.split("(")[0] if "(" in sig else sig.split()[0] if sig.split() else sig,
                            "descriptor": sig,
                        })
            except Exception:
                continue

    return methods


def build_sample_signature(methods: List[Dict[str, Any]]) -> Dict[str, Any]:
    if not methods:
        return {"method_signatures": [], "expanded_signature_hashes": [], "total_methods": 0}

    signatures = []
    for m in methods:
        full = f"{m.get('class', '')}->{m.get('method', '')}{m.get('descriptor', '')}"
        signatures.append(hash_method_signature(full))

    expanded_hashes = []
    for i, sig in enumerate(signatures[:100]):
        for seed in range(5):
            h = hashlib.sha256(f"{sig}:{seed}".encode()).hexdigest()
            expanded_hashes.append(h)

    return {
        "method_signatures": signatures,
        "expanded_signature_hashes": list(set(expanded_hashes)),
        "total_methods": len(methods),
    }


def jaccard_similarity(a: Set, b: Set) -> float:
    """
    Computes Jaccard similarity over two sets.

    NOTE: When applied to expanded_signature_hashes, the metric is
    influenced by method count — larger samples produce more set
    elements and may read as systematically less similar to smaller
    ones. This is a known property of the fingerprinting approach,
    not a defect.
    """
    if not a or not b:
        return 0.0
    return len(a & b) / len(a | b)


def match_against_index(
    query_signature: Dict[str, Any],
    index: Dict[str, Any],
    threshold: float = 0.3,
) -> Dict[str, Any]:
    query_hashes = set(query_signature.get("expanded_signature_hashes", []))
    if not query_hashes:
        return {"matches": [], "best_match": None}

    matches = []
    for sample_id, entry in index.get("samples", {}).items():
        sample_hashes = set(entry.get("expanded_signature_hashes", []))
        if not sample_hashes:
            continue
        similarity = jaccard_similarity(query_hashes, sample_hashes)
        if similarity >= threshold:
            matches.append({
                "sample_id": sample_id,
                "family": entry.get("family", "unknown"),
                "similarity": round(similarity, 4),
                "method_count": entry.get("signature_count", 0),
            })

    matches.sort(key=lambda m: -m["similarity"])
    best = matches[0] if matches else None

    return {"matches": matches, "best_match": best}


def cluster_family(
    sample_id: str,
    apk_info: Dict[str, Any],
    result: Dict[str, Any],
) -> Dict[str, Any]:
    extracted_path = apk_info.get("extracted_path") or apk_info.get("work_dir", "")
    if not extracted_path:
        return {"matches": [], "best_match": None, "total_matches": 0}

    methods = extract_methods_from_source(extracted_path)
    signature = build_sample_signature(methods)
    index = load_index()
    match_result = match_against_index(signature, index)

    family = result.get("family_identification", {}).get("family", "unknown")
    add_to_index(sample_id, family, signature)

    return {
        "total_methods_extracted": signature["total_methods"],
        "total_signatures": len(signature["method_signatures"]),
        "best_match": match_result["best_match"],
        "matches": match_result["matches"][:20],
        "total_matches": len(match_result["matches"]),
        "index_size": len(index.get("samples", {})),
    }


def get_family_graph_data() -> Dict[str, Any]:
    """
    Build graph data from the cross-sample index.

    # NOTE: O(n^2) pairwise similarity computation over the full index.
    # Needs a cap or incremental-update strategy once the index passes a
    # few thousand samples. Not blocking at current corpus scale.
    """
    index = load_index()
    nodes = []
    edges = []

    samples = index.get("samples", {})
    for sid, entry in samples.items():
        nodes.append({
            "id": sid,
            "family": entry.get("family", "unknown"),
            "method_count": entry.get("signature_count", 0),
        })

    ids = list(samples.keys())
    for i in range(len(ids)):
        for j in range(i + 1, len(ids)):
            a_hashes = set(samples[ids[i]].get("expanded_signature_hashes", []))
            b_hashes = set(samples[ids[j]].get("expanded_signature_hashes", []))
            sim = jaccard_similarity(a_hashes, b_hashes)
            if sim >= 0.3:
                edges.append({
                    "source": ids[i],
                    "target": ids[j],
                    "similarity": round(sim, 4),
                })

    return {"nodes": nodes, "edges": edges, "total_samples": len(nodes)}
