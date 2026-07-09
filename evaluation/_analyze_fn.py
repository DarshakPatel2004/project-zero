"""
Deep-dive on 5 Drebin false negatives.
For each: what did the pipeline see vs miss?
"""
import json
from pathlib import Path

WORK_DIR = Path("analysis/work")
TEST_SET_FILE = Path("ground_truth_test_set.json")
DREBIN_HASHES_FILE = Path("evaluation/drebin_hashes.txt")

test_set = {}
for s in json.loads(TEST_SET_FILE.read_text()):
    test_set[s["sha256"]] = s

drebin_hashes = [line.strip() for line in DREBIN_HASHES_FILE.read_text().strip().splitlines() if line.strip()]
by_hash = {}
for d in WORK_DIR.iterdir():
    if not d.is_dir():
        continue
    pr_file = d / "pipeline_result.json"
    if not pr_file.exists():
        continue
    pr = json.loads(pr_file.read_text())
    llm = pr.get("llm_assessment") or {}
    by_hash[d.name] = {
        "sha256": d.name,
        "risk_score": llm.get("risk_score", 0) or 0,
        "severity": llm.get("severity", "unknown"),
        "method": llm.get("method", ""),
        "narrative": llm.get("narrative", ""),
        "primary_threat": llm.get("primary_threat", ""),
        "confidence": llm.get("confidence", ""),
        "metadata": pr.get("metadata", {}),
        "manifest": pr.get("manifest", {}),
        "threat_chains": pr.get("threat_chains", []),
        "obfuscation": pr.get("obfuscation_analysis", {}),
        "c2_info": pr.get("c2_infrastructure", {}),
        "encodings": pr.get("encodings", []),
        "payloads": pr.get("payloads", []),
        "strings": pr.get("strings", {}),
    }

# Find the 5 false negatives
fns = []
for h in drebin_hashes:
    r = by_hash.get(h)
    if r and r["risk_score"] < 50:
        gt = test_set.get(h, {})
        r["ground_truth_family"] = gt.get("family", "?")
        r["package"] = gt.get("package", "?")
        fns.append(r)

print(f"False negatives: {len(fns)}\n")

for r in sorted(fns, key=lambda x: x["ground_truth_family"]):
    h = r["sha256"]
    print("=" * 70)
    print(f"FAMILY: {r['ground_truth_family']}")
    print(f"SHA256: {h}")
    print(f"Package: {r['package']}")
    print(f"Risk: {r['risk_score']}  Severity: {r['severity']}  Method: {r['method']}")
    print(f"Confidence: {r['confidence']}")
    print()

    meta = r["metadata"] or {}
    print("--- Metadata ---")
    print(f"  APK size: {meta.get('file_size', '?')}")
    print(f"  Classes: {meta.get('class_count', '?')}")
    print(f"  Native libs: {meta.get('native_lib_count', '?')}")
    print()

    man = r["manifest"] or {}
    perms = man.get("permissions", [])
    print(f"--- Manifest ---")
    print(f"  Permissions ({len(perms)}): {perms[:15]}...")
    print()

    obf = r["obfuscation"] or {}
    print(f"--- Obfuscation ---")
    print(f"  Obfuscation score: {obf.get('obfuscation_score', '?')}")
    print(f"  Reflection count: {obf.get('reflection_api_count', '?')}")
    print(f"  Dynamic loading: {obf.get('dynamic_loading_api_count', '?')}")
    print(f"  Crypto API count: {obf.get('crypto_api_count', '?')}")
    print(f"  Suspicious API count: {obf.get('suspicious_api_count', '?')}")
    print()

    tc = r["threat_chains"] or []
    print(f"--- Threat Chains ({len(tc)}) ---")
    for t in tc[:5]:
        print(f"  {t.get('category','?')}: {t.get('description','?')[:120]}")
    print()

    c2 = r["c2_info"] or {}
    c2_domains = c2.get("domains", []) or []
    print(f"--- C2 Domains ({len(c2_domains)}) ---")
    for d in c2_domains[:5]:
        print(f"  {d}")
    encs = r["encodings"] or []
    print(f"--- Encodings ({len(encs)}) ---")
    for e in encs[:5]:
        print(f"  Type: {e.get('type','?')}  Data: {str(e.get('data','?'))[:80]}")
    pls = r["payloads"] or []
    print(f"--- Payloads ({len(pls)}) ---")
    for p in pls[:5]:
        print(f"  Type: {p.get('type','?')}  Technique: {p.get('technique','?')}")
    print()

    print(f"--- Narrative ---")
    print(f"  {r['narrative'][:300]}" if r['narrative'] else "  (none)")
    print(f"--- Primary Threat ---")
    print(f"  {r['primary_threat']}" if r['primary_threat'] else "  (none)")
    print()

print("=" * 70)

# Summary
print("\n\n=== SUMMARY TABLE ===")
print(f"{'Family':<15} {'Risk':>5} {'Method':<12} {'Obfuscation':<12} {'Reflection':<10} {'C2':<5} {'Permissions':<10}")
print("-" * 75)
for r in sorted(fns, key=lambda x: x["ground_truth_family"]):
    obf = r["obfuscation"] or {}
    c2 = r["c2_info"] or {}
    c2_domains = c2.get("domains", []) or []
    man = r["manifest"] or {}
    perms = man.get("permissions", [])
    print(f"{r['ground_truth_family']:<15} {r['risk_score']:>5} {r['method']:<12} {obf.get('obfuscation_score','?'):<12} {obf.get('reflection_api_count','?'):<10} {len(c2_domains):<5} {len(perms):<10}")
