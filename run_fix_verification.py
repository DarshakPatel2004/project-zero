"""Run the fixed pipeline on the two output.txt samples and print a summary."""
import json
from pathlib import Path

from analysis.pipeline import run_pipeline

SAMPLES = [
    ("Metasploit stager", "samples/malware/github/android-malware/1722087714.apk"),
    ("jRPN calculator", "samples/legitimate/fdroid/com.jovial.jrpn.apk"),
]

for label, apk_path in SAMPLES:
    path = Path(apk_path)
    if not path.exists():
        print(f"[!] Missing: {apk_path}")
        continue

    print(f"\n{'='*60}")
    print(f"Running: {label} ({apk_path})")
    print(f"{'='*60}")

    result = run_pipeline(str(path))

    meta = result.get("metadata", {})
    llm = result.get("llm_assessment", {})
    obf = result.get("obfuscation_analysis", {})
    c2s = result.get("c2_infrastructure", [])
    chains = result.get("threat_chains", [])

    print(f"Package : {meta.get('package_name')}")
    print(f"Size    : {meta.get('file_size_bytes', 0):,} bytes")
    print(f"Classes : {result.get('extraction', {}).get('decompiled_classes')}")
    print(f"Strings : {result.get('extraction', {}).get('total_strings_extracted')}")
    print(f"Encodings: {len(result.get('encodings', []))}")
    print(f"Payloads : {len(result.get('payloads', []))}")
    print(f"C2 found : {len(c2s)}")
    print(f"Chains   : {len(chains)}")
    print(f"Obfuscation: {obf.get('obfuscation_level')} ({obf.get('obfuscation_score')})")
    print(f"---> FINAL: severity={llm.get('severity')}, risk_score={llm.get('risk_score')}, "
          f"primary={llm.get('primary_threat')}, confidence={llm.get('confidence')}")
    print(f"Narrative: {llm.get('narrative', '')[:200]}...")

    for note in result.get("post_process_notes", []):
        print(f"[POST-PROCESS] {note}")
