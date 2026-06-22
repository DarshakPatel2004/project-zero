"""
Reprocess Step 7-9 for all ground-truth samples using the latest fixed code.

This script:
1. Locates each sample's work directory by SHA256 or sample name.
2. If pipeline_result.json is corrupt, reconstructs it from intermediate step files.
3. Re-runs Step 8 (obfuscation analysis) with the current benign-library filter.
4. Re-runs Step 7 (LLM/fallback assessment) using fallback directly (Ollama not available).
5. Re-runs Step 9 (post-processing corrections).
6. Saves updated pipeline_result.json and a validation status file.
"""

import json
from pathlib import Path
import concurrent.futures
import time
import sys

# Ensure project root is importable
sys.path.insert(0, str(Path(__file__).parent))

from analysis.step8_obfuscation_analysis import analyze_obfuscation
from analysis.step7_llm_assessment import fallback_assessment
from analysis.step9_post_process import post_process_result


def load_json_safe(path: Path):
    try:
        with open(path, "r", encoding="utf-8") as f:
            return json.load(f)
    except (json.JSONDecodeError, FileNotFoundError):
        return None


def find_result_path(sample: dict) -> Path | None:
    """Locate the pipeline_result.json path for a ground-truth sample."""
    sha = sample.get("sha256")
    if sha:
        candidate = Path("analysis/work") / sha / "pipeline_result.json"
        if candidate.exists():
            return candidate

    apk_name = Path(sample["apk_path"]).name
    for d in Path("analysis/work").iterdir():
        if not d.is_dir():
            continue
        result_path = d / "pipeline_result.json"
        if not result_path.exists():
            continue
        data = load_json_safe(result_path)
        if data and data.get("metadata", {}).get("sample_name") == apk_name:
            return result_path
    return None


def reconstruct_pipeline_result(work_dir: Path, sample: dict) -> dict | None:
    """Rebuild a pipeline_result.json from intermediate step files."""
    step1 = load_json_safe(work_dir / "step1_extraction.json")
    step5 = load_json_safe(work_dir / "step5_c2s.json")
    step6 = load_json_safe(work_dir / "step6_chains.json")
    step8 = load_json_safe(work_dir / "step8_obfuscation.json")

    if not (step1 and step5 and step6):
        return None

    sample_id = work_dir.name
    return {
        "sample_id": sample_id,
        "metadata": step1.get("metadata", {}),
        "c2_infrastructure": step5.get("c2_infrastructure", []),
        "threat_chains": step6.get("threat_chains", []),
        "obfuscation_analysis": step8 or {},
        "llm_assessment": {},
    }


def reprocess_sample(sample: dict) -> dict:
    apk_path = sample["apk_path"]
    name = sample["name"]

    result_path = find_result_path(sample)
    if not result_path:
        return {"sample": name, "status": "result_not_found"}

    work_dir = result_path.parent

    # Load existing result, reconstructing if the JSON is corrupt
    result = load_json_safe(result_path)
    if result is None:
        result = reconstruct_pipeline_result(work_dir, sample)
        if result is None:
            return {"sample": name, "status": "reconstruct_failed"}

    try:
        sample_id = result.get("sample_id") or work_dir.name

        # Re-run Step 8 with current code. analyze_obfuscation writes to
        # settings.WORK_DIR / sample_id, which matches our SHA-named work dirs.
        obfuscation_result = analyze_obfuscation(apk_path, sample_id=sample_id)
        result["obfuscation_analysis"] = obfuscation_result

        # Step 7: use fallback directly to avoid Ollama timeout
        chains_result = {
            "sample_id": sample_id,
            "total_chains": len(result.get("threat_chains", [])),
            "threat_chains": result.get("threat_chains", []),
        }
        c2_result = {
            "sample_id": sample_id,
            "total_c2s": len(result.get("c2_infrastructure", [])),
            "c2_infrastructure": result.get("c2_infrastructure", []),
        }
        llm_assessment = fallback_assessment(chains_result, c2_result, obfuscation_result)
        result["llm_assessment"] = llm_assessment

        # Re-run Step 9
        result = post_process_result(result)

        with open(result_path, "w", encoding="utf-8") as f:
            json.dump(result, f, indent=2, default=str)

        return {
            "sample": name,
            "status": "success",
            "risk_score": result["llm_assessment"]["risk_score"],
            "severity": result["llm_assessment"]["severity"],
            "work_dir": work_dir.name,
        }
    except Exception as e:
        import traceback
        return {
            "sample": name,
            "status": "error",
            "error": str(e),
            "traceback": traceback.format_exc(),
        }


def main():
    with open("ground_truth_test_set.json", "r", encoding="utf-8") as f:
        samples = json.load(f)

    print(f"Reprocessing {len(samples)} ground-truth samples...")
    start = time.time()
    results = []

    # Use a single worker for Step 8 because androguard/dex parsing is CPU-bound
    # and concurrent execution can be slower on resource-constrained machines.
    for i, sample in enumerate(samples, 1):
        res = reprocess_sample(sample)
        results.append(res)
        if i % 10 == 0 or i == len(samples):
            print(f"[{i}/{len(samples)}] done, elapsed {time.time() - start:.0f}s")

    success = sum(1 for r in results if r["status"] == "success")
    print(f"\nReprocessed: {success}/{len(samples)}")
    print(f"Total time: {time.time() - start:.0f}s")

    with open("reprocess_status.json", "w", encoding="utf-8") as f:
        json.dump(results, f, indent=2)


if __name__ == "__main__":
    main()
