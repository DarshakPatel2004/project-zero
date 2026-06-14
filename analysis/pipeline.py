"""
DroidForensix Analysis Pipeline Orchestrator

Coordinates the 8-step analysis pipeline:
1. APK Extraction
2. String Enumeration
3. Encoding Detection
4. Payload Decoding
5. C2 Extraction
6. Threat Chain Correlation
7. LLM Assessment
8. Obfuscation Analysis

Emits events at key milestones for backend WebSocket broadcasting.
"""

import json
import time
from pathlib import Path
from typing import Callable, Optional

from analysis.step1_apk_extraction import extract_apk
from analysis.step2_string_enumeration import enumerate_strings
from analysis.step3_encoding_detection import detect_encoding
from analysis.step4_decoding import decode_payloads
from analysis.step5_c2_extraction import extract_c2_infrastructure
from analysis.step6_correlation import build_threat_chains
from analysis.step7_llm_assessment import assess_with_llm
from analysis.step8_obfuscation_analysis import analyze_obfuscation
from backend.dissection import APKDissector


class PipelineError(Exception):
    """Raised when pipeline execution fails."""
    pass


# Event emitter callback type: function(event_type, data) -> None
EventEmitter = Optional[Callable[[str, dict], None]]


def _emit(emitter: EventEmitter, event_type: str, data: dict):
    """Emit an event if emitter is provided."""
    if emitter:
        try:
            emitter(event_type, data)
        except Exception:
            pass


def run_pipeline(apk_path: str, work_dir: str = "analysis/work",
                 event_emitter: EventEmitter = None) -> dict:
    """
    Run the full analysis pipeline on an APK.

    Args:
        apk_path: Path to APK file.
        work_dir: Working directory for intermediate outputs.
        event_emitter: Optional callback for emitting events.

    Returns:
        dict with full analysis results.
    """
    start_time = time.time()
    timeline = {}

    # Step 1: APK Extraction
    step_start = time.time()
    try:
        extraction = extract_apk(apk_path, work_dir)
    except Exception as e:
        raise PipelineError(f"Step 1 failed: {e}")
    timeline["step1"] = round(time.time() - step_start, 2)

    sample_id = extraction["sample_id"]
    _emit(event_emitter, "analysis_started", {
        "sample_id": sample_id,
        "sample_name": extraction["sample_name"],
        "total_steps": 8,
    })
    _emit(event_emitter, "extraction_complete", {
        "sample_id": sample_id,
        "apktool_success": extraction["apktool_success"],
        "jadx_success": extraction["jadx_success"],
        "native_libs_found": extraction["native_libs_found"],
    })

    # Step 2: String Enumeration
    step_start = time.time()
    try:
        strings_result = enumerate_strings(extraction)
    except Exception as e:
        raise PipelineError(f"Step 2 failed: {e}")
    timeline["step2"] = round(time.time() - step_start, 2)
    _emit(event_emitter, "strings_enumerated", {
        "sample_id": sample_id,
        "total_strings": strings_result["total_strings"],
    })

    # Step 3: Encoding Detection
    step_start = time.time()
    try:
        encodings_result = detect_encoding(strings_result)
    except Exception as e:
        raise PipelineError(f"Step 3 failed: {e}")
    timeline["step3"] = round(time.time() - step_start, 2)
    for enc in encodings_result.get("encodings", []):
        _emit(event_emitter, "encoding_detected", {
            "sample_id": sample_id,
            "encoding_id": enc["encoding_id"],
            "type": enc["type"],
            "original_string": enc["original_string"][:100],
            "confidence": enc["confidence"],
            "entropy": enc["entropy"],
            "source_location": enc["source_location"],
            "decoded_preview": enc["decoded_preview"][:100],
        })

    # Step 4: Payload Decoding
    step_start = time.time()
    try:
        payloads_result = decode_payloads(encodings_result)
    except Exception as e:
        raise PipelineError(f"Step 4 failed: {e}")
    timeline["step4"] = round(time.time() - step_start, 2)
    for pld in payloads_result.get("payloads", []):
        _emit(event_emitter, "payload_decoded", {
            "sample_id": sample_id,
            "payload_id": pld["payload_id"],
            "encoding_id": pld["encoding_id"],
            "decoded_content": pld["decoded_content"][:200],
            "artifacts": pld["artifacts"],
            "source_location": pld["source_location"],
        })

    # Step 5: C2 Extraction
    step_start = time.time()
    try:
        c2_result = extract_c2_infrastructure(payloads_result, strings_result)
    except Exception as e:
        raise PipelineError(f"Step 5 failed: {e}")
    timeline["step5"] = round(time.time() - step_start, 2)
    for c2 in c2_result.get("c2_infrastructure", []):
        _emit(event_emitter, "c2_extracted", {
            "sample_id": sample_id,
            "c2_id": c2["c2_id"],
            "payload_id": c2["payload_id"],
            "raw_url": c2["raw_url"],
            "protocol": c2["protocol"],
            "domain": c2["domain"],
            "ip": c2["ip"],
            "port": c2["port"],
            "ip_classification": c2["ip_classification"],
            "communication_type": c2["communication_type"],
            "confidence": c2["confidence"],
        })

    # Step 6: Threat Chain Correlation
    step_start = time.time()
    try:
        chains_result = build_threat_chains(encodings_result, payloads_result, c2_result)
    except Exception as e:
        raise PipelineError(f"Step 6 failed: {e}")
    timeline["step6"] = round(time.time() - step_start, 2)
    for chain in chains_result.get("threat_chains", []):
        _emit(event_emitter, "threat_chain_created", {
            "sample_id": sample_id,
            "chain_id": chain["chain_id"],
            "severity": chain["severity"],
            "confidence": chain["confidence"],
            "steps": chain["steps"],
        })

    # Step 8: Obfuscation Analysis (run before LLM so the verdict can use it)
    step_start = time.time()
    try:
        obfuscation_result = analyze_obfuscation(apk_path, work_dir, sample_id=sample_id)
    except Exception as e:
        obfuscation_result = {
            "sample_id": sample_id,
            "obfuscation_score": 0.0,
            "obfuscation_level": "low",
            "indicators": {},
            "dex_entropy": [],
            "native_library_artifacts": [],
            "notes": [f"Obfuscation analysis failed: {e}"],
        }
    timeline["step8"] = round(time.time() - step_start, 2)

    # Step 7: LLM Assessment
    step_start = time.time()
    try:
        llm_assessment = assess_with_llm(chains_result, c2_result, obfuscation_result)
    except Exception as e:
        llm_assessment = {
            "severity": "low",
            "risk_score": 0,
            "narrative": f"LLM assessment failed: {e}",
            "primary_threat": "other",
            "recommended_actions": ["Check Ollama connection", "Retry analysis"],
            "confidence": 0.0,
        }
    timeline["step7"] = round(time.time() - step_start, 2)

    duration = round(time.time() - start_time, 2)
    timeline["total"] = duration

    # Save structural APK dissection (fast, cached for dashboard)
    try:
        dissector = APKDissector(apk_path, work_dir=work_dir)
        dissection_data = dissector.dissect()
        dissection_path = Path(work_dir) / sample_id / "dissection.json"
        with open(dissection_path, "w", encoding="utf-8") as f:
            json.dump(dissection_data, f, indent=2, default=str)
    except Exception as e:
        # Dissection should never fail the full pipeline
        _emit(event_emitter, "error", {
            "sample_id": sample_id,
            "message": f"Dissection save failed: {e}",
        })

    result = {
        "sample_id": sample_id,
        "metadata": {
            "sample_name": extraction["sample_name"],
            "file_size_bytes": extraction["file_size_bytes"],
            "sha256": extraction["sha256"],
            "md5": extraction["md5"],
            "package_name": extraction["package_name"],
        },
        "extraction": {
            "apktool_success": extraction["apktool_success"],
            "jadx_success": extraction["jadx_success"],
            "native_libs_found": extraction["native_libs_found"],
            "decompiled_classes": extraction["decompiled_classes"],
            "total_strings_extracted": strings_result["total_strings"],
        },
        "strings": strings_result["categories"],
        "encodings": encodings_result["encodings"],
        "payloads": payloads_result["payloads"],
        "c2_infrastructure": c2_result["c2_infrastructure"],
        "threat_chains": chains_result["threat_chains"],
        "llm_assessment": llm_assessment,
        "obfuscation_analysis": obfuscation_result,
        "timeline": timeline,
    }

    # Save full result
    result_path = Path(work_dir) / sample_id / "pipeline_result.json"
    result_path.parent.mkdir(parents=True, exist_ok=True)
    with open(result_path, "w", encoding="utf-8") as f:
        json.dump(result, f, indent=2, default=str)

    _emit(event_emitter, "analysis_complete", {
        "sample_id": sample_id,
        "total_encodings": len(encodings_result["encodings"]),
        "total_payloads": len(payloads_result["payloads"]),
        "total_c2s": len(c2_result["c2_infrastructure"]),
        "total_chains": len(chains_result["threat_chains"]),
        "duration_seconds": duration,
        "report_path": str(result_path),
    })

    return result


if __name__ == "__main__":
    import sys
    if len(sys.argv) < 2:
        print("Usage: python pipeline.py <apk_path> [work_dir]")
        sys.exit(1)
    apk = sys.argv[1]
    work = sys.argv[2] if len(sys.argv) > 2 else "analysis/work"

    def print_event(event_type, data):
        print(f"[EVENT] {event_type}: {json.dumps(data, default=str)[:150]}")

    result = run_pipeline(apk, work, event_emitter=print_event)
    print(json.dumps(result, indent=2, default=str))
