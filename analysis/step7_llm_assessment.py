"""
Step 7: LLM-Powered Assessment

Sends threat chains to a local Ollama LLM for severity assessment.
Validates JSON output, retries on failure, and provides rule-based fallback.
"""

import json
import os
import re
import time
from pathlib import Path
from typing import Dict, Any, Optional, List

import ollama


class LLMAssessmentError(Exception):
    """Raised when LLM assessment fails."""
    pass


DEFAULT_FALLBACK = {
    "severity": "low",
    "risk_score": 25,
    "narrative": "LLM assessment unavailable. Fallback assessment based on indicator count.",
    "primary_threat": "other",
    "recommended_actions": ["Review extracted indicators manually", "Re-run analysis when LLM is available"],
    "confidence": 0.5,
}


SYSTEM_PROMPT = """You are an expert malware threat analyst. Assess the severity of the Android malware sample based on the provided threat chains.

Output must be valid JSON only, with no markdown, no explanation, and no code blocks. Use this exact schema:

{
  "severity": "critical|high|medium|low",
  "risk_score": 0-100 integer,
  "narrative": "concise explanation of the threat",
  "primary_threat": "c2_exfiltration|ransomware|spyware|banking_trojan|other",
  "recommended_actions": ["action1", "action2", "action3"],
  "confidence": 0.0-1.0
}

Rules:
- Severity critical: active public C2 with exfiltration, banking trojan behavior, or ransomware indicators.
- Severity high: multiple encodings leading to C2, spyware behavior, or suspicious network infrastructure.
- Severity medium: encoding/obfuscation present but no clear active C2.
- Severity low: few or no malicious indicators.
- Risk score must align with severity: critical 80-100, high 60-79, medium 30-59, low 0-29.
- Do not include actual malicious URLs or payloads in the narrative; describe them indirectly.
"""


def format_threat_context(chains_result: dict, c2_result: dict) -> str:
    """Format threat chains and C2 summary for LLM consumption."""
    lines = []
    lines.append(f"Total threat chains: {chains_result.get('total_chains', 0)}")
    lines.append(f"Total C2 indicators: {c2_result.get('total_c2s', 0)}")
    lines.append("")

    for chain in chains_result.get("threat_chains", [])[:10]:  # Limit to 10 chains
        lines.append(f"Chain {chain.get('chain_id')}: severity={chain.get('severity')}, confidence={chain.get('confidence')}")
        for step in chain.get("steps", []):
            artifact = str(step.get("artifact", ""))[:80]
            lines.append(f"  Step {step.get('step')}: {step.get('type')} -> {artifact}")
        lines.append("")

    lines.append("C2 Infrastructure Summary:")
    for c2 in c2_result.get("c2_infrastructure", [])[:10]:
        domain = c2.get("domain") or c2.get("ip") or "unknown"
        lines.append(f"  - {c2.get('protocol', 'unknown')}://{domain}:{c2.get('port', 'unknown')}{c2.get('path', '/')} "
                     f"(classification={c2.get('ip_classification', 'n/a')}, type={c2.get('communication_type', 'other')})")

    return "\n".join(lines)


def parse_llm_json(raw_output: str) -> Optional[Dict[str, Any]]:
    """Extract and parse JSON from LLM output."""
    # Try to find JSON block
    raw_output = raw_output.strip()

    # Remove markdown code blocks if present
    if raw_output.startswith("```"):
        lines = raw_output.splitlines()
        if lines[0].startswith("```"):
            lines = lines[1:]
        if lines and lines[-1].startswith("```"):
            lines = lines[:-1]
        raw_output = "\n".join(lines).strip()

    # Try parsing the whole thing
    try:
        return json.loads(raw_output)
    except json.JSONDecodeError:
        pass

    # Try to extract JSON object with regex
    match = re.search(r'\{.*\}', raw_output, re.DOTALL)
    if match:
        try:
            return json.loads(match.group(0))
        except json.JSONDecodeError:
            pass

    return None


def validate_assessment(assessment: dict) -> bool:
    """Validate LLM assessment schema."""
    required = ["severity", "risk_score", "narrative", "recommended_actions"]
    if not all(k in assessment for k in required):
        return False
    if assessment.get("severity") not in ("critical", "high", "medium", "low"):
        return False
    risk_score = assessment.get("risk_score")
    if not isinstance(risk_score, int) or not (0 <= risk_score <= 100):
        return False
    if not isinstance(assessment.get("recommended_actions"), list):
        return False
    return True


def sanity_check(assessment: dict, chains_result: dict, c2_result: dict) -> dict:
    """Cross-reference LLM severity against detected indicators."""
    c2_count = c2_result.get("total_c2s", 0)
    chain_count = chains_result.get("total_chains", 0)
    severity = assessment.get("severity", "low")
    risk_score = assessment.get("risk_score", 0)

    # If active C2 exists but severity is low, raise it
    if c2_count > 0 and severity == "low":
        assessment["severity"] = "medium"
        assessment["risk_score"] = max(risk_score, 35)
        assessment["narrative"] += " [SANITY CHECK: elevated due to detected C2 infrastructure.]"

    # If no C2 and severity is critical, lower it
    if c2_count == 0 and severity == "critical":
        assessment["severity"] = "medium"
        assessment["risk_score"] = min(risk_score, 55)
        assessment["narrative"] += " [SANITY CHECK: lowered due to absence of confirmed C2.]"

    return assessment


def fallback_assessment(chains_result: dict, c2_result: dict) -> dict:
    """Rule-based fallback assessment when LLM fails."""
    c2_count = c2_result.get("total_c2s", 0)
    chain_count = chains_result.get("total_chains", 0)

    if c2_count > 0:
        severity = "high"
        risk_score = 75
        narrative = f"Detected {c2_count} C2 indicator(s) across {chain_count} threat chain(s). Active infrastructure present."
        primary_threat = "c2_exfiltration"
        actions = ["Block identified C2 domains/IPs", "Analyze network traffic for exfiltration"]
    elif chain_count > 0:
        severity = "medium"
        risk_score = 45
        narrative = f"Detected {chain_count} threat chain(s) but no confirmed active C2. Obfuscation/encoding present."
        primary_threat = "other"
        actions = ["Review decoded artifacts", "Investigate encoding functions"]
    else:
        severity = "low"
        risk_score = 15
        narrative = "No significant malicious indicators detected."
        primary_threat = "other"
        actions = ["Perform manual review", "Collect additional samples"]

    return {
        "severity": severity,
        "risk_score": risk_score,
        "narrative": narrative,
        "primary_threat": primary_threat,
        "recommended_actions": actions,
        "confidence": 0.6,
        "raw_llm_output": "",
    }


def assess_with_llm(chains_result: dict, c2_result: dict) -> dict:
    """
    Full Step 7: Get LLM assessment of threat chains.

    Args:
        chains_result: Output dict from Step 6.
        c2_result: Output dict from Step 5.

    Returns:
        dict with LLM assessment.
    """
    sample_id = chains_result["sample_id"]
    work_dir = Path("analysis/work") / sample_id
    work_dir.mkdir(parents=True, exist_ok=True)

    ollama_host = os.environ.get("OLLAMA_HOST", "http://localhost:11434")
    model = os.environ.get("OLLAMA_MODEL", "llama3.2:3b")

    context = format_threat_context(chains_result, c2_result)
    prompt = f"{SYSTEM_PROMPT}\n\nTHREAT CHAINS:\n{context}\n\nASSESSMENT:"

    assessment = None
    raw_output = ""
    max_retries = 3

    for attempt in range(max_retries):
        try:
            client = ollama.Client(host=ollama_host)
            response = client.generate(
                model=model,
                prompt=prompt,
                format="json",
                options={"num_ctx": 4096, "temperature": 0.1},
            )
            raw_output = response.get("response", "")
            parsed = parse_llm_json(raw_output)
            if parsed and validate_assessment(parsed):
                assessment = sanity_check(parsed, chains_result, c2_result)
                break
            else:
                # Retry with stricter prompt
                prompt = f"{SYSTEM_PROMPT}\n\nYour previous response was invalid. Output ONLY valid JSON.\n\nTHREAT CHAINS:\n{context}\n\nASSESSMENT:"
                time.sleep(1)
        except Exception as e:
            raw_output = str(e)
            time.sleep(2)

    if assessment is None:
        assessment = fallback_assessment(chains_result, c2_result)

    assessment["raw_llm_output"] = raw_output[:2000]

    # Save intermediate result
    result_path = work_dir / "step7_assessment.json"
    with open(result_path, "w", encoding="utf-8") as f:
        json.dump(assessment, f, indent=2)

    return assessment


if __name__ == "__main__":
    import sys
    if len(sys.argv) < 3:
        print("Usage: python step7_llm_assessment.py <step6_chains.json> <step5_c2s.json>")
        sys.exit(1)
    with open(sys.argv[1], "r", encoding="utf-8") as f:
        chains = json.load(f)
    with open(sys.argv[2], "r", encoding="utf-8") as f:
        c2s = json.load(f)
    print(json.dumps(assess_with_llm(chains, c2s), indent=2))
