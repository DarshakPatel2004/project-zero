"""
Step 7: LLM-Powered Assessment

Sends threat chains to an LLM (NVIDIA NIM by default) for severity assessment.
Validates JSON output, retries on failure, and provides rule-based fallback.

Environment variables:
    NVIDIA_NIM_API_KEY  - NVIDIA NIM API key (required unless Ollama is used)
    NVIDIA_NIM_MODEL    - Model ID on NVIDIA NIM (default: nvidia/nemotron-nano-9b-v2)
    NVIDIA_NIM_BASE_URL - Endpoint base URL (default: https://integrate.api.nvidia.com/v1)

Fallback to local Ollama is still supported:
    OLLAMA_HOST         - Ollama host (default: http://localhost:11434)
    OLLAMA_MODEL        - Ollama model (default: llama3.2:3b)
"""

import json
import os
import re
import time
import urllib.parse
from pathlib import Path
from typing import Dict, Any, Optional

from backend.config import settings


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


SYSTEM_PROMPT = """/no_think

You are an expert Android malware threat analyst writing a forensic investigation report. Assess the severity of the Android malware sample based on the provided threat chains and static obfuscation/permission indicators.

Output must be valid JSON only, with no markdown, no explanation, and no code blocks. Use this exact schema:

{
  "severity": "critical|high|medium|low",
  "risk_score": 0-100 integer,
  "narrative": "4-6 sentence detailed forensic narrative covering: (1) what the sample appears to do, (2) key technical indicators that support this assessment, (3) what data or capabilities are at risk, (4) confidence level and any caveats",
  "primary_threat": "c2_exfiltration|ransomware|spyware|banking_trojan|adware|dropper|other",
  "threat_indicators": ["specific indicator 1", "specific indicator 2", "specific indicator 3"],
  "recommended_actions": ["action1", "action2", "action3", "action4"],
  "confidence": 0.0-1.0
}

Rules:
- Severity critical: active public C2 with exfiltration, banking trojan behavior, or ransomware indicators.
- Severity high: multiple encodings leading to C2, spyware behavior, suspicious network infrastructure, OR heavy obfuscation with dangerous permissions.
- Severity medium: encoding/obfuscation present but no clear active C2.
- Severity low: few or no malicious indicators.
- Risk score must align with severity: critical 80-100, high 60-79, medium 30-59, low 0-29.
- If decompilation failed (few or no strings/chains) but obfuscation score is medium/high with dangerous permissions, raise severity to at least medium/high accordingly.
- narrative must be specific — name the encoding types, permission categories, and obfuscation techniques observed. Do not write generic descriptions.
- threat_indicators must list concrete technical artifacts (e.g. "Base64-encoded payload in strings", "DexClassLoader present", "READ_SMS permission declared").
- recommended_actions must be actionable and specific to the findings, not generic security advice.
- Do not include actual malicious URLs or payloads in the narrative; describe them indirectly.
"""


def format_threat_context(chains_result: dict, c2_result: dict, obfuscation_result: Optional[dict] = None) -> str:
    """Format threat chains, C2 summary, and obfuscation indicators for LLM consumption."""
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

    if obfuscation_result:
        lines.append("")
        lines.append("Static Obfuscation & Permission Analysis:")
        lines.append(f"  Obfuscation score: {obfuscation_result.get('obfuscation_score', 0)} ({obfuscation_result.get('obfuscation_level', 'unknown')})")
        indicators = obfuscation_result.get("indicators", {})
        lines.append(f"  Classes: {indicators.get('total_classes', 0)}, Methods: {indicators.get('total_methods', 0)}")
        lines.append(f"  Reflection usages: {len(indicators.get('reflection', []))}")
        lines.append(f"  Dynamic loading usages: {len(indicators.get('dynamic_loading', []))}")
        lines.append(f"  Crypto API usages: {len(indicators.get('crypto_apis', []))}")
        lines.append(f"  Suspicious API usages: {len(indicators.get('suspicious_apis', []))}")
        lines.append(f"  Dangerous permissions: {len(indicators.get('dangerous_permissions', []))}")
        for perm in indicators.get("dangerous_permissions", [])[:10]:
            lines.append(f"    - {perm}")
        dex_entropy = obfuscation_result.get("dex_entropy", [])
        if any(d.get("likely_packed") for d in dex_entropy):
            lines.append("  DEX packing detected: likely_packed=True")

    return "\n".join(lines)


def parse_llm_json(raw_output: str) -> Optional[Dict[str, Any]]:
    """Extract and parse JSON from LLM output."""
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


def sanity_check(assessment: dict, chains_result: dict, c2_result: dict, obfuscation_result: Optional[dict] = None) -> dict:
    """Cross-reference LLM severity against detected indicators, including obfuscation/permissions."""
    c2_count = c2_result.get("total_c2s", 0)
    chain_count = chains_result.get("total_chains", 0)
    severity = assessment.get("severity", "low")
    risk_score = assessment.get("risk_score", 0)
    obf_score = (obfuscation_result or {}).get("obfuscation_score", 0)
    indicators = (obfuscation_result or {}).get("indicators", {})
    dangerous_perms = indicators.get("dangerous_permissions", [])

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

    # Obfuscation/permissions anchor: if decompilation failed (empty chains) but obfuscation is significant, raise severity
    if chain_count == 0 and c2_count == 0 and obf_score >= 50:
        if severity == "low":
            assessment["severity"] = "medium"
            assessment["risk_score"] = max(risk_score, 50)
            assessment["narrative"] += f" [SANITY CHECK: elevated due to {obf_score} obfuscation score with {len(dangerous_perms)} dangerous permissions.]"
        elif severity == "medium" and obf_score >= 70:
            assessment["severity"] = "high"
            assessment["risk_score"] = max(risk_score, 65)
            assessment["narrative"] += f" [SANITY CHECK: elevated to high due to heavy obfuscation (score {obf_score}).]"

    return assessment


def fallback_assessment(chains_result: dict, c2_result: dict, obfuscation_result: Optional[dict] = None) -> dict:
    """Rule-based fallback assessment when LLM fails, anchored by obfuscation/permissions when chains are empty."""
    c2_count = c2_result.get("total_c2s", 0)
    chain_count = chains_result.get("total_chains", 0)
    obf_score = (obfuscation_result or {}).get("obfuscation_score", 0)
    obf_level = (obfuscation_result or {}).get("obfuscation_level", "low")
    indicators = (obfuscation_result or {}).get("indicators", {})
    dangerous_perms = indicators.get("dangerous_permissions", [])
    suspicious_apis = indicators.get("suspicious_apis", [])
    reflection = indicators.get("reflection", [])
    dynamic_loading = indicators.get("dynamic_loading", [])

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
    elif obf_score >= 50 or len(dangerous_perms) >= 3:
        # Obfuscation/permissions anchor when decompilation fails or chains are empty
        severity = "high" if obf_score >= 70 else "medium"
        risk_score = min(100, max(50, int(obf_score)))
        narrative = (
            f"No decoded threat chains, but static analysis shows {obf_level} obfuscation "
            f"(score {obf_score}) with {len(dangerous_perms)} dangerous permissions, "
            f"{len(suspicious_apis)} suspicious APIs, {len(reflection)} reflection usages, "
            f"and {len(dynamic_loading)} dynamic loading usages."
        )
        primary_threat = "other"
        actions = ["Perform manual reverse engineering", "Inspect smali/bytecode for hidden behavior"]
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


def _call_nvidia_nim(context: str, model: str, base_url: str, api_key: str, max_retries: int = 3) -> Optional[str]:
    """Call NVIDIA NIM chat completions endpoint and return raw response text."""
    try:
        from openai import OpenAI
    except ImportError as e:
        raise LLMAssessmentError(f"openai package not installed: {e}")

    client = OpenAI(base_url=base_url, api_key=api_key)
    messages = [
        {"role": "system", "content": SYSTEM_PROMPT},
        {"role": "user", "content": f"THREAT CHAINS:\n{context}\n\nASSESSMENT:"},
    ]

    last_error = ""
    for attempt in range(max_retries):
        try:
            response = client.chat.completions.create(
                model=model,
                messages=messages,
                temperature=0.1,
                max_tokens=512,
                response_format={"type": "json_object"},
            )
            return response.choices[0].message.content
        except Exception as e:
            last_error = str(e)
            # NVIDIA NIM free tier: 40 RPM. Back off on 429.
            if "429" in last_error:
                sleep_time = 15 + attempt * 5
                print(f"  [!] Rate limited (429). Sleeping {sleep_time}s...")
                time.sleep(sleep_time)
            else:
                time.sleep(2)

    return last_error


def _normalize_ollama_host(host: str) -> str:
    """Normalize Ollama host so it is reachable on Windows.

    On Windows, connecting to 0.0.0.0 raises [Errno 22] Invalid argument.
    Rewrite 0.0.0.0 to 127.0.0.1 while preserving scheme and port.
    """
    if not host:
        return "http://127.0.0.1:11434"
    parsed = urllib.parse.urlparse(host)
    hostname = parsed.hostname or "127.0.0.1"
    if hostname in ("0.0.0.0", "::"):
        hostname = "127.0.0.1"
    port = parsed.port or 11434
    scheme = parsed.scheme or "http"
    return f"{scheme}://{hostname}:{port}"


def _ollama_available(host: str, timeout: float = 2.0) -> bool:
    """Quick check if Ollama is reachable before attempting a full request."""
    host = _normalize_ollama_host(host)
    parsed = urllib.parse.urlparse(host)
    netloc = parsed.hostname or "127.0.0.1"
    port = parsed.port or 11434
    try:
        import socket
        s = socket.create_connection((netloc, port), timeout=timeout)
        s.close()
        return True
    except (OSError, socket.error):
        return False


def _call_ollama(context: str, host: str, model: str, max_retries: int = 3) -> Optional[str]:
    """Call local Ollama generate endpoint and return raw response text."""
    host = _normalize_ollama_host(host)
    if not _ollama_available(host):
        return "Ollama not running"

    try:
        import ollama
    except ImportError as e:
        raise LLMAssessmentError(f"ollama package not installed: {e}")

    prompt = f"{SYSTEM_PROMPT}\n\nTHREAT CHAINS:\n{context}\n\nASSESSMENT:"
    client = ollama.Client(host=host, timeout=30)

    for attempt in range(max_retries):
        try:
            response = client.generate(
                model=model,
                prompt=prompt,
                format="json",
                options={"num_ctx": 4096, "temperature": 0.1},
            )
            return response.get("response", "")
        except Exception as e:
            if attempt < max_retries - 1:
                time.sleep(2)
            else:
                return str(e)

    return ""


def assess_with_llm(chains_result: dict, c2_result: dict, obfuscation_result: Optional[dict] = None) -> dict:
    """
    Full Step 7: Get LLM assessment of threat chains and obfuscation indicators.

    Prefers NVIDIA NIM if NVIDIA_NIM_API_KEY is set, otherwise falls back to Ollama.
    Any unexpected error returns the rule-based fallback assessment so the pipeline
    keeps running.
    """
    sample_id = chains_result.get("sample_id") or c2_result.get("sample_id") or "unknown"
    work_dir = settings.WORK_DIR / sample_id
    try:
        work_dir.mkdir(parents=True, exist_ok=True)
    except OSError:
        # If the work directory cannot be created, still return a fallback.
        pass

    try:
        context = format_threat_context(chains_result, c2_result, obfuscation_result)
        assessment = None
        raw_output = ""
        max_retries = 3

        # Determine provider: explicit setting overrides auto-detection.
        provider = (os.environ.get("LLM_PROVIDER") or settings.LLM_PROVIDER or "auto").lower()
        nim_api_key = os.environ.get("NVIDIA_NIM_API_KEY")
        use_nvidia = provider == "nvidia" or (provider == "auto" and nim_api_key)

        if use_nvidia:
            # NVIDIA NIM path
            nim_model = os.environ.get("NVIDIA_NIM_MODEL", settings.NIM_MODEL or "nvidia/nemotron-nano-9b-v2")
            nim_base_url = os.environ.get("NVIDIA_NIM_BASE_URL", settings.NIM_HOST or "https://integrate.api.nvidia.com/v1")
            print(f"  [*] Using NVIDIA NIM model: {nim_model}")

            for attempt in range(max_retries):
                raw_output = _call_nvidia_nim(context, nim_model, nim_base_url, nim_api_key, max_retries=1)
                parsed = parse_llm_json(raw_output) if raw_output else None
                if parsed and validate_assessment(parsed):
                    assessment = sanity_check(parsed, chains_result, c2_result, obfuscation_result)
                    break
                else:
                    # Add stricter instruction and retry
                    context = format_threat_context(chains_result, c2_result, obfuscation_result)
                    messages_note = "Your previous response was invalid. Output ONLY valid JSON.\n\n"
                    context = messages_note + context
                    time.sleep(1)
        else:
            # Local Ollama path
            ollama_host = _normalize_ollama_host(os.environ.get("OLLAMA_HOST", settings.OLLAMA_HOST))
            ollama_model = os.environ.get("OLLAMA_MODEL", settings.OLLAMA_MODEL)
            print(f"  [*] Using Ollama model: {ollama_model} at {ollama_host}")

            for attempt in range(max_retries):
                raw_output = _call_ollama(context, ollama_host, ollama_model, max_retries=1)
                parsed = parse_llm_json(raw_output) if raw_output else None
                if parsed and validate_assessment(parsed):
                    assessment = sanity_check(parsed, chains_result, c2_result, obfuscation_result)
                    break
                else:
                    context = format_threat_context(chains_result, c2_result, obfuscation_result)
                    messages_note = "Your previous response was invalid. Output ONLY valid JSON.\n\n"
                    context = messages_note + context
                    time.sleep(1)

        if assessment is None:
            assessment = fallback_assessment(chains_result, c2_result, obfuscation_result)

        assessment["raw_llm_output"] = (raw_output or "")[:2000]

        # Save intermediate result
        try:
            result_path = work_dir / "step7_assessment.json"
            with open(result_path, "w", encoding="utf-8") as f:
                json.dump(assessment, f, indent=2)
        except OSError as e:
            assessment["raw_llm_output"] += f" [save warning: {e}]"

        return assessment
    except Exception as e:
        # Last-resort fallback: never let LLM assessment crash the pipeline.
        assessment = fallback_assessment(chains_result, c2_result, obfuscation_result)
        assessment["raw_llm_output"] = f"LLM assessment error: {e}"[:2000]
        return assessment


METHOD_EXPLAIN_SYSTEM_PROMPT = """/no_think

You are an Android malware analyst reviewing decompiled Java bytecode for a forensic report.
Given a method's name, its class context, any suspicious flags already detected, and its full body,
write a detailed analyst note covering:
- What the method does technically (specific API calls, data flows, control logic)
- Why it is suspicious or benign, with reference to specific lines or patterns in the code
- What an attacker could use this method for, or why it is safe if benign
- Any Android-specific security implications (permission abuse, dynamic code loading, data exfiltration paths)

Be specific. Reference actual method names, class names, or variable patterns you observe in the code.
Do not write generic descriptions — ground every claim in the actual code provided.

Output must be valid JSON only. No markdown, no preamble, no code blocks. Schema:
{
  "summary": "3-5 sentence detailed analyst note grounded in the actual code",
  "threat_type": "reflection|dynamic_loading|crypto|network|command_exec|persistence|permissions|benign|unknown",
  "confidence": 0.0-1.0
}
"""


def explain_method(
    class_name: str,
    method_name: str,
    method_code: str,
    flags: list[str] | None = None,
) -> dict:
    """
    Call the configured LLM (NIM or Ollama) to produce a plain-English
    explanation of a single decompiled method.

    Returns a dict with keys: summary, threat_type, confidence.
    Never raises — returns a fallback dict on any error.
    """
    flags = flags or []
    # Truncate code to keep prompt lean — shorter = faster inference on limited VRAM
    code_snippet = method_code[:1500] if method_code else "(no body)"

    context = (
        f"Class: {class_name}\n"
        f"Method: {method_name}\n"
        f"Detected flags: {', '.join(flags) if flags else 'none'}\n\n"
        f"Method body:\n{code_snippet}"
    )

    fallback = {
        "summary": "LLM explanation unavailable. Review the method body manually.",
        "threat_type": "unknown",
        "confidence": 0.0,
    }

    try:
        provider = (os.environ.get("LLM_PROVIDER") or settings.LLM_PROVIDER or "auto").lower()
        nim_api_key = os.environ.get("NVIDIA_NIM_API_KEY")
        use_nvidia = provider == "nvidia" or (provider == "auto" and nim_api_key)

        raw_output = ""
        if use_nvidia:
            nim_model = os.environ.get("NVIDIA_NIM_MODEL", settings.NIM_MODEL or "nvidia/nemotron-nano-9b-v2")
            nim_base_url = os.environ.get("NVIDIA_NIM_BASE_URL", settings.NIM_HOST or "https://integrate.api.nvidia.com/v1")
            # Temporarily swap system prompt via a wrapper prompt
            combined = f"{METHOD_EXPLAIN_SYSTEM_PROMPT}\n\nMETHOD TO ANALYSE:\n{context}\n\nEXPLANATION:"
            raw_output = _call_nvidia_nim(combined, nim_model, nim_base_url, nim_api_key, max_retries=2) or ""
        else:
            ollama_host = _normalize_ollama_host(os.environ.get("OLLAMA_HOST", settings.OLLAMA_HOST))
            ollama_model = os.environ.get("OLLAMA_MODEL", settings.OLLAMA_MODEL)
            # Build a self-contained prompt since _call_ollama embeds SYSTEM_PROMPT;
            # override by passing everything as the context string with inline instructions.
            combined = f"{METHOD_EXPLAIN_SYSTEM_PROMPT}\n\nMETHOD TO ANALYSE:\n{context}\n\nEXPLANATION:"

            import ollama as _ollama
            client = _ollama.Client(
                host=_normalize_ollama_host(ollama_host),
                timeout=120,
            )
            resp = client.generate(
                model=ollama_model,
                prompt=combined,
                format="json",
                options={"num_ctx": 4096, "temperature": 0.1},
            )
            raw_output = resp.get("response", "")

        parsed = parse_llm_json(raw_output)
        if parsed and "summary" in parsed:
            return {
                "summary": str(parsed.get("summary", ""))[:500],
                "threat_type": str(parsed.get("threat_type", "unknown")),
                "confidence": float(parsed.get("confidence", 0.5)),
            }
        return fallback

    except Exception as e:
        fallback["summary"] = f"Explanation error: {e}"[:300]
        return fallback


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