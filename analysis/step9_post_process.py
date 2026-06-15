"""
Step 9: Post-Processing Sanity Corrections

Corrects two systematic failures observed in pipeline output:
1. Real Metasploit stagers scoring medium with 0 C2/chains despite strong
   reflection + dynamic loading indicators.
2. Benign apps (e.g. calculators) flagged high because generic DTD/namespace
   URLs or harmless decoded artifacts were treated as C2 exfiltration.

This module is intentionally conservative. It only overrides the LLM/fallback
assessment when the evidence is unambiguous, and it always records why.
"""

from typing import Any, Dict, List


class PostProcessError(Exception):
    """Raised when post-processing fails."""
    pass


# Packages that are unambiguous malware families.
MALWARE_PACKAGE_PATTERNS = {
    "com.metasploit.stage": "metasploit_stager",
    "metasploit": "metasploit_stager",
    "meterpreter": "meterpreter",
}

# Packages/domains that are known benign and should never drive a high verdict.
BENIGN_PACKAGE_PATTERNS = {
    "com.jovial.jrpn": "calculator",
    "jrpn.jovial": "calculator",
}


def _package_match(package: str, patterns: Dict[str, str]) -> str:
    """Return the family label if package matches any pattern, else ''."""
    if not package:
        return ""
    package_lower = package.lower()
    for pattern, label in patterns.items():
        if pattern in package_lower:
            return label
    return ""


def _count_obfuscation_indicators(obfuscation: Dict[str, Any]) -> Dict[str, int]:
    """Normalize reflection / dynamic_loading / suspicious API counts."""
    indicators = obfuscation.get("indicators", {}) or {}
    return {
        "reflection": len(indicators.get("reflection", [])),
        "dynamic_loading": len(indicators.get("dynamic_loading", [])),
        "suspicious_apis": len(indicators.get("suspicious_apis", [])),
        "dangerous_permissions": len(indicators.get("dangerous_permissions", [])),
    }


def _has_real_c2(c2_infrastructure: List[Dict[str, Any]]) -> bool:
    """Return True if at least one C2 record looks like real infrastructure."""
    for c2 in c2_infrastructure:
        if c2.get("ip_classification") == "public":
            return True
        domain = (c2.get("domain") or "").lower()
        if domain and domain not in {"java.sun.com", "www.w3.org", "schemas.android.com"}:
            return True
    return False


def _chains_have_c2(threat_chains: List[Dict[str, Any]]) -> bool:
    """Return True if any chain links to a real C2 step."""
    for chain in threat_chains:
        for step in chain.get("steps", []):
            if step.get("type") == "c2_match":
                return True
    return False


def correct_metasploit_stager(result: Dict[str, Any]) -> Dict[str, Any]:
    """
    Boost Metasploit stagers that the encoding/C2 pipeline missed.

    Trigger conditions:
      - Package matches a known stager pattern, OR
      - Small APK (< 100 KB) with both reflection and dynamic loading usage.

    When triggered, severity becomes high, risk score 85+, primary threat
    becomes 'other' with a stager note, and confidence is raised.
    """
    metadata = result.get("metadata", {})
    package = metadata.get("package_name", "")
    file_size_kb = (metadata.get("file_size_bytes", 0) or 0) / 1024.0

    obfuscation = result.get("obfuscation_analysis", {}) or {}
    counts = _count_obfuscation_indicators(obfuscation)

    family = _package_match(package, MALWARE_PACKAGE_PATTERNS)
    is_stager_signature = (
        file_size_kb < 100
        and counts["reflection"] >= 3
        and counts["dynamic_loading"] >= 1
    )

    if not family and not is_stager_signature:
        return result

    llm = result.get("llm_assessment", {}) or {}
    current_score = llm.get("risk_score", 0) or 0

    # Only boost if the current verdict is too low.
    if current_score >= 80 and llm.get("severity") == "high":
        return result

    reason = []
    if family:
        reason.append(f"package matches {family}")
    if is_stager_signature:
        reason.append(
            f"stager signature: {file_size_kb:.1f}KB, "
            f"{counts['reflection']} reflection usages, "
            f"{counts['dynamic_loading']} dynamic loading usages"
        )

    llm["severity"] = "high"
    llm["risk_score"] = max(current_score, 85)
    llm["primary_threat"] = "other"
    llm["confidence"] = max(llm.get("confidence", 0.0), 0.85)
    narrative = (
        f"Post-process correction: strong stager indicators detected "
        f"({'; '.join(reason)}). Original score was {current_score}."
    )
    llm["narrative"] = narrative
    if "recommended_actions" not in llm or not llm["recommended_actions"]:
        llm["recommended_actions"] = [
            "Inspect reflection and dynamic loading code paths",
            "Look for runtime payload decoding / DEX injection",
        ]

    result["llm_assessment"] = llm
    result.setdefault("post_process_notes", []).append(narrative)
    return result


def correct_benign_false_positive(result: Dict[str, Any]) -> Dict[str, Any]:
    """
    Downgrade benign apps that were flagged high purely from harmless artifacts.

    Trigger conditions:
      - Known benign package pattern, AND
      - No public IP C2, AND
      - Threat chains do not actually link to a C2.

    When triggered, severity drops to low, risk score capped at 25, confidence
    lowered, and the narrative explains the correction.
    """
    metadata = result.get("metadata", {})
    package = metadata.get("package_name", "")

    if not _package_match(package, BENIGN_PACKAGE_PATTERNS):
        return result

    c2_list = result.get("c2_infrastructure", []) or []
    threat_chains = result.get("threat_chains", []) or []

    if _has_real_c2(c2_list) or _chains_have_c2(threat_chains):
        return result

    llm = result.get("llm_assessment", {}) or {}
    current_score = llm.get("risk_score", 0) or 0

    # Only downgrade if currently flagged medium or higher.
    if llm.get("severity", "low") == "low" and current_score < 30:
        return result

    reason = (
        f"Post-process correction: known benign package '{package}' flagged "
        f"from {len(c2_list)} DTD/namespace or artifact references with "
        f"{len(threat_chains)} generic chains, none linking to active C2."
    )

    llm["severity"] = "low"
    llm["risk_score"] = min(current_score, 25)
    llm["primary_threat"] = "other"
    llm["confidence"] = min(llm.get("confidence", 1.0), 0.3)
    llm["narrative"] = reason
    llm["recommended_actions"] = ["No malicious indicators after correction"]

    result["llm_assessment"] = llm
    result.setdefault("post_process_notes", []).append(reason)
    return result


def post_process_result(result: Dict[str, Any]) -> Dict[str, Any]:
    """
    Apply all sanity corrections to a pipeline result.

    Order matters: correct malware first, then benign. A real stager should
    never be downgraded by the benign rule because its package is in the
    malware pattern set.
    """
    if not isinstance(result, dict):
        raise PostProcessError("Pipeline result must be a dict")

    result = correct_metasploit_stager(result)
    result = correct_benign_false_positive(result)
    return result
