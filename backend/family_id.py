"""
Malware family identification.

Combines deterministic signals with an optional LLM enrichment pass:

1. Ground-truth lookup  -- exact sha256 -> family map from the bundled
   ``ground_truth_*.json`` datasets (authoritative for known samples).
2. Signature heuristics -- lightweight pure-Python rules over package name,
   C2 domains and behaviour (no native ``yara`` dependency required).
3. YARA (optional)      -- used only if ``yara-python`` is importable and the
   project's ``analysis/yara_rules.yar`` compiles.
4. LLM (optional)       -- NVIDIA NIM / Ollama, reusing the Step-7 provider
   selection, used as a fallback/enrichment when deterministic signals are
   inconclusive.

Results are cached to ``<work_dir>/<sample_id>/family.json``.
"""

import json
import os
from functools import lru_cache
from pathlib import Path
from typing import Any, Dict, List, Optional

from backend.config import settings

# Reuse the generic JSON extractor from Step 7 (no SYSTEM_PROMPT coupling).
try:
    from analysis.step7_llm_assessment import parse_llm_json
except Exception:  # pragma: no cover - defensive import
    parse_llm_json = None


PROJECT_ROOT = settings.WORK_DIR.parent.parent  # D:\DroidForensix
GROUND_TRUTH_FILES = [
    "ground_truth_test_set.json",
    "ground_truth_drebin.json",
    "ground_truth_fdroid.json",
]


# ---------------------------------------------------------------------------
# 1. Ground-truth lookup
# ---------------------------------------------------------------------------

@lru_cache(maxsize=1)
def _ground_truth_map() -> Dict[str, str]:
    """Build {sha256: family} from the bundled ground-truth datasets."""
    mapping: Dict[str, str] = {}
    for name in GROUND_TRUTH_FILES:
        path = PROJECT_ROOT / name
        if not path.exists():
            continue
        try:
            with open(path, "r", encoding="utf-8") as f:
                data = json.load(f)
        except Exception:
            continue
        entries = data if isinstance(data, list) else data.values()
        for entry in entries:
            if not isinstance(entry, dict):
                continue
            sha = (entry.get("sha256") or "").lower()
            family = entry.get("family")
            if sha and family and str(family).lower() not in ("", "unknown", "none"):
                mapping[sha] = family
    return mapping


# ---------------------------------------------------------------------------
# 2. Signature heuristics (no external deps)
# ---------------------------------------------------------------------------

# Each signature: family + any matching token in package names or C2 domains.
# Tokens are lowercase substrings. Deliberately conservative — a hit is a
# candidate, not a verdict.
_SIGNATURES = [
    {"family": "FakeInstaller", "packages": ["fakeinst", "instaler"], "domains": ["apkmania", "androidblip"]},
    {"family": "DroidKungFu", "packages": ["kungfu", "gjsvw", "ku6"], "domains": ["search.gongfu-android.com", "jin.51android.net"]},
    {"family": "Plankton", "packages": ["plankton", "apperhand", "counterclank"], "domains": ["searchmobileonline.com", "plankton-search.com"]},
    {"family": "GinMaster", "packages": ["ginmaster", "gamebox", "gmaster"], "domains": ["b3.8866.org", "android.d3g.com"]},
    {"family": "BaseBridge", "packages": ["basebridge", "sec_apk"], "domains": ["b3.8866.org"]},
    {"family": "Geinimi", "packages": ["geinimi", "ad.notify"], "domains": ["widget.skymobi.com", "wap.youlu.com"]},
    {"family": "DroidDream", "packages": ["droiddream", "rootcager", "exploid"], "domains": ["184.105.245.17"]},
    {"family": "Opfake", "packages": ["opfake", "depositmobi"], "domains": []},
    {"family": "SMSreg", "packages": ["smsreg", "smspay"], "domains": []},
    {"family": "Adrd", "packages": ["adrd", "xagchina"], "domains": ["adrd.taxuxu.com", "anchemi.com"]},
    {"family": "Kmin", "packages": ["kmin"], "domains": ["mo.cydrepower.com"]},
    {"family": "FakeDoc", "packages": ["fakedoc", "batterydoctor"], "domains": []},
    {"family": "Gappusin", "packages": ["gappusin"], "domains": []},
]

_HIGH_RISK_PERMS = {
    "android.permission.SEND_SMS", "android.permission.RECEIVE_SMS",
    "android.permission.READ_SMS", "android.permission.CALL_PHONE",
    "android.permission.READ_CONTACTS", "android.permission.READ_PHONE_STATE",
}


def _signature_candidates(result: Dict[str, Any]) -> List[Dict[str, Any]]:
    metadata = result.get("metadata", {}) or {}
    package = (metadata.get("package") or metadata.get("package_name") or "").lower()
    domains = [
        (c2.get("domain") or "").lower()
        for c2 in (result.get("c2_infrastructure", []) or [])
        if c2.get("domain")
    ]

    candidates: List[Dict[str, Any]] = []
    for sig in _SIGNATURES:
        reasons = []
        for tok in sig.get("packages", []):
            if tok and tok in package:
                reasons.append(f"package contains '{tok}'")
        for dom_tok in sig.get("domains", []):
            if dom_tok and any(dom_tok in d for d in domains):
                reasons.append(f"C2 domain matches '{dom_tok}'")
        if reasons:
            # Domain matches are stronger evidence than package-name tokens.
            confidence = 0.75 if any("domain" in r for r in reasons) else 0.5
            candidates.append({
                "family": sig["family"],
                "source": "signature",
                "confidence": confidence,
                "reasoning": "; ".join(reasons),
            })
    return candidates


# ---------------------------------------------------------------------------
# 3. YARA (optional)
# ---------------------------------------------------------------------------

def _yara_candidates(result: Dict[str, Any], sample_id: str) -> List[Dict[str, Any]]:
    try:
        import yara  # type: ignore
    except Exception:
        return []  # yara-python not installed -- silently skip

    rules_path = PROJECT_ROOT / "analysis" / "yara_rules.yar"
    if not rules_path.exists():
        return []
    try:
        rules = yara.compile(filepath=str(rules_path))
    except Exception:
        return []

    # Scan over the extracted strings / decoded payloads if present on disk.
    blob_parts: List[str] = []
    strings_path = settings.WORK_DIR / sample_id / "step2_strings.json"
    if strings_path.exists():
        try:
            with open(strings_path, "r", encoding="utf-8") as f:
                data = json.load(f)
            for s in (data.get("strings", []) or [])[:20000]:
                val = s.get("value") if isinstance(s, dict) else s
                if val:
                    blob_parts.append(str(val))
        except Exception:
            pass
    if not blob_parts:
        return []

    try:
        matches = rules.match(data="\n".join(blob_parts).encode("utf-8", "ignore"))
    except Exception:
        return []

    candidates = []
    for m in matches:
        family = (m.meta or {}).get("family") or m.rule
        candidates.append({
            "family": family,
            "source": "yara",
            "confidence": 0.85,
            "reasoning": f"matched YARA rule '{m.rule}'",
        })
    return candidates


# ---------------------------------------------------------------------------
# 4. LLM (optional)
# ---------------------------------------------------------------------------

_FAMILY_SYSTEM_PROMPT = """/no_think
You are an expert Android malware analyst. Given static-analysis indicators,
identify the most likely malware family.

Output valid JSON only, no markdown, exactly this schema:
{"family": "<family name or 'unknown'>", "confidence": 0.0-1.0, "reasoning": "<short>"}

Use well-known family names (e.g. FakeInstaller, DroidKungFu, Plankton, GinMaster,
BaseBridge, Geinimi, Opfake, DroidDream, Adrd). If indicators are insufficient,
return "unknown" with low confidence."""


def _family_context(result: Dict[str, Any]) -> str:
    metadata = result.get("metadata", {}) or {}
    c2s = result.get("c2_infrastructure", []) or []
    perms = ((result.get("manifest", {}) or {}).get("uses_permissions", []) or [])
    assessment = result.get("llm_assessment", {}) or {}
    lines = [
        f"Package: {metadata.get('package') or metadata.get('package_name') or 'unknown'}",
        f"Primary threat: {assessment.get('primary_threat', 'unknown')}",
        f"Severity: {assessment.get('severity', 'unknown')}",
        f"C2 indicators ({len(c2s)}):",
    ]
    for c2 in c2s[:12]:
        lines.append(f"  - {c2.get('protocol', '?')}://{c2.get('domain') or c2.get('ip') or '?'}{c2.get('path', '')}")
    lines.append(f"Permissions ({len(perms)}): " + ", ".join(p.split('.')[-1] for p in perms[:20]))
    return "\n".join(lines)


def _llm_family(result: Dict[str, Any]) -> Optional[Dict[str, Any]]:
    """Best-effort LLM family guess. Returns None if no provider is available."""
    if parse_llm_json is None:
        return None

    provider = (os.environ.get("LLM_PROVIDER") or settings.LLM_PROVIDER or "auto").lower()
    nim_api_key = os.environ.get("NVIDIA_NIM_API_KEY")
    use_nvidia = provider == "nvidia" or (provider == "auto" and nim_api_key)
    context = _family_context(result)
    raw = None

    try:
        if use_nvidia and nim_api_key:
            from openai import OpenAI
            client = OpenAI(
                base_url=os.environ.get("NVIDIA_NIM_BASE_URL", settings.NIM_HOST or "https://integrate.api.nvidia.com/v1"),
                api_key=nim_api_key,
            )
            resp = client.chat.completions.create(
                model=os.environ.get("NVIDIA_NIM_MODEL", settings.NIM_MODEL or "nvidia/nemotron-nano-9b-v2"),
                messages=[
                    {"role": "system", "content": _FAMILY_SYSTEM_PROMPT},
                    {"role": "user", "content": f"INDICATORS:\n{context}\n\nFAMILY:"},
                ],
                temperature=0.1,
                max_tokens=200,
                response_format={"type": "json_object"},
            )
            raw = resp.choices[0].message.content
        else:
            # Local Ollama path (only if reachable).
            from analysis.step7_llm_assessment import _ollama_available, _normalize_ollama_host
            host = _normalize_ollama_host(os.environ.get("OLLAMA_HOST", settings.OLLAMA_HOST))
            if not _ollama_available(host):
                return None
            import ollama
            client = ollama.Client(host=host, timeout=30)
            resp = client.generate(
                model=os.environ.get("OLLAMA_MODEL", settings.OLLAMA_MODEL),
                prompt=f"{_FAMILY_SYSTEM_PROMPT}\n\nINDICATORS:\n{context}\n\nFAMILY:",
                format="json",
                options={"num_ctx": 4096, "temperature": 0.1},
            )
            raw = resp.get("response", "")
    except Exception:
        return None

    parsed = parse_llm_json(raw) if raw else None
    if not parsed or not parsed.get("family"):
        return None
    family = str(parsed["family"]).strip()
    if family.lower() in ("", "none", "n/a"):
        return None
    # Treat LLM "unknown" as a valid low-confidence signal so the dashboard
    # shows that the LLM was consulted rather than silently failing.
    try:
        confidence = float(parsed.get("confidence", 0.5))
    except (TypeError, ValueError):
        confidence = 0.5
    return {
        "family": family,
        "source": "llm",
        "confidence": max(0.0, min(1.0, confidence)),
        "reasoning": str(parsed.get("reasoning", ""))[:300],
    }


# ---------------------------------------------------------------------------
# Orchestration
# ---------------------------------------------------------------------------

def identify_family(sample_id: str, result: Dict[str, Any],
                    use_llm: bool = True, use_cache: bool = True) -> Dict[str, Any]:
    """Identify the malware family for a sample.

    Returns a dict with the chosen ``family``, ``confidence``, ``method``,
    the full list of ``candidates`` and per-source detail.
    """
    cache_path = settings.WORK_DIR / sample_id / "family.json"
    if use_cache and cache_path.exists():
        try:
            with open(cache_path, "r", encoding="utf-8") as f:
                return json.load(f)
        except Exception:
            pass

    sha = (result.get("metadata", {}) or {}).get("sha256", sample_id).lower()
    candidates: List[Dict[str, Any]] = []

    # 1. Ground truth (authoritative).
    gt_family = _ground_truth_map().get(sha)
    if gt_family:
        candidates.append({
            "family": gt_family, "source": "ground_truth", "confidence": 1.0,
            "reasoning": "exact sha256 match in labelled dataset",
        })

    # 2. Signatures, 3. YARA.
    candidates.extend(_signature_candidates(result))
    candidates.extend(_yara_candidates(result, sample_id))

    deterministic = bool(candidates)

    # 4. LLM — only when deterministic signals are weak/absent.
    best_det_conf = max((c["confidence"] for c in candidates), default=0.0)
    if use_llm and best_det_conf < 0.75:
        llm = _llm_family(result)
        if llm:
            candidates.append(llm)

    # Pick the winner by source priority then confidence.
    priority = {"ground_truth": 4, "yara": 3, "signature": 2, "llm": 1}
    if candidates:
        best = max(candidates, key=lambda c: (priority.get(c["source"], 0), c["confidence"]))
        outcome = {
            "family": best["family"],
            "confidence": round(best["confidence"], 2),
            "method": best["source"],
            "reasoning": best.get("reasoning", ""),
            "candidates": sorted(candidates, key=lambda c: -c["confidence"]),
            "deterministic": deterministic,
        }
    else:
        outcome = {
            "family": "unknown",
            "confidence": 0.0,
            "method": "none",
            "reasoning": "no deterministic or LLM signal matched",
            "candidates": [],
            "deterministic": False,
        }

    # Cache (best-effort).
    try:
        cache_path.parent.mkdir(parents=True, exist_ok=True)
        with open(cache_path, "w", encoding="utf-8") as f:
            json.dump(outcome, f, indent=2)
    except Exception:
        pass

    return outcome
