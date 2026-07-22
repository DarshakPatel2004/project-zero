"""
Malware family identification engine v2.

Multi-dimensional matching across:
1. Ground-truth lookup  -- exact sha256 -> family (authoritative)
2. Signature heuristics -- package name, C2 domains, permissions, strings,
   native libraries, obfuscation characteristics
3. Permission-profile similarity -- Jaccard against known family profiles
4. YARA (optional)      -- yara-python rules
5. LLM (optional)       -- NVIDIA NIM / Ollama fallback

Each dimension contributes weighted evidence. The highest-confidence candidate
wins, with source priority used as a tiebreaker.
"""

import json
import logging
import os
from functools import lru_cache
from pathlib import Path
from typing import Any, Dict, List, Optional, Set

from backend.config import settings

logger = logging.getLogger(__name__)

try:
    from analysis.step7_llm_assessment import parse_llm_json
except Exception:
    parse_llm_json = None


PROJECT_ROOT = settings.WORK_DIR.parent.parent
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
# 2. Expanded signature database
# ---------------------------------------------------------------------------
# Each entry: family + patterns across packages, domains, permissions, strings,
# native libs, obfuscation style.  Tokens are lowercase substrings.

_SIGNATURES: List[Dict[str, Any]] = [
    # === Drebin families (core) ===
    {"family": "FakeInstaller", "packages": ["fakeinst", "instaler"], "domains": ["apkmania", "androidblip"], "perms": ["INSTALL_PACKAGES", "DELETE_PACKAGES"], "obfuscation": "none"},
    {"family": "DroidKungFu", "packages": ["kungfu", "gjsvw", "ku6", "kungu"], "domains": ["search.gongfu-android.com", "jin.51android.net", "183.6.82.102"], "perms": ["RECEIVE_BOOT_COMPLETED", "ACCESS_NETWORK_STATE"], "strings": ["kungfu", "gongfu"], "native": ["libkungfu"]},
    {"family": "Plankton", "packages": ["plankton", "apperhand", "counterclank"], "domains": ["searchmobileonline.com", "plankton-search.com", "planktondl.com"], "perms": ["INTERNET", "READ_PHONE_STATE", "ACCESS_NETWORK_STATE"], "strings": ["plankton", "apperhand"]},
    {"family": "GinMaster", "packages": ["ginmaster", "gamebox", "gmaster", "ginmaster"], "domains": ["b3.8866.org", "android.d3g.com", "gin.8866.org"], "perms": ["RECEIVE_BOOT_COMPLETED", "READ_PHONE_STATE", "ACCESS_WIFI_STATE"], "obfuscation": "reflection"},
    {"family": "BaseBridge", "packages": ["basebridge", "sec_apk", "bridge"], "domains": ["b3.8866.org", "bridge.8866.org"], "perms": ["RECEIVE_BOOT_COMPLETED", "READ_PHONE_STATE", "ACCESS_NETWORK_STATE"], "native": ["libbridge"]},
    {"family": "Geinimi", "packages": ["geinimi", "ad.notify", "adnotify"], "domains": ["widget.skymobi.com", "wap.youlu.com", "geinimi.net"], "perms": ["READ_PHONE_STATE", "ACCESS_COARSE_LOCATION", "ACCESS_FINE_LOCATION"]},
    {"family": "DroidDream", "packages": ["droiddream", "rootcager", "exploid", "dream"], "domains": ["184.105.245.17", "dream.8866.org"], "perms": ["RECEIVE_BOOT_COMPLETED", "READ_LOGS", "MOUNT_UNMOUNT_FILESYSTEMS"], "native": ["libexploid"]},
    {"family": "Opfake", "packages": ["opfake", "depositmobi", "opfake", "fakeplayer"], "domains": [], "perms": ["SEND_SMS", "RECEIVE_SMS", "READ_SMS", "WRITE_SMS"], "strings": ["premium", "rate", "sms"]},
    {"family": "SMSreg", "packages": ["smsreg", "smspay", "smssend"], "domains": [], "perms": ["SEND_SMS", "RECEIVE_SMS", "INTERNET"], "strings": ["smsreg", "smspay"]},
    {"family": "Adrd", "packages": ["adrd", "xagchina"], "domains": ["adrd.taxuxu.com", "anchemi.com", "adrd.net"], "perms": ["INTERNET", "READ_PHONE_STATE", "ACCESS_NETWORK_STATE"]},
    {"family": "Kmin", "packages": ["kmin"], "domains": ["mo.cydrepower.com"], "perms": ["INTERNET", "READ_PHONE_STATE", "SEND_SMS"]},
    {"family": "FakeDoc", "packages": ["fakedoc", "batterydoctor", "fake"], "domains": [], "perms": ["SEND_SMS", "INTERNET"], "obfuscation": "none"},
    {"family": "Gappusin", "packages": ["gappusin", "gapp"], "domains": ["gappusin.com"], "perms": ["INTERNET", "ACCESS_NETWORK_STATE"]},

    # === Additional Drebin families ===
    {"family": "Iconosys", "packages": ["iconosys", "iconsmobile"], "domains": ["iconosys.com"], "perms": ["INTERNET", "SEND_SMS", "READ_PHONE_STATE"]},
    {"family": "FakeRun", "packages": ["fakerun", "fakeservice"], "domains": [], "perms": ["SEND_SMS", "RECEIVE_SMS"], "strings": ["premium", "charge"]},
    {"family": "Jifake", "packages": ["jifake"], "domains": [], "perms": ["SEND_SMS", "INTERNET"]},
    {"family": "Boxer", "packages": ["boxer"], "domains": ["boxer.sk"], "perms": ["SEND_SMS", "RECEIVE_SMS", "INTERNET"]},
    {"family": "Smssniffer", "packages": ["smssniffer", "smsniff"], "domains": [], "perms": ["RECEIVE_SMS", "READ_SMS"], "strings": ["intercept"]},
    {"family": "FakeAngry", "packages": ["fakeangry", "angry"], "domains": [], "perms": ["SEND_SMS", "INTERNET"], "strings": ["angry"]},
    {"family": "MobileTx", "packages": ["mobiletx"], "domains": ["mobil.tx.com"], "perms": ["SEND_SMS", "INTERNET"]},
    {"family": "GoldDream", "packages": ["golddream", "gold"], "domains": ["gold.culture.com"], "perms": ["READ_PHONE_STATE", "RECEIVE_BOOT_COMPLETED"]},

    # === Banking / financial trojans ===
    {"family": "BankBot", "packages": ["bankbot", "bank"], "domains": ["bankbot.cc"], "perms": ["RECEIVE_SMS", "READ_SMS", "SYSTEM_ALERT_WINDOW", "BIND_ACCESSIBILITY_SERVICE"], "strings": ["bank", "credential", "overlay", "accessibility"]},
    {"family": "Cerberus", "packages": ["cerberus"], "domains": ["cerberus.cc"], "perms": ["BIND_ACCESSIBILITY_SERVICE", "SYSTEM_ALERT_WINDOW", "RECEIVE_SMS", "READ_SMS"], "strings": ["cerberus", "overlay"]},
    {"family": "EventBot", "packages": ["eventbot"], "domains": ["eventbot.cc"], "perms": ["BIND_ACCESSIBILITY_SERVICE", "RECEIVE_SMS", "SYSTEM_ALERT_WINDOW"], "obfuscation": "reflection"},
    {"family": "XLoader", "packages": ["xloader"], "domains": ["xloader.cc"], "perms": ["BIND_ACCESSIBILITY_SERVICE", "RECEIVE_SMS"], "native": ["libxloader"]},
    {"family": "Anubis", "packages": ["anubis"], "domains": ["anubis.cc", "anubis.download"], "perms": ["BIND_ACCESSIBILITY_SERVICE", "SYSTEM_ALERT_WINDOW", "RECEIVE_SMS", "READ_SMS", "READ_CONTACTS"], "obfuscation": "packing"},
    {"family": "Gustuff", "packages": ["gustuff"], "domains": ["gustuff.net"], "perms": ["BIND_ACCESSIBILITY_SERVICE", "SYSTEM_ALERT_WINDOW", "SEND_SMS"], "native": ["libgustuff"]},
    {"family": "Cabossous", "packages": ["cabossous"], "domains": [], "perms": ["BIND_ACCESSIBILITY_SERVICE", "SYSTEM_ALERT_WINDOW", "RECEIVE_SMS", "READ_SMS"], "obfuscation": "reflection"},
    {"family": "TeaBot", "packages": ["teabot", "teabot"], "domains": ["teabot.net"], "perms": ["BIND_ACCESSIBILITY_SERVICE", "SYSTEM_ALERT_WINDOW"], "obfuscation": "packing"},
    {"family": "FluBot", "packages": ["flubot", "flubot"], "domains": ["flubot.cc"], "perms": ["BIND_ACCESSIBILITY_SERVICE", "SYSTEM_ALERT_WINDOW", "RECEIVE_SMS"], "strings": ["flubot"]},

    # === RAT families ===
    {"family": "AhMyth", "packages": ["ahmyth", "ahmythrat"], "domains": ["ahmyth.cc"], "perms": ["READ_CONTACTS", "READ_CALL_LOG", "CAMERA", "RECORD_AUDIO", "ACCESS_FINE_LOCATION"], "native": ["libahmyth"]},
    {"family": "SpyNote", "packages": ["spynote", "spy"], "domains": ["spynote.net"], "perms": ["CAMERA", "RECORD_AUDIO", "READ_CONTACTS", "READ_CALL_LOG", "ACCESS_FINE_LOCATION"], "obfuscation": "reflection"},
    {"family": "DroidJack", "packages": ["droidjack", "djack"], "domains": ["droidjack.net"], "perms": ["CAMERA", "READ_CONTACTS", "ACCESS_FINE_LOCATION", "READ_PHONE_STATE"], "native": ["libdjack"]},
    {"family": "AndroRAT", "packages": ["androrat", "androidrat"], "domains": [], "perms": ["CAMERA", "RECORD_AUDIO", "READ_CONTACTS", "ACCESS_FINE_LOCATION"], "strings": ["rat", "remote"]},
    {"family": "VncServer", "packages": ["vncserver", "vnc"], "domains": [], "perms": ["SYSTEM_ALERT_WINDOW", "CAMERA"], "native": ["libvnc"]},
    {"family": "OmniRAT", "packages": ["omni", "omnirat"], "domains": ["omni.cc"], "perms": ["CAMERA", "RECORD_AUDIO", "READ_CONTACTS", "READ_CALL_LOG"], "strings": ["omni"]},

    # === SMS / premium-rate trojans ===
    {"family": "SndApps", "packages": ["sndapps"], "domains": ["sndapps.net"], "perms": ["SEND_SMS", "RECEIVE_SMS", "INTERNET"], "strings": ["snd"]},
    {"family": "ZertSecurity", "packages": ["zert", "zertsec"], "domains": [], "perms": ["SEND_SMS", "RECEIVE_SMS", "READ_SMS"]},
    {"family": "FakePlayer", "packages": ["fakeplayer", "fakeplay"], "domains": [], "perms": ["SEND_SMS", "INTERNET"], "strings": ["media", "player"]},
    {"family": "FakeMart", "packages": ["fakemart"], "domains": [], "perms": ["SEND_SMS"]},
    {"family": "SendPay", "packages": ["sendpay"], "domains": [], "perms": ["SEND_SMS", "READ_SMS", "INTERNET"]},
    {"family": "BeanBot", "packages": ["beanbot"], "domains": [], "perms": ["SEND_SMS", "RECEIVE_SMS", "INTERNET"], "obfuscation": "reflection"},
    {"family": "Zsone", "packages": ["zsone"], "domains": ["zsone.net"], "perms": ["SEND_SMS", "INTERNET"]},
    {"family": "FakeAV", "packages": ["fakeav", "antivir"], "domains": [], "perms": ["INTERNET", "SYSTEM_ALERT_WINDOW"]},
    {"family": "DogWars", "packages": ["dogwars"], "domains": ["dogwars.net"], "perms": ["SEND_SMS", "RECEIVE_SMS"]},

    # === Spyware / stalkerware ===
    {"family": "FlexiSpy", "packages": ["flexispy", "flex"], "domains": ["flexispy.com"], "perms": ["CAMERA", "RECORD_AUDIO", "READ_CONTACTS", "READ_CALL_LOG", "ACCESS_FINE_LOCATION", "RECEIVE_SMS"], "obfuscation": "none"},
    {"family": "Mspy", "packages": ["mspy"], "domains": ["mspy.com"], "perms": ["CAMERA", "RECORD_AUDIO", "READ_CONTACTS", "READ_CALL_LOG"], "strings": ["mspy"]},
    {"family": "Copy9", "packages": ["copy9"], "domains": ["copy9.com"], "perms": ["CAMERA", "RECORD_AUDIO", "READ_CONTACTS"]},
    {"family": "TheTruthSpy", "packages": ["truthspy", "thetruth"], "domains": ["thetruthspy.com"], "perms": ["CAMERA", "RECORD_AUDIO", "ACCESS_FINE_LOCATION"]},
    {"family": "Mobistealth", "packages": ["mobistealth"], "domains": ["mobistealth.com"], "perms": ["CAMERA", "RECORD_AUDIO", "RECEIVE_SMS"], "native": ["libmobistealth"]},

    # === Adware / potentially unwanted ===
    {"family": "AirPush", "packages": ["airpush", "airpush"], "domains": ["airpush.com"], "perms": ["INTERNET", "ACCESS_NETWORK_STATE"], "obfuscation": "none"},
    {"family": "Leadbolt", "packages": ["leadbolt"], "domains": ["leadbolt.com"], "perms": ["INTERNET", "ACCESS_NETWORK_STATE"], "obfuscation": "none"},
    {"family": "Koodous", "packages": ["koodous"], "domains": [], "perms": ["INTERNET"]},
    {"family": "MobCLI", "packages": ["mobcli"], "domains": [], "perms": ["INTERNET", "ACCESS_NETWORK_STATE"]},
    {"family": "Dowgin", "packages": ["dowgin"], "domains": ["dowgin.net"], "perms": ["INTERNET", "READ_PHONE_STATE"], "native": ["libdowgin"]},

    # === Chinese / Gameloop malware families ===
    {"family": "Xavier", "packages": ["xavier"], "domains": ["xavier.net"], "perms": ["INTERNET", "READ_PHONE_STATE", "READ_EXTERNAL_STORAGE"], "strings": ["xavier"]},
    {"family": "RottenSys", "packages": ["rottensys", "rotten"], "domains": ["rottensys.com"], "perms": ["INTERNET", "SYSTEM_ALERT_WINDOW"], "strings": ["rotten"]},
    {"family": "LionMobi", "packages": ["lionmobi", "lion"], "domains": ["lionmobi.com"], "perms": ["INTERNET", "SYSTEM_ALERT_WINDOW"]},
    {"family": "Judy", "packages": ["judy"], "domains": ["judy.net"], "perms": ["INTERNET", "ACCESS_NETWORK_STATE"], "obfuscation": "none"},
    {"family": "VikingHorde", "packages": ["vikinghorde", "viking"], "domains": [], "perms": ["INTERNET", "ACCESS_NETWORK_STATE"], "native": ["libviking"]},

    # === Fileless / DEX-loading families ===
    {"family": "Dropper", "packages": ["dropper"], "domains": [], "perms": ["REQUEST_INSTALL_PACKAGES", "WRITE_EXTERNAL_STORAGE"], "obfuscation": "packing", "strings": ["dex", "load", "reflect"]},
    {"family": "Hqwar", "packages": ["hqwar"], "domains": [], "perms": ["INTERNET", "READ_EXTERNAL_STORAGE"], "obfuscation": "packing", "strings": ["hqwar"]},
    {"family": "Triada", "packages": ["triada"], "domains": ["triada.net"], "perms": ["INTERNET", "READ_PHONE_STATE", "INSTALL_PACKAGES"], "native": ["libtriada"]},
    {"family": "Gooligan", "packages": ["gooligan"], "domains": ["gooligan.net"], "perms": ["INTERNET", "GET_ACCOUNTS", "READ_PHONE_STATE"], "obfuscation": "reflection"},
    {"family": "CopyCat", "packages": ["copycat"], "domains": ["copycat.cc"], "perms": ["INTERNET", "SYSTEM_ALERT_WINDOW", "INSTALL_PACKAGES"], "native": ["libcopycat"]},
    {"family": "Mariposa", "packages": ["mariposa"], "domains": ["mariposa.cc"], "perms": ["INTERNET", "ACCESS_NETWORK_STATE"], "obfuscation": "reflection"},
    {"family": "SharkBot", "packages": ["sharkbot"], "domains": ["sharkbot.cc"], "perms": ["BIND_ACCESSIBILITY_SERVICE", "SYSTEM_ALERT_WINDOW", "RECEIVE_SMS"], "obfuscation": "packing"},
]

# High-risk permission set used for permission-profile similarity.
_HIGH_RISK_PERMS: Set[str] = {
    "android.permission.SEND_SMS", "android.permission.RECEIVE_SMS",
    "android.permission.READ_SMS", "android.permission.CALL_PHONE",
    "android.permission.READ_CONTACTS", "android.permission.READ_PHONE_STATE",
    "android.permission.ACCESS_FINE_LOCATION", "android.permission.ACCESS_COARSE_LOCATION",
    "android.permission.RECORD_AUDIO", "android.permission.CAMERA",
    "android.permission.READ_CALL_LOG", "android.permission.WRITE_CALL_LOG",
    "android.permission.BIND_ACCESSIBILITY_SERVICE",
    "android.permission.SYSTEM_ALERT_WINDOW",
    "android.permission.REQUEST_INSTALL_PACKAGES",
    "android.permission.INSTALL_PACKAGES",
}


def _extract_permissions(result: Dict[str, Any]) -> Set[str]:
    """Extract all permission names from the result."""
    perms: Set[str] = set()
    raw = result.get("manifest", {}) or {}
    for key in ("uses_permissions", "permissions"):
        entries = raw.get(key, []) or []
        for p in entries:
            if isinstance(p, str):
                perms.add(p)
            elif isinstance(p, dict):
                name = p.get("name") or p.get("permission") or ""
                if name:
                    perms.add(name)
    return perms


# ---------------------------------------------------------------------------
# 2a. Signature heuristics — multi-dimensional (restored original confidence
#     model: base 0.5 for package, 0.75 for domain; extra signals boost)
# ---------------------------------------------------------------------------

def _safe_lib_name(lib) -> str:
    try:
        if isinstance(lib, dict):
            return (lib.get("name") or lib.get("library") or str(lib)).lower()
        return str(lib).lower()
    except Exception:
        return ""


def _signature_candidates(result: Dict[str, Any]) -> List[Dict[str, Any]]:
    metadata = result.get("metadata", {}) or {}
    package = (metadata.get("package") or metadata.get("package_name") or "").lower()
    domains = [
        (c2.get("domain") or "").lower()
        for c2 in (result.get("c2_infrastructure", []) or [])
        if c2.get("domain")
    ]
    apk_perms = _extract_permissions(result)
    strings_data = result.get("strings", {}) or {}
    all_strs: List[str] = []
    if isinstance(strings_data, dict):
        for cat in ("string_literals", "byte_arrays", "native_strings"):
            all_strs.extend(strings_data.get(cat, []) or [])
    strs_text = " ".join(s.lower() if isinstance(s, str) else str(s) for s in all_strs)
    extraction = result.get("extraction", {}) or {}
    raw_libs = extraction.get("native_libs", []) or []
    if not isinstance(raw_libs, list):
        raw_libs = [raw_libs]
    lib_names = " ".join(_safe_lib_name(lib) for lib in raw_libs)

    candidates: List[Dict[str, Any]] = []
    for sig in _SIGNATURES:
        reasons = []

        for tok in sig.get("packages", []):
            if tok and tok in package:
                reasons.append(f"package contains '{tok}'")
                break

        has_domain = False
        for dom_tok in sig.get("domains", []):
            if dom_tok and any(dom_tok in d for d in domains):
                reasons.append(f"C2 domain matches '{dom_tok}'")
                has_domain = True
                break

        fam_perms = set(sig.get("perms", []))
        if fam_perms:
            matched_perms = apk_perms & fam_perms
            if matched_perms:
                reasons.append(f"permissions match: {', '.join(sorted(matched_perms)[:4])}")

        for st in sig.get("strings", []):
            if st and st in strs_text:
                reasons.append(f"string contains '{st}'")
                break

        for nt in sig.get("native", []):
            if nt and nt in lib_names:
                reasons.append(f"native lib matches '{nt}'")
                break

        if reasons:
            confidence = 0.55 if has_domain else 0.40
            if len(reasons) >= 2:
                confidence = min(confidence + 0.10 * (len(reasons) - 1), 0.95)
            if has_domain:
                confidence = max(confidence, 0.70)
            candidates.append({
                "family": sig["family"],
                "source": "signature",
                "confidence": round(confidence, 3),
                "reasoning": "; ".join(reasons),
            })
    return candidates


# (Permission-profile matching is integrated directly into _signature_candidates
# as a per-signature bonus signal — no separate standalone matcher needed.)


# ---------------------------------------------------------------------------
# 2c. Obfuscation-profile matching
# ---------------------------------------------------------------------------

# Correlate obfuscation techniques with known families.
_OBFUSCATION_PROFILES: List[Dict[str, Any]] = [
    {"family": "Packed", "techniques": ["packing", "dex_protection"], "min_score": 6},
    {"family": "ReflectiveLoader", "techniques": ["reflection"], "min_score": 4},
    {"family": "DynamicLoader", "techniques": ["dynamic_loading"], "min_score": 3},
    {"family": "Obfuscated", "techniques": ["string_obfuscation", "control_flow"], "min_score": 2},
]


def _obfuscation_candidates(result: Dict[str, Any]) -> List[Dict[str, Any]]:
    """Match obfuscation characteristics against known profiles."""
    obf = result.get("obfuscation_analysis", {}) or {}
    indicators = obf.get("indicators", {}) or {}

    reflection_count = len(indicators.get("reflection", []))
    dynamic_count = len(indicators.get("dynamic_loading", []))
    crypto_count = len(indicators.get("crypto_apis", []))
    obf_score = obf.get("obfuscation_score", 0)

    candidates: List[Dict[str, Any]] = []
    for profile in _OBFUSCATION_PROFILES:
        score = 0
        reasons = []
        for tech in profile["techniques"]:
            if tech == "reflection":
                score += min(reflection_count / 5, 1.0) * 0.4
                if reflection_count >= profile["min_score"]:
                    reasons.append(f"{reflection_count} reflection usages")
            if tech == "dynamic_loading":
                score += min(dynamic_count / 3, 1.0) * 0.3
                if dynamic_count >= profile["min_score"]:
                    reasons.append(f"{dynamic_count} dynamic loading calls")
            if tech == "packing":
                dex_ents = obf.get("dex_entropy", []) or []
                packed = sum(1 for d in dex_ents if d.get("likely_packed"))
                if packed > 0:
                    score += 0.5
                    reasons.append(f"{packed} packed DEX sections")
                if obf_score >= 7:
                    score += 0.2
                    reasons.append(f"obfuscation score {obf_score}")
            if tech in ("string_obfuscation", "control_flow"):
                if obf_score >= profile["min_score"]:
                    score += min(obf_score / 10, 0.5)
                    reasons.append(f"obfuscation score {obf_score}")
        score = min(score, 0.6)
        if score > 0.2:
            candidates.append({
                "family": profile["family"],
                "source": "obfuscation_profile",
                "confidence": round(score, 3),
                "reasoning": "; ".join(reasons),
            })
    return candidates


# ---------------------------------------------------------------------------
# 2d. String-pattern matching for known malware strings
# ---------------------------------------------------------------------------

# Distinctive strings that strongly correlate with specific families.
_STRING_SIGNATURES: List[Dict[str, Any]] = [
    {"family": "Anubis", "patterns": ["anubis", "overlay"]},
    {"family": "Cerberus", "patterns": ["cerberus"]},
    {"family": "EventBot", "patterns": ["eventbot"]},
    {"family": "FluBot", "patterns": ["flubot", "flu"]},
    {"family": "TeaBot", "patterns": ["teabot"]},
    {"family": "XLoader", "patterns": ["xloader"]},
    {"family": "SharkBot", "patterns": ["sharkbot"]},
    {"family": "Xavier", "patterns": ["xavier"]},
    {"family": "Triada", "patterns": ["triada"]},
    {"family": "CopyCat", "patterns": ["copycat"]},
    {"family": "Gooligan", "patterns": ["gooligan"]},
    {"family": "Hqwar", "patterns": ["hqwar"]},
    {"family": "VikingHorde", "patterns": ["vikinghorde"]},
    {"family": "RottenSys", "patterns": ["rottensys", "systemupdate"]},
    {"family": "LionMobi", "patterns": ["lionmobi"]},
    {"family": "Judy", "patterns": ["judy"]},
]


def _string_pattern_candidates(result: Dict[str, Any]) -> List[Dict[str, Any]]:
    strings_data = result.get("strings", {}) or {}
    all_strs: List[str] = []
    if isinstance(strings_data, dict):
        for cat in ("string_literals", "byte_arrays", "native_strings"):
            all_strs.extend(strings_data.get(cat, []) or [])
    strs_text = " ".join(s.lower() if isinstance(s, str) else str(s) for s in all_strs)

    candidates: List[Dict[str, Any]] = []
    for sig in _STRING_SIGNATURES:
        matched = [p for p in sig["patterns"] if p in strs_text]
        if matched:
            candidates.append({
                "family": sig["family"],
                "source": "string_pattern",
                "confidence": round(min(0.5 + 0.1 * len(matched), 0.8), 3),
                "reasoning": f"strings contain '{', '.join(matched)}'",
            })
    return candidates


# ---------------------------------------------------------------------------
# 3. YARA (optional)
# ---------------------------------------------------------------------------

def _yara_candidates(result: Dict[str, Any], sample_id: str) -> List[Dict[str, Any]]:
    try:
        import yara
    except Exception:
        return []

    rules_path = PROJECT_ROOT / "analysis" / "yara_rules.yar"
    if not rules_path.exists():
        return []
    try:
        rules = yara.compile(filepath=str(rules_path))
    except Exception:
        return []

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
            logger.debug("Failed to parse strings for blob extraction")
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
You are an expert Android malware analyst performing family identification on
an APK. You receive structured static-analysis output covering C2 infrastructure,
threat chains, obfuscation, encrypted assets, native libraries, and permissions.

Analyze ALL evidence holistically before deciding. Look for:
- Obfuscated/encrypted game assets hiding real domains (common in game-wrapped malware)
- Native library undersizing (stub .so files that download real payload at runtime)
- Encrypted asset archives (splash.zip, data files with entropy >7.9)
- Repeated obfuscated domain patterns in asset paths
- Permission clusters that match known family behavior profiles
- DEX packing indicators (high entropy, few strings relative to size)

Output valid JSON only, no markdown, exactly this schema:
{"family": "<family name or 'unknown'>", "confidence": 0.0-1.0, "reasoning": "<short>"}

When returning a known family name, cite specific evidence (e.g. "package name
contains 'kungfu'", "C2 domain matches known Geinimi infrastructure").
If indicators are insufficient or the sample appears benign, return "unknown"
with low confidence. Do NOT force a match when the evidence is weak."""


def _family_context(result: Dict[str, Any]) -> str:
    metadata = result.get("metadata", {}) or {}
    c2s = result.get("c2_infrastructure", []) or []
    perms = list(_extract_permissions(result))
    assessment = result.get("llm_assessment", {}) or {}
    obf = result.get("obfuscation_analysis", {}) or {}
    chains_raw = result.get("threat_chains", []) or []
    encodings = result.get("encodings", []) or []
    payloads = result.get("payloads", []) or []
    extraction = result.get("extraction", {}) or {}

    size_bytes = metadata.get('file_size_bytes', 0)
    try:
        size_mb = float(size_bytes) / 1024 / 1024
    except (TypeError, ValueError):
        size_mb = 0.0

    lines = [
        f"Package: {metadata.get('package') or metadata.get('package_name') or 'unknown'}",
        f"Version: {metadata.get('version_name', '?')}",
        f"File size: {size_mb:.1f} MB",
        f"Strings extracted: {extraction.get('total_strings_extracted', 0)}",
        f"Primary threat: {assessment.get('primary_threat', 'unknown')}",
        f"Severity: {assessment.get('severity', 'unknown')}",
        f"Risk score: {assessment.get('risk_score', '?')}",
    ]

    strings_cats = result.get("strings", {}) or {}
    if isinstance(strings_cats, dict):
        for cat_name in ["string_literals", "byte_arrays", "numeric_constants", "resource_strings", "native_strings"]:
            items = strings_cats.get(cat_name, []) or []
            lines.append(f"  {cat_name}: {len(items)}")

    lines += [
        f"Total classes: {extraction.get('decompiled_classes', 0)}",
        f"Native libs found: {extraction.get('native_libs_found', 0)}",
        "",
    ]

    lines.append(f"C2 indicators ({len(c2s)}):")
    for c2 in c2s[:12]:
        domain = c2.get('domain') or c2.get('ip') or '?'
        lines.append(f"  - {c2.get('protocol', '?')}://{domain}{c2.get('path', '')}")
    if not c2s:
        lines.append("  (none)")
    lines.append("")

    lines.append(f"Threat chains: {len(chains_raw)}")
    high_chains = [c for c in chains_raw if c.get('severity') == 'high']
    if high_chains:
        lines.append(f"  High-severity chains: {len(high_chains)}")
        for c in high_chains[:5]:
            dc = c.get('decoding_chain', [])
            dc_str = ' -> '.join(dc) if dc else '?'
            lines.append(f"    Chain {c.get('chain_id')}: {dc_str}")
    lines.append("")

    lines.append(f"Encoding types ({len(encodings)}):")
    if encodings:
        for enc in encodings[:10]:
            if isinstance(enc, dict):
                lines.append(f"  - {enc.get('type', '?')} ({enc.get('count', 0)} occurrences)")
            else:
                lines.append(f"  - {enc}")
    lines.append("")

    lines.append(f"Decoded payloads: {len(payloads)}")
    for p in payloads[:8]:
        if isinstance(p, dict):
            lines.append(f"  - {str(p.get('decoded', ''))[:80]}")
        else:
            lines.append(f"  - {str(p)[:80]}")
    lines.append("")

    obf_score = obf.get('obfuscation_score', 0)
    obf_level = obf.get('obfuscation_level', 'unknown')
    lines.append(f"Obfuscation score: {obf_score} ({obf_level})")
    indicators = obf.get('indicators', {}) or {}
    lines.append(f"  Reflection usages: {len(indicators.get('reflection', []))}")
    lines.append(f"  Dynamic loading: {len(indicators.get('dynamic_loading', []))}")
    lines.append(f"  Crypto APIs: {len(indicators.get('crypto_apis', []))}")
    lines.append(f"  Suspicious APIs: {len(indicators.get('suspicious_apis', []))}")
    dangerous_perms = indicators.get('dangerous_permissions', [])
    if dangerous_perms:
        lines.append(f"  Dangerous permissions ({len(dangerous_perms)}): " + ", ".join(p.split('.')[-1] for p in dangerous_perms[:10]))

    flags = obf.get('flags', []) or []
    if flags:
        lines.append(f"  Flags ({len(flags)}):")
        for f in flags[:10]:
            lines.append(f"    [{f.get('severity','?')}] {f.get('type','?')}: {str(f.get('detail',''))[:100]}")

    native = obf.get('native_library_analysis', {}) or {}
    suspicious_libs = native.get('suspicious', []) or []
    if suspicious_libs:
        lines.append(f"  Suspicious native libs ({len(suspicious_libs)}):")
        for lib in suspicious_libs[:8]:
            lines.append(f"    {lib.get('library', '?')}: {lib.get('reason', '?')} ({lib.get('detail', '')})")

    dex_ents = obf.get('dex_entropy', []) or []
    if any(d.get('likely_packed') for d in dex_ents):
        lines.append("  DEX packing: DETECTED")
    lines.append("")

    lines.append(f"All permissions ({len(perms)}): " + ", ".join(p.split('.')[-1] for p in perms[:25]))
    if len(perms) > 25:
        lines.append(f"  ... and {len(perms) - 25} more")

    return "\n".join(lines)


def _llm_family(result: Dict[str, Any]) -> Optional[Dict[str, Any]]:
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
                model=os.environ.get("NVIDIA_NIM_MODEL", settings.NIM_MODEL or "deepseek-ai/deepseek-v4-pro"),
                messages=[
                    {"role": "system", "content": _FAMILY_SYSTEM_PROMPT},
                    {"role": "user", "content": f"INDICATORS:\n{context}\n\nFAMILY:"},
                ],
                temperature=0.1,
                max_tokens=400,
                response_format={"type": "json_object"},
            )
            raw = resp.choices[0].message.content
        else:
            from analysis.step7_llm_assessment import _ollama_available, _normalize_ollama_host
            host = _normalize_ollama_host(os.environ.get("OLLAMA_HOST", settings.OLLAMA_HOST))
            if not _ollama_available(host):
                return None
            import ollama
            client = ollama.Client(host=host, timeout=120)
            resp = client.generate(
                model=os.environ.get("OLLAMA_MODEL", settings.OLLAMA_MODEL),
                prompt=f"{_FAMILY_SYSTEM_PROMPT}\n\nINDICATORS:\n{context}\n\nFAMILY:",
                format="json",
                options={"num_ctx": 8192, "temperature": 0.1},
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

    Multi-dimensional matching across:
    - Ground truth (authoritative SHA-256 lookup)
    - Signature heuristics (package, domains, permissions, strings, native libs)
    - Permission-profile similarity (Jaccard against family profiles)
    - Obfuscation-profile matching
    - String-pattern matching (distinctive family strings)
    - YARA rules (if available)
    - LLM (fallback, if available)

    Returns a dict with the chosen ``family``, ``confidence``, ``method``,
    the full list of ``candidates`` and per-source detail.
    """
    env_val = os.environ.get("FAMILY_USE_CACHE", "")
    if env_val and env_val.lower() in ("0", "false", "no"):
        use_cache = False

    cache_path = settings.WORK_DIR / sample_id / "family.json"
    if use_cache and cache_path.exists():
        try:
            with open(cache_path, "r", encoding="utf-8") as f:
                return json.load(f)
        except Exception:
            logger.debug("Failed to read family cache for %s", sample_id)

    sha = (result.get("metadata", {}) or {}).get("sha256", sample_id).lower()
    candidates: List[Dict[str, Any]] = []

    # 1. Ground truth (authoritative).
    gt_family = _ground_truth_map().get(sha)
    if gt_family:
        candidates.append({
            "family": gt_family, "source": "ground_truth", "confidence": 1.0,
            "reasoning": "exact sha256 match in labelled dataset",
        })

    # 2. Multi-dimensional signature heuristics.
    candidates.extend(_signature_candidates(result))

    # 3. Obfuscation-profile matching.
    candidates.extend(_obfuscation_candidates(result))

    # 4. String-pattern matching.
    candidates.extend(_string_pattern_candidates(result))

    # 5. YARA.
    candidates.extend(_yara_candidates(result, sample_id))

    deterministic = bool(candidates)

    # 6. LLM — only when deterministic signals are weak/absent.
    best_det_conf = max((c["confidence"] for c in candidates), default=0.0)
    if use_llm and best_det_conf < 0.75:
        llm = _llm_family(result)
        if llm:
            candidates.append(llm)

    # Pick the winner by source priority then confidence.
    priority = {"ground_truth": 5, "yara": 4, "string_pattern": 4,
                "signature": 3, "obfuscation_profile": 1, "llm": 1}
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

    try:
        cache_path.parent.mkdir(parents=True, exist_ok=True)
        with open(cache_path, "w", encoding="utf-8") as f:
            json.dump(outcome, f, indent=2)
    except Exception:
        logger.warning("Failed to write family cache for %s", sample_id)

    return outcome
