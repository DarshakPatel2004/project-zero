"""
Step 8: Advanced Obfuscation Analysis

Uses Androguard DEX bytecode analysis, native library string extraction,
and DEX packing/entropy detection to catch obfuscation techniques that
static decompilation (apktool/jadx) misses.

Detects:
- Reflection usage
- Dynamic code loading (DexClassLoader, PathClassLoader, etc.)
- Native library loading (System.loadLibrary)
- Crypto/encryption API usage
- Suspicious permission + API combinations
- Packed/encrypted DEX via entropy analysis
- Native library strings (potential C2 in .so files)
"""

import json
import logging
import math
import re
import shutil
import subprocess
import zipfile
from pathlib import Path
from typing import Dict, List, Any, Optional

from backend.config import settings

# Suppress verbose Androguard logging
logging.getLogger("androguard").setLevel(logging.WARNING)
try:
    import loguru
    loguru.logger.remove()
except Exception:
    pass


class ObfuscationAnalysisError(Exception):
    """Raised when obfuscation analysis fails."""
    pass


# ---------------------------------------------------------------------------
# Patterns
# ---------------------------------------------------------------------------

REFLECTION_PATTERNS = [
    r"Ljava/lang/reflect/",
    r"invoke",
    r"getMethod",
    r"getDeclaredMethod",
    r"getConstructor",
    r"getDeclaredConstructor",
    r"newInstance",
    r"setAccessible",
]

DYNAMIC_LOADING_PATTERNS = [
    r"Ldalvik/system/DexClassLoader",
    r"Ldalvik/system/PathClassLoader",
    r"Ldalvik/system/InMemoryClassLoader",
    r"Ldalvik/system/DelegateLastClassLoader",
    r"Landroid/app/DexClassLoader",
    r"Ljava/lang/ClassLoader",
]

NATIVE_LOADING_PATTERNS = [
    r"Ljava/lang/System;->loadLibrary",
    r"Ljava/lang/System;->load",
    r"Ldalvik/system/Runtime;->loadLibrary",
]

CRYPTO_PATTERNS = [
    r"Ljavax/crypto/",
    r"Ljava/security/",
    r"Landroid/security/",
    r"MessageDigest",
    r"Cipher",
    r"SecretKey",
    r"KeyGenerator",
    r"IvParameterSpec",
    r"Mac",
    r"Signature",
]

SUSPICIOUS_APIS = [
    r"Landroid/telephony/SmsManager;->sendTextMessage",
    r"Landroid/telephony/TelephonyManager;->getDeviceId",
    r"Landroid/telephony/TelephonyManager;->getSubscriberId",
    r"Landroid/telephony/TelephonyManager;->getLine1Number",
    r"Landroid/content/ContentResolver;->query",
    r"Landroid/provider/ContactsContract",
    r"Landroid/location/LocationManager;->getLastKnownLocation",
    r"Landroid/location/LocationManager;->requestLocationUpdates",
    r"Landroid/app/admin/DevicePolicyManager",
    r"Landroid/accessibilityservice/AccessibilityService",
    r"Landroid/media/projection/MediaProjectionManager",
    r"Landroid/content/pm/PackageManager;->setComponentEnabledSetting",
    r"Landroid/os/PowerManager\$WakeLock;->acquire",
    r"Landroid/net/wifi/WifiManager",
    r"Ljava/net/HttpURLConnection",
    r"Lokhttp3/",
    r"Lretrofit2/",
]

DANGEROUS_PERMISSIONS = [
    "SEND_SMS",
    "READ_SMS",
    "RECEIVE_SMS",
    "READ_PHONE_STATE",
    "READ_CONTACTS",
    "READ_CALL_LOG",
    "RECORD_AUDIO",
    "CAMERA",
    "ACCESS_FINE_LOCATION",
    "ACCESS_COARSE_LOCATION",
    "SYSTEM_ALERT_WINDOW",
    "BIND_ACCESSIBILITY_SERVICE",
    "BIND_DEVICE_ADMIN",
    "REQUEST_INSTALL_PACKAGES",
    "WRITE_EXTERNAL_STORAGE",
]

URL_RE = re.compile(r'https?://[^\s"\'<>]+', re.IGNORECASE)
IP_RE = re.compile(r'\b(?:(?:25[0-5]|2[0-4]\d|[01]?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d?\d)\b')
DOMAIN_RE = re.compile(r'\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}\b')


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def shannon_entropy(data: bytes) -> float:
    """Calculate Shannon entropy of bytes."""
    if not data:
        return 0.0
    length = len(data)
    freq = {}
    for byte in data:
        freq[byte] = freq.get(byte, 0) + 1
    entropy = 0.0
    for count in freq.values():
        p = count / length
        entropy -= p * math.log2(p)
    return entropy


def dex_entropy_from_apk(apk_path: Path) -> List[Dict[str, Any]]:
    """Compute entropy of each classes.dex entry in the APK."""
    results = []
    try:
        with zipfile.ZipFile(apk_path, 'r') as z:
            for name in z.namelist():
                if name.startswith('classes') and name.endswith('.dex'):
                    data = z.read(name)
                    entropy = shannon_entropy(data)
                    results.append({
                        "file": name,
                        "size": len(data),
                        "entropy": round(entropy, 4),
                        "likely_packed": entropy > 7.5,
                    })
    except Exception:
        pass
    return results


def extract_native_strings(apk_path: Path) -> List[Dict[str, Any]]:
    """Extract printable strings from native .so libraries inside the APK."""
    findings = []
    strings_bin = shutil.which("strings")
    if not strings_bin:
        return findings

    try:
        with zipfile.ZipFile(apk_path, 'r') as z:
            for name in z.namelist():
                if not name.endswith('.so'):
                    continue
                try:
                    data = z.read(name)
                    if not data:
                        continue

                    # Run strings on the .so bytes
                    result = subprocess.run(
                        [strings_bin, "-n", "6", "-"],
                        input=data,
                        capture_output=True,
                        timeout=30,
                    )
                    text = result.stdout.decode("utf-8", errors="ignore")
                    lines = text.splitlines()

                    # Extract URLs/IPs/domains
                    artifacts = []
                    for line in lines:
                        for url in URL_RE.findall(line):
                            artifacts.append({"type": "url", "value": url})
                        for ip in IP_RE.findall(line):
                            artifacts.append({"type": "ip", "value": ip})
                        for domain in DOMAIN_RE.findall(line):
                            if '.' in domain and not domain.endswith(('.so', '.c', '.h', '.cpp')):
                                artifacts.append({"type": "domain", "value": domain})

                    # Deduplicate
                    seen = set()
                    unique = []
                    for a in artifacts:
                        key = (a["type"], a["value"])
                        if key not in seen:
                            seen.add(key)
                            unique.append(a)

                    if unique:
                        findings.append({
                            "library": name,
                            "total_strings": len(lines),
                            "artifacts": unique[:20],  # limit
                        })
                except Exception:
                    continue
    except Exception:
        pass
    return findings


def analyze_with_androguard(apk_path: Path) -> Dict[str, Any]:
    """Run Androguard analysis and return obfuscation indicators."""
    try:
        from androguard.misc import AnalyzeAPK
    except ImportError as e:
        raise ObfuscationAnalysisError(f"Androguard not installed: {e}")

    try:
        a, d, dx = AnalyzeAPK(str(apk_path))
    except Exception as e:
        raise ObfuscationAnalysisError(f"Androguard failed to analyze APK: {e}")

    indicators = {
        "reflection": [],
        "dynamic_loading": [],
        "native_loading": [],
        "crypto_apis": [],
        "suspicious_apis": [],
        "dangerous_permissions": [],
        "native_libraries": [],
        "total_classes": 0,
        "total_methods": 0,
    }

    # Permissions
    perms = a.get_permissions() if hasattr(a, 'get_permissions') else []
    for perm in perms:
        for dangerous in DANGEROUS_PERMISSIONS:
            if dangerous in perm:
                indicators["dangerous_permissions"].append(perm)
                break

    # Native libraries declared in manifest/lib dirs
    libs = a.get_libraries() if hasattr(a, 'get_libraries') else []
    indicators["native_libraries"] = list(set(libs))

    # Total classes/methods
    try:
        indicators["total_classes"] = len(dx.get_classes())
        # Androguard 4 returns generators; materialize once for counting + iteration
        methods = list(dx.get_methods())
        indicators["total_methods"] = len(methods)
    except Exception:
        methods = []

    # Analyze methods for obfuscation indicators
    for method in methods:
        try:
            method_name = method.full_name
            if not method_name:
                continue

            for pattern in REFLECTION_PATTERNS:
                if re.search(pattern, method_name):
                    indicators["reflection"].append(method_name)
                    break

            for pattern in DYNAMIC_LOADING_PATTERNS:
                if re.search(pattern, method_name):
                    indicators["dynamic_loading"].append(method_name)
                    break

            for pattern in NATIVE_LOADING_PATTERNS:
                if re.search(pattern, method_name):
                    indicators["native_loading"].append(method_name)
                    break

            for pattern in CRYPTO_PATTERNS:
                if re.search(pattern, method_name):
                    indicators["crypto_apis"].append(method_name)
                    break

            for pattern in SUSPICIOUS_APIS:
                if re.search(pattern, method_name):
                    indicators["suspicious_apis"].append(method_name)
                    break
        except Exception:
            continue

    # Deduplicate and limit
    for key in ["reflection", "dynamic_loading", "native_loading", "crypto_apis", "suspicious_apis"]:
        indicators[key] = list(set(indicators[key]))[:50]
    indicators["dangerous_permissions"] = list(set(indicators["dangerous_permissions"]))

    return indicators


def calculate_obfuscation_score(indicators: Dict[str, Any], dex_entropy: List[Dict[str, Any]]) -> float:
    """Calculate a 0-100 obfuscation score."""
    score = 0.0
    score += min(20, len(indicators.get("reflection", [])) * 2)
    score += min(20, len(indicators.get("dynamic_loading", [])) * 5)
    score += min(10, len(indicators.get("native_loading", [])) * 3)
    score += min(15, len(indicators.get("crypto_apis", [])) * 1.5)
    score += min(15, len(indicators.get("suspicious_apis", [])) * 1.5)
    score += min(10, len(indicators.get("dangerous_permissions", [])) * 2)

    if any(d.get("likely_packed") for d in dex_entropy):
        score += 15

    return round(min(100, score), 2)


def analyze_obfuscation(apk_path: str, work_dir: Optional[str] = None, sample_id: Optional[str] = None) -> Dict[str, Any]:
    """
    Full Step 8: Advanced obfuscation analysis.

    Args:
        apk_path: Path to APK file.
        work_dir: Working directory for intermediate outputs. Defaults to
            settings.WORK_DIR.
        sample_id: Optional sample identifier; falls back to APK filename stem.

    Returns:
        dict with obfuscation indicators, native strings, DEX entropy, and score.
    """
    apk_path = Path(apk_path)
    if sample_id is None:
        sample_id = apk_path.stem
    out_dir = (Path(work_dir) if work_dir else settings.WORK_DIR) / sample_id
    out_dir.mkdir(parents=True, exist_ok=True)

    result = {
        "sample_id": sample_id,
        "obfuscation_score": 0.0,
        "obfuscation_level": "low",
        "indicators": {},
        "dex_entropy": [],
        "native_library_artifacts": [],
        "notes": [],
    }

    # DEX entropy / packing detection
    result["dex_entropy"] = dex_entropy_from_apk(apk_path)

    # Native library strings
    result["native_library_artifacts"] = extract_native_strings(apk_path)

    # Androguard DEX analysis
    try:
        result["indicators"] = analyze_with_androguard(apk_path)
    except Exception as e:
        result["notes"].append(f"Androguard analysis failed: {e}")
        result["indicators"] = {
            "reflection": [],
            "dynamic_loading": [],
            "native_loading": [],
            "crypto_apis": [],
            "suspicious_apis": [],
            "dangerous_permissions": [],
            "native_libraries": [],
            "total_classes": 0,
            "total_methods": 0,
        }

    # Score
    result["obfuscation_score"] = calculate_obfuscation_score(
        result["indicators"], result["dex_entropy"]
    )

    if result["obfuscation_score"] >= 70:
        result["obfuscation_level"] = "high"
    elif result["obfuscation_score"] >= 40:
        result["obfuscation_level"] = "medium"
    else:
        result["obfuscation_level"] = "low"

    # Save intermediate result
    result_path = out_dir / "step8_obfuscation.json"
    with open(result_path, "w", encoding="utf-8") as f:
        json.dump(result, f, indent=2, default=str)

    return result


if __name__ == "__main__":
    import sys
    if len(sys.argv) < 2:
        print("Usage: python step8_obfuscation_analysis.py <apk_path> [work_dir]")
        sys.exit(1)
    apk = sys.argv[1]
    work = sys.argv[2] if len(sys.argv) > 2 else str(settings.WORK_DIR)
    print(json.dumps(analyze_obfuscation(apk, work), indent=2, default=str))
