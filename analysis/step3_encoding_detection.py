"""
Step 3: Encoding Detection & Classification

Detects Base64, URL-safe Base64, hex, XOR, and suspected custom encoding
in enumerated strings. Assigns confidence scores based on alphabet match,
decode success, meaningful output, and entropy alignment.
"""

import base64
import binascii
import json
import math
import re
from pathlib import Path
from typing import Dict, List, Any, Optional, Tuple


class EncodingDetectionError(Exception):
    """Raised when encoding detection fails."""
    pass


# ---------------------------------------------------------------------------
# Patterns and constants
# ---------------------------------------------------------------------------

BASE64_RE = re.compile(r'[A-Za-z0-9+/]{20,}={0,2}')
BASE64_URLSAFE_RE = re.compile(r'[A-Za-z0-9_-]{20,}')
HEX_RE = re.compile(r'[0-9A-Fa-f]{16,}')

URL_RE = re.compile(r'https?://[^\s"\']+', re.IGNORECASE)
IP_RE = re.compile(r'\b(?:\d{1,3}\.){3}\d{1,3}\b')
DOMAIN_RE = re.compile(r'\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}\b')
EMAIL_RE = re.compile(r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}')

HIGH_ENTROPY_THRESHOLD = 5.0
CUSTOM_ENCODING_THRESHOLD = 7.0
XOR_PRINTABLE_THRESHOLD = 0.70


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def shannon_entropy(data: bytes) -> float:
    """Calculate Shannon entropy."""
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


def is_printable_ratio(data: bytes) -> float:
    """Return ratio of printable ASCII bytes."""
    if not data:
        return 0.0
    printable = sum(1 for b in data if 32 <= b <= 126 or b in (9, 10, 13))
    return printable / len(data)


def has_meaningful_content(text: str) -> bool:
    """Check if decoded text contains URLs, IPs, domains, or emails."""
    if URL_RE.search(text):
        return True
    if IP_RE.search(text):
        return True
    if DOMAIN_RE.search(text):
        return True
    if EMAIL_RE.search(text):
        return True
    return False


def looks_like_base64(s: str) -> bool:
    """Check if string looks like valid Base64."""
    if len(s) < 4:
        return False
    # Standard Base64 length multiple of 4 (with padding)
    if len(s) % 4 != 0 and not s.endswith('='):
        return False
    # Character set
    allowed = set("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/=")
    if not set(s).issubset(allowed):
        return False
    return True


def looks_like_urlsafe_base64(s: str) -> bool:
    """Check if string looks like URL-safe Base64."""
    if len(s) < 4:
        return False
    allowed = set("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_")
    if not set(s).issubset(allowed):
        return False
    return True


def looks_like_hex(s: str) -> bool:
    """Check if string looks like hex."""
    if len(s) < 4 or len(s) % 2 != 0:
        return False
    allowed = set("0123456789ABCDEFabcdef")
    return set(s).issubset(allowed)


# ---------------------------------------------------------------------------
# Decoders
# ---------------------------------------------------------------------------


def try_base64_decode(s: str) -> Optional[str]:
    """Try decoding standard Base64."""
    try:
        decoded = base64.b64decode(s, validate=True)
        try:
            return decoded.decode("utf-8")
        except UnicodeDecodeError:
            return decoded.hex()
    except Exception:
        return None


def try_urlsafe_base64_decode(s: str) -> Optional[str]:
    """Try decoding URL-safe Base64."""
    try:
        # Add padding if needed
        padding = 4 - len(s) % 4
        if padding != 4:
            s += '=' * padding
        decoded = base64.urlsafe_b64decode(s)
        try:
            return decoded.decode("utf-8")
        except UnicodeDecodeError:
            return decoded.hex()
    except Exception:
        return None


def try_hex_decode(s: str) -> Optional[str]:
    """Try decoding hex string."""
    try:
        decoded = binascii.unhexlify(s)
        try:
            return decoded.decode("utf-8")
        except UnicodeDecodeError:
            return decoded.hex()
    except Exception:
        return None


def _has_strong_meaningful_content(text: str) -> bool:
    """Check for strong indicators: URLs, IPs, or emails (domains alone are too noisy for XOR)."""
    if URL_RE.search(text):
        return True
    if IP_RE.search(text):
        return True
    if EMAIL_RE.search(text):
        return True
    return False


def xor_brute_force(data: bytes) -> List[Tuple[int, str, float]]:
    """Brute-force XOR keys 1-255, return top candidates with printable ratio.

    Key 0 is excluded because XOR with 0 is identity and would always
    match printable inputs, producing false positives.
    """
    candidates = []
    for key in range(1, 256):
        decrypted = bytes(b ^ key for b in data)
        ratio = is_printable_ratio(decrypted)
        if ratio >= XOR_PRINTABLE_THRESHOLD:
            try:
                text = decrypted.decode("utf-8", errors="ignore")
                score = ratio
                # Strongly boost candidates that produce strong meaningful content
                if _has_strong_meaningful_content(text):
                    score += 0.30
                candidates.append((key, text, score))
            except Exception:
                pass
    # Sort by score descending, return top 3
    candidates.sort(key=lambda x: x[2], reverse=True)
    return candidates[:3]


# ---------------------------------------------------------------------------
# Confidence scoring
# ---------------------------------------------------------------------------


def calculate_confidence(alphabet_match: float, decode_success: float,
                         meaningful: float, entropy_alignment: float) -> float:
    """Weighted confidence score."""
    score = (alphabet_match * 0.3 + decode_success * 0.3 +
             meaningful * 0.2 + entropy_alignment * 0.2)
    return round(min(1.0, max(0.0, score)), 4)


# ---------------------------------------------------------------------------
# Main detection
# ---------------------------------------------------------------------------


def detect_encoding(strings_result: dict) -> dict:
    """
    Full Step 3: Detect encodings in enumerated strings.

    Args:
        strings_result: Output dict from Step 2.

    Returns:
        dict with detected encodings.
    """
    sample_id = strings_result["sample_id"]
    work_dir = Path("analysis/work") / sample_id
    work_dir.mkdir(parents=True, exist_ok=True)

    encodings = []
    encoding_id = 0

    # Flatten all strings to process
    all_strings = []
    categories = strings_result.get("categories", {})
    for category_name, items in categories.items():
        for item in items:
            value = item.get("value", "")
            if isinstance(value, str) and len(value) >= 8:
                all_strings.append({
                    "value": value,
                    "source": item.get("source", "unknown"),
                    "entropy": item.get("entropy", 0.0),
                    "category": category_name,
                })

    # Deduplicate by value
    seen_values = set()
    unique_strings = []
    for s in all_strings:
        if s["value"] not in seen_values:
            seen_values.add(s["value"])
            unique_strings.append(s)

    for s in unique_strings:
        value = s["value"]
        entropy = s.get("entropy", 0.0)
        source = s.get("source", "unknown")

        # Remove quotes/whitespace that might surround encoded data
        clean = value.strip().strip('"').strip("'")
        if len(clean) < 8:
            continue

        # Try Base64
        if BASE64_RE.search(clean) and looks_like_base64(clean):
            decoded = try_base64_decode(clean)
            if decoded is not None:
                meaningful = 1.0 if has_meaningful_content(decoded) else 0.3
                encodings.append({
                    "encoding_id": f"enc_{encoding_id:03d}",
                    "type": "base64",
                    "original_string": clean,
                    "confidence": calculate_confidence(1.0, 1.0, meaningful,
                                                        0.8 if 3.0 < entropy < 6.0 else 0.5),
                    "entropy": entropy,
                    "source_location": source,
                    "decoded_preview": decoded[:200],
                    "validation_status": "valid" if meaningful > 0.5 else "uncertain",
                })
                encoding_id += 1
                continue

        # Try Hex (before URL-safe Base64 because hex strings also match URL-safe B64 regex)
        if HEX_RE.search(clean) and looks_like_hex(clean):
            decoded = try_hex_decode(clean)
            if decoded is not None:
                meaningful = 1.0 if has_meaningful_content(decoded) else 0.3
                encodings.append({
                    "encoding_id": f"enc_{encoding_id:03d}",
                    "type": "hex",
                    "original_string": clean,
                    "confidence": calculate_confidence(1.0, 1.0, meaningful,
                                                        0.8 if 2.0 < entropy < 5.0 else 0.5),
                    "entropy": entropy,
                    "source_location": source,
                    "decoded_preview": decoded[:200],
                    "validation_status": "valid" if meaningful > 0.5 else "uncertain",
                })
                encoding_id += 1
                continue

        # Try URL-safe Base64
        if BASE64_URLSAFE_RE.search(clean) and looks_like_urlsafe_base64(clean):
            decoded = try_urlsafe_base64_decode(clean)
            if decoded is not None:
                meaningful = 1.0 if has_meaningful_content(decoded) else 0.3
                encodings.append({
                    "encoding_id": f"enc_{encoding_id:03d}",
                    "type": "base64_urlsafe",
                    "original_string": clean,
                    "confidence": calculate_confidence(1.0, 1.0, meaningful, 0.7),
                    "entropy": entropy,
                    "source_location": source,
                    "decoded_preview": decoded[:200],
                    "validation_status": "valid" if meaningful > 0.5 else "uncertain",
                })
                encoding_id += 1
                continue

        # XOR brute-force for high-entropy strings
        if entropy > HIGH_ENTROPY_THRESHOLD:
            try:
                # Use latin-1 to preserve byte values for XOR analysis
                data = clean.encode("latin-1", errors="ignore")
                if len(data) >= 8:
                    candidates = xor_brute_force(data)
                    if candidates:
                        best_key, best_text, best_score = candidates[0]
                        meaningful = 1.0 if has_meaningful_content(best_text) else 0.4
                        encodings.append({
                            "encoding_id": f"enc_{encoding_id:03d}",
                            "type": "xor",
                            "original_string": clean,
                            "confidence": calculate_confidence(0.7, 0.9 if best_score > 0.8 else 0.6,
                                                                meaningful, 0.8),
                            "entropy": entropy,
                            "source_location": source,
                            "decoded_preview": best_text[:200],
                            "xor_key": best_key,
                            "xor_printable_ratio": round(best_score, 4),
                            "validation_status": "valid" if meaningful > 0.5 else "uncertain",
                        })
                        encoding_id += 1
                        continue
            except Exception:
                pass

        # Custom encoding flag for very high entropy failures
        if entropy > CUSTOM_ENCODING_THRESHOLD:
            encodings.append({
                "encoding_id": f"enc_{encoding_id:03d}",
                "type": "custom",
                "original_string": clean,
                "confidence": 0.4,
                "entropy": entropy,
                "source_location": source,
                "decoded_preview": "",
                "validation_status": "uncertain",
            })
            encoding_id += 1

    result = {
        "sample_id": sample_id,
        "total_encodings": len(encodings),
        "encodings": encodings,
    }

    # Save intermediate result
    result_path = work_dir / "step3_encodings.json"
    with open(result_path, "w", encoding="utf-8") as f:
        json.dump(result, f, indent=2)

    return result


if __name__ == "__main__":
    import sys
    if len(sys.argv) < 2:
        print("Usage: python step3_encoding_detection.py <step2_strings.json>")
        sys.exit(1)
    with open(sys.argv[1], "r", encoding="utf-8") as f:
        strings_data = json.load(f)
    print(json.dumps(detect_encoding(strings_data), indent=2))
