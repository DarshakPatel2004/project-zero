"""
Step 16: APK Signing & Certificate Analysis.

Extracts META-INF/MANIFEST.MF + CERT.RSA from APK ZIP.
Parses certificate fields (issuer, subject, validity, fingerprint),
checks against known-bad certificate databases,
flags self-signed vs organization-signed.

NOTE: KNOWN_BAD_CERTIFICATES is a placeholder pending a real known-bad
cert feed. It ships empty. See audit finding D2 in the threat synthesis
engine plan for the scope of future work needed here.
"""

import hashlib
import logging
import zipfile
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Any, Optional

logger = logging.getLogger(__name__)

# Placeholder -- empty by design, see module docstring.
KNOWN_BAD_CERTIFICATES: Dict[str, str] = {
}

SUSPICIOUS_ISSUERS = [
    "CN=Android Debug", "O=Android", "O=Google Inc.", "CN=Android",
]


def parse_openssl_output(raw: str) -> Dict[str, Any]:
    info = {}
    for line in raw.splitlines():
        line = line.strip()
        if line.startswith("subject=") or line.startswith("Subject:"):
            info["subject"] = line.split("=", 1)[-1].strip() if "=" in line else ""
        elif line.startswith("issuer=") or line.startswith("Issuer:"):
            info["issuer"] = line.split("=", 1)[-1].strip() if "=" in line else ""
        elif "Not Before" in line:
            info["not_before"] = line.split(":", 1)[-1].strip() if ":" in line else ""
        elif "Not After" in line:
            info["not_after"] = line.split(":", 1)[-1].strip() if ":" in line else ""
        elif "SHA-256" in line or "SHA256" in line:
            parts = line.split()
            if len(parts) >= 2:
                info["sha256_fingerprint"] = parts[-1]
    return info


def parse_certificate_from_apk(apk_path: str) -> Optional[Dict[str, Any]]:
    try:
        with zipfile.ZipFile(apk_path, "r") as zf:
            cert_files = [n for n in zf.namelist()
                          if n.startswith("META-INF/") and n.endswith((".RSA", ".DSA", ".EC"))]
            if not cert_files:
                return None
            cert_data = zf.read(cert_files[0])
    except Exception:
        return None

    try:
        from cryptography import x509
        from cryptography.hazmat.backends import default_backend
        from cryptography.hazmat.primitives import hashes

        cert = x509.load_der_x509_certificate(cert_data, default_backend())
        subject = cert.subject.rfc4514_string()
        issuer = cert.issuer.rfc4514_string()

        fingerprint = cert.fingerprint(hashes.SHA256()).hex(":")
        not_before = cert.not_valid_before_utc.isoformat() if hasattr(cert, "not_valid_before_utc") else str(cert.not_valid_before)
        not_after = cert.not_valid_after_utc.isoformat() if hasattr(cert, "not_valid_after_utc") else str(cert.not_valid_after)

        is_self_signed = subject == issuer
        is_debug = "Android Debug" in subject or "Android Debug" in issuer
        days_valid = (cert.not_valid_after_utc - cert.not_valid_before_utc).days if hasattr(cert, "not_valid_after_utc") else 0

        return {
            "subject": subject,
            "issuer": issuer,
            "sha256_fingerprint": fingerprint,
            "not_before": str(not_before),
            "not_after": str(not_after),
            "is_self_signed": is_self_signed,
            "is_debug": is_debug,
            "days_valid": days_valid,
            "serial_number": str(cert.serial_number),
        }
    except ImportError:
        return None
    except Exception as e:
        logger.debug("Certificate parse failed: %s", e)
        return None


def check_known_bad_certificate(fingerprint: str) -> Dict[str, Any]:
    if fingerprint in KNOWN_BAD_CERTIFICATES:
        return {
            "known_bad": True,
            "family": KNOWN_BAD_CERTIFICATES[fingerprint],
            "source": "known_malicious_cert_db",
        }
    return {"known_bad": False}


def analyze_certificate(apk_path: str) -> Dict[str, Any]:
    if not apk_path or not Path(apk_path).exists():
        return {"certificate_found": False, "error": "APK path not provided or does not exist"}

    cert_info = parse_certificate_from_apk(apk_path)
    if not cert_info:
        return {"certificate_found": False, "error": "No certificate found in APK"}

    bad_check = check_known_bad_certificate(cert_info.get("sha256_fingerprint", ""))
    suspicious_issuer = any(
        si in cert_info.get("issuer", "") for si in SUSPICIOUS_ISSUERS
    )

    return {
        "certificate_found": True,
        "certificate": cert_info,
        "known_bad": bad_check["known_bad"],
        "known_bad_family": bad_check.get("family"),
        "suspicious_issuer": suspicious_issuer,
        "warnings": [],
    }
