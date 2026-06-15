"""
Step 5: C2 Infrastructure Extraction

Parses URLs/IPs from decoded payloads and direct source strings into structured
C2 records: protocol, domain, port, path, query params, IP classification,
communication type, and confidence scores.
"""

import ipaddress
import json
import re
import socket
from pathlib import Path
from typing import Dict, List, Any, Optional
from urllib.parse import urlparse, parse_qs

from backend.config import settings

try:
    from backend.circl_client import CIRCLAuthError, CIRCLClient, CIRCLClientError
    CIRCL_AVAILABLE = True
except ImportError:
    CIRCL_AVAILABLE = False


class C2ExtractionError(Exception):
    """Raised when C2 extraction fails."""
    pass


# ---------------------------------------------------------------------------
# Patterns and constants
# ---------------------------------------------------------------------------

URL_RE = re.compile(r'https?://[^\s"\'<>]+', re.IGNORECASE)
IP_RE = re.compile(r'\b(?:(?:25[0-5]|2[0-4]\d|[01]?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d?\d)\b')
DOMAIN_RE = re.compile(r'\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}\b')

# Known benign SDK, documentation, and namespace domains that are not C2.
# These appear frequently in legitimate apps and dilute the C2 signal.
BENIGN_DOMAINS = {
    # Android / Google
    "schemas.android.com",
    "play.google.com",
    "developer.android.com",
    "issuetracker.google.com",
    "maps.google.com",
    "www.googleapis.com",
    "www.google.com",
    "google.com",
    "youtube.com",
    "android.com",
    "www.android.com",
    # W3C / XML
    "www.w3.org",
    "xml.org",
    "xmlpull.org",
    "www.w3.org",
    "xmlns.org",
    # Development platforms / libraries
    "github.com",
    "gitlab.com",
    "bitbucket.org",
    "www.slf4j.org",
    "apache.org",
    "www.apache.org",
    "kotlinlang.org",
    # Adobe / media
    "ns.adobe.com",
    "aomedia.org",
    # JetBrains
    "youtrack.jetbrains.com",
    "developer.apple.com",
    "docs.flutter.dev",
    # Mozilla
    "mozilla.org",
    "www.mozilla.org",
    # Common legitimate app endpoints observed in dataset
    "videolan.org",
    "www.videolan.org",
    "etesync.com",
    "etebase.com",
    "dashboard.etebase.com",
    "api.etebase.com",
    "api.etesync.com",
    "fastmail.com",
    "www.fastmail.com",
    "api.fastmail.com",
    "api.login.aol.com",
    "thunderbird.net",
    "autoconfig.thunderbird.net",
    "jrpn.jovial.com",
    "legacy.jrpn.jovial.com",
    "dmfs.org",
    "schema.dmfs.org",
    "t.me",
    # PDF/file converter services (legitimate, often embedded in readers)
    "cloudconvert.com",
    "www.zamzar.com",
    "zamzar.com",
    "www.pdfrotate.com",
    "pdfrotate.com",
    "smallpdf.com",
    "topdf.com",
    "smaltilpdf.com",
}

BENIGN_URL_PATHS = {
    "/apk/res/android",
    "/apk/res-auto",
}

# Known VPN/proxy ranges (common examples, not exhaustive)
VPN_RANGES = [
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.168.0.0/16"),
]


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def is_valid_ip(ip: str) -> bool:
    """Validate IPv4 address."""
    try:
        socket.inet_aton(ip)
        return True
    except socket.error:
        return False


def is_benign_url(url: str) -> bool:
    """Return True if URL belongs to a known benign SDK/documentation endpoint."""
    try:
        parsed = urlparse(url)
        if parsed.hostname:
            hostname = parsed.hostname.lower().lstrip("www.")
            if hostname in BENIGN_DOMAINS:
                return True
            # Also match any subdomain of a benign domain
            parts = parsed.hostname.lower().split(".")
            for i in range(len(parts)):
                if ".".join(parts[i:]) in BENIGN_DOMAINS:
                    return True
        for benign_path in BENIGN_URL_PATHS:
            if benign_path in parsed.path:
                return True
    except Exception:
        pass
    return False


def classify_ip(ip: str) -> str:
    """Classify IP as private, loopback, vpn, or public."""
    if not is_valid_ip(ip):
        return "invalid"
    try:
        addr = ipaddress.ip_address(ip)
        if addr.is_loopback:
            return "loopback"
        if addr.is_private:
            return "private"
        # Check known VPN ranges (redundant with is_private but explicit)
        for net in VPN_RANGES:
            if addr in net:
                return "vpn"
        return "public"
    except ValueError:
        return "invalid"


def infer_communication_type(url: str, source_location: str) -> str:
    """Infer communication type from URL scheme and source context."""
    parsed = urlparse(url)
    source_lower = source_location.lower()

    if parsed.scheme in ("http", "https"):
        return "http_request"
    if "inetaddress" in source_lower or "dns" in source_lower:
        return "dns_query"
    if "socket" in source_lower:
        return "socket"
    if parsed.scheme in ("tcp", "udp"):
        return parsed.scheme
    return "other"


def parse_url(url: str) -> Optional[Dict[str, Any]]:
    """Parse URL into components."""
    try:
        parsed = urlparse(url)
        if parsed.scheme not in ("http", "https"):
            return None

        domain = parsed.hostname
        ip = None
        if domain:
            # Check if hostname is actually an IP
            if is_valid_ip(domain):
                ip = domain
                domain = None

        port = parsed.port
        if port is None and parsed.scheme == "http":
            port = 80
        elif port is None and parsed.scheme == "https":
            port = 443

        query_params = {k: v[0] if len(v) == 1 else v for k, v in parse_qs(parsed.query).items()}

        return {
            "protocol": parsed.scheme,
            "domain": domain,
            "ip": ip,
            "port": port,
            "path": parsed.path if parsed.path else "/",
            "query_params": query_params,
        }
    except Exception:
        return None


def calculate_c2_confidence(parsed: dict, source_context: str) -> float:
    """Calculate confidence score for a C2 record."""
    score = 0.5

    # Boost for valid URL structure
    if parsed["protocol"] in ("http", "https"):
        score += 0.2

    # Boost for public IP or real domain
    if parsed["ip"]:
        ip_class = classify_ip(parsed["ip"])
        if ip_class == "public":
            score += 0.2
        elif ip_class == "private":
            score -= 0.1
        elif ip_class == "loopback":
            score -= 0.2
    elif parsed["domain"]:
        # Real domain with TLD
        if "." in parsed["domain"] and len(parsed["domain"].split(".")[-1]) >= 2:
            score += 0.2

    # Boost for non-default path (suggests C2 endpoint)
    if parsed["path"] and parsed["path"] != "/":
        score += 0.1

    return round(min(1.0, max(0.0, score)), 4)


def enrich_with_circl(c2_records: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """
    Optionally enrich C2 records with CIRCL pSSL/pDNS data.

    Returns the records unmodified if CIRCL is not configured or the
    enrichment fails.
    """
    if not CIRCL_AVAILABLE:
        return c2_records

    try:
        client = CIRCLClient()
    except CIRCLAuthError:
        # Credentials not configured; skip enrichment silently
        return c2_records

    # CIRCL client expects items with ip/domain/url/cert_sha1 keys
    enrichment_input = []
    for record in c2_records:
        enrichment_input.append({
            "ip": record.get("ip"),
            "domain": record.get("domain"),
            "url": record.get("raw_url"),
            "cert_sha1": record.get("cert_sha1"),
        })

    try:
        enriched = client.enrich_c2_infrastructure(enrichment_input)
    except CIRCLClientError:
        return c2_records

    # Merge CIRCL data back into original records
    for original, circl_data in zip(c2_records, enriched):
        original["circl"] = circl_data.get("circl", {})

    return c2_records


# ---------------------------------------------------------------------------
# Main extraction
# ---------------------------------------------------------------------------


def extract_c2_infrastructure(payloads_result: dict, strings_result: dict) -> dict:
    """
    Full Step 5: Extract C2 infrastructure from payloads and source strings.

    Args:
        payloads_result: Output dict from Step 4.
        strings_result: Output dict from Step 2.

    Returns:
        dict with C2 records.
    """
    sample_id = payloads_result["sample_id"]
    work_dir = settings.WORK_DIR / sample_id
    work_dir.mkdir(parents=True, exist_ok=True)

    c2_records = []
    c2_id = 0
    seen_urls = set()

    # Extract URLs from decoded payloads
    for payload in payloads_result.get("payloads", []):
        payload_id = payload.get("payload_id", "")
        source_location = payload.get("source_location", "unknown")

        for artifact in payload.get("artifacts", []):
            if artifact["type"] == "url":
                url = artifact["value"]
                if url in seen_urls:
                    continue
                seen_urls.add(url)

                parsed = parse_url(url)
                if parsed is None or is_benign_url(url):
                    continue

                c2_records.append({
                    "c2_id": f"c2_{c2_id:03d}",
                    "payload_id": payload_id,
                    "raw_url": url,
                    "protocol": parsed["protocol"],
                    "domain": parsed["domain"],
                    "ip": parsed["ip"],
                    "port": parsed["port"],
                    "path": parsed["path"],
                    "query_params": parsed["query_params"],
                    "ip_classification": classify_ip(parsed["ip"]) if parsed["ip"] else "n/a",
                    "communication_type": infer_communication_type(url, source_location),
                    "is_fallback": False,
                    "source_location": source_location,
                    "confidence": calculate_c2_confidence(parsed, source_location),
                })
                c2_id += 1

    # Also scan source strings directly for URLs not caught by payloads
    for category_name, items in strings_result.get("categories", {}).items():
        for item in items:
            value = item.get("value", "")
            if not isinstance(value, str):
                continue
            source_location = item.get("source", "unknown")

            for url in URL_RE.findall(value):
                if url in seen_urls:
                    continue
                seen_urls.add(url)

                parsed = parse_url(url)
                if parsed is None or is_benign_url(url):
                    continue

                c2_records.append({
                    "c2_id": f"c2_{c2_id:03d}",
                    "payload_id": None,
                    "raw_url": url,
                    "protocol": parsed["protocol"],
                    "domain": parsed["domain"],
                    "ip": parsed["ip"],
                    "port": parsed["port"],
                    "path": parsed["path"],
                    "query_params": parsed["query_params"],
                    "ip_classification": classify_ip(parsed["ip"]) if parsed["ip"] else "n/a",
                    "communication_type": infer_communication_type(url, source_location),
                    "is_fallback": False,
                    "source_location": source_location,
                    "confidence": round(calculate_c2_confidence(parsed, source_location) * 0.9, 4),
                })
                c2_id += 1

    # Optional CIRCL enrichment (pSSL/pDNS) — never fail the pipeline
    c2_records = enrich_with_circl(c2_records)

    result = {
        "sample_id": sample_id,
        "total_c2s": len(c2_records),
        "c2_infrastructure": c2_records,
    }

    # Save intermediate result
    result_path = work_dir / "step5_c2s.json"
    with open(result_path, "w", encoding="utf-8") as f:
        json.dump(result, f, indent=2)

    return result


if __name__ == "__main__":
    import sys
    if len(sys.argv) < 3:
        print("Usage: python step5_c2_extraction.py <step4_payloads.json> <step2_strings.json>")
        sys.exit(1)
    with open(sys.argv[1], "r", encoding="utf-8") as f:
        payloads = json.load(f)
    with open(sys.argv[2], "r", encoding="utf-8") as f:
        strings = json.load(f)
    print(json.dumps(extract_c2_infrastructure(payloads, strings), indent=2))
