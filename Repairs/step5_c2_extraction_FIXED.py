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


class C2ExtractionError(Exception):
    """Raised when C2 extraction fails."""
    pass


# ---------------------------------------------------------------------------
# Patterns and constants
# ---------------------------------------------------------------------------

URL_RE = re.compile(r'https?://[^\s"\'<>]+', re.IGNORECASE)
IP_RE = re.compile(r'\b(?:(?:25[0-5]|2[0-4]\d|[01]?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d?\d)\b')
DOMAIN_RE = re.compile(r'\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}\b')

# FIX: Benign domain whitelist (prevents false positives like java.sun.com)
BENIGN_DOMAINS = {
    # Java/JRE standard library
    "java.sun.com", "sun.com", "oracle.com", "openjdk.java.net",
    # Android/Google
    "android.com", "google.com", "googleapis.com", "gstatic.com",
    # XML/Web standards
    "w3.org", "w3schools.com", "schemas.android.com", "schemas.microsoft.com",
    "xmlsoap.org", "apache.org",
    # Common frameworks
    "androidx.appcompat", "junit.org", "springframework.io",
    # CDNs and package repos
    "github.com", "githubusercontent.com", "npmjs.com", "pypi.org", "maven.org",
    "dl.google.com",
}

# FIX: Benign DTD/namespace URIs (never actual network requests)
BENIGN_URIS = {
    "http://java.sun.com/dtd/properties.dtd",
    "http://www.w3.org/2000/xmlns",
    "http://www.w3.org/2001/XMLSchema",
    "http://www.w3.org/2001/XMLSchema-instance",
    "http://www.w3.org/1999/xlink",
    "http://www.w3.org/1999/xhtml",
    "http://www.w3.org/2005/Atom",
    "http://www.w3.org/2000/svg",
    "http://java.sun.com/xml/ns/javaee",
    "http://www.springframework.org/schema/beans",
    "http://maven.apache.org/xsd/maven-4.0.0.xsd",
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


def is_benign_domain(url: str) -> bool:
    """FIX: Check if URL is in benign whitelist. Prevents false positives."""
    # Check full URL against URI whitelist
    if url in BENIGN_URIS or any(url.startswith(uri) for uri in BENIGN_URIS):
        return True
    
    # Extract domain
    try:
        parsed = urlparse(url)
        domain = parsed.hostname or parsed.netloc
        if not domain:
            return False
        
        domain_lower = domain.lower()
        
        # Exact match
        if domain_lower in BENIGN_DOMAINS:
            return True
        
        # Suffix match
        for benign in BENIGN_DOMAINS:
            if domain_lower.endswith("." + benign):
                return True
    except:
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
    """FIX: Calculate confidence score for a C2 record.
    
    Fixed to NOT penalize private IPs (VPNs are valid C2 infrastructure).
    Real Metasploit staggers use both public and private C2s."""
    score = 0.5

    # Boost for valid URL structure
    if parsed["protocol"] in ("http", "https"):
        score += 0.2

    # FIX: Boost for ANY IP (public or private), only penalize loopback
    if parsed["ip"]:
        ip_class = classify_ip(parsed["ip"])
        if ip_class in ("public", "private", "vpn"):
            # Both public and private IPs indicate potential C2
            score += 0.25
        elif ip_class == "loopback":
            score -= 0.2
    elif parsed["domain"]:
        # Real domain with TLD
        if "." in parsed["domain"] and len(parsed["domain"].split(".")[-1]) >= 2:
            score += 0.2

    # FIX: Increase boost for non-default path (strong C2 endpoint indicator)
    if parsed["path"] and parsed["path"] != "/":
        score += 0.15

    return round(min(1.0, max(0.0, score)), 4)


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
    work_dir = Path("analysis/work") / sample_id
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

                # FIX: Filter benign domains BEFORE processing
                if is_benign_domain(url):
                    continue

                parsed = parse_url(url)
                if parsed is None:
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

                # FIX: Filter benign domains BEFORE processing
                if is_benign_domain(url):
                    continue

                parsed = parse_url(url)
                if parsed is None:
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
                    # FIX: Keep full confidence (direct URLs in strings are valid)
                    "confidence": round(calculate_c2_confidence(parsed, source_location), 4),
                })
                c2_id += 1

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
