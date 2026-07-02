"""
Step 14: Network Protocol Analysis.

Extracts network endpoints from raw strings, classifies them as benign,
suspicious, or C2 based on IP, port, path, and domain characteristics.
"""

import ipaddress
import logging
import re
from typing import Any, Dict, List
from urllib.parse import urlparse

logger = logging.getLogger(__name__)

BENIGN_DOMAINS = {
    "google.com",
    "github.com",
    "developer.android.com",
    "android.com",
}

SUSPICIOUS_PORTS = {4444, 1337, 8080, 8443}

SUSPICIOUS_PATHS = {"/gate", "/command", "/admin", "/panel"}

URL_RE = re.compile(r'https?://[^\s"\'<>]+', re.IGNORECASE)

IP_RE = re.compile(
    r"(?:(?:25[0-5]|2[0-4]\d|[01]?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d?\d)"
)


def _is_private_ip(ip_str: str) -> bool:
    try:
        return ipaddress.ip_address(ip_str).is_private
    except ValueError:
        return False


def _extract_endpoint(url: str) -> Dict[str, Any]:
    parsed = urlparse(url)
    hostname = parsed.hostname or ""  # type: ignore
    domain = None
    ip = None

    if IP_RE.fullmatch(hostname):
        ip = hostname
    elif hostname:
        domain = hostname

    port = parsed.port
    if port is None:
        port = 443 if parsed.scheme == "https" else 80

    path = parsed.path if parsed.path else "/"

    return {
        "url": url,
        "ip": ip,
        "domain": domain,
        "port": port,
        "path": path,
        "is_c2": False,
        "is_suspicious": False,
    }


def _is_benign_domain(domain: str) -> bool:
    domain_lower = domain.lower()
    parts = domain_lower.split(".")
    for i in range(len(parts)):
        if ".".join(parts[i:]) in BENIGN_DOMAINS:
            return True
    return False


def _classify_endpoint(endpoint: Dict[str, Any]) -> Dict[str, Any]:
    domain = endpoint["domain"]
    ip = endpoint["ip"]
    port = endpoint["port"]
    path = endpoint["path"]

    if domain and _is_benign_domain(domain):
        return endpoint

    is_private = bool(ip and _is_private_ip(ip))
    port_suspicious = port in SUSPICIOUS_PORTS
    path_suspicious = any(
        path == sp or path.startswith(sp + "/") for sp in SUSPICIOUS_PATHS
    )

    endpoint["is_suspicious"] = port_suspicious or path_suspicious

    if (is_private or domain) and port_suspicious and path_suspicious:
        endpoint["is_c2"] = True

    return endpoint


def analyze_network_protocols(strings: List[str]) -> Dict[str, Any]:
    if not strings:
        return {
            "total_endpoints": 0,
            "total_c2": 0,
            "total_suspicious": 0,
            "endpoints": [],
            "c2_endpoints": [],
        }

    seen_urls: set = set()
    endpoints: list = []

    for s in strings:
        for url in URL_RE.findall(s):
            url_clean = url.strip().rstrip(".,;:!?')")
            if url_clean in seen_urls:
                continue
            seen_urls.add(url_clean)
            endpoint = _extract_endpoint(url_clean)
            endpoint = _classify_endpoint(endpoint)
            endpoints.append(endpoint)

    c2_endpoints = [e for e in endpoints if e["is_c2"]]

    return {
        "total_endpoints": len(endpoints),
        "total_c2": len(c2_endpoints),
        "total_suspicious": sum(1 for e in endpoints if e["is_suspicious"]),
        "endpoints": endpoints,
        "c2_endpoints": c2_endpoints,
    }
