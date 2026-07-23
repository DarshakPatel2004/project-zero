import logging
from typing import Dict, Any, List, Optional
from urllib.parse import urlparse

from analysis.dynamic.config import settings

logger = logging.getLogger(__name__)


def _extract_domain(url: str) -> Optional[str]:
    try:
        parsed = urlparse(url)
        host = parsed.hostname
        if host:
            return host.lower().strip()
    except Exception:
        pass
    return None


def _extract_port(url: str) -> Optional[int]:
    try:
        parsed = urlparse(url)
        return parsed.port
    except Exception:
        return None


def _c2_key(c2: Dict[str, Any]) -> tuple:
    domain = (c2.get("domain") or "").lower().strip()
    ip = (c2.get("ip") or "").strip()
    port = c2.get("port") or 0
    host = domain or ip
    return (host, port)


def correlate(
    static_c2_list: List[Dict[str, Any]],
    dynamic_events: Dict[str, List[Dict[str, Any]]],
) -> Dict[str, Any]:
    if not static_c2_list:
        static_c2_list = []
    if not dynamic_events:
        dynamic_events = {}

    validated = []
    contradicted = []
    new_candidates = []
    decisions = []

    static_index: Dict[tuple, Any] = {}
    static_keys: set = set()
    for c2 in static_c2_list:
        key = _c2_key(c2)
        static_index[key] = c2
        static_keys.add(key)

    dynamic_urls = dynamic_events.get("url_openconnection", [])
    seen_dynamic = set()

    for event in dynamic_urls:
        data = event.get("data", {})
        url = data.get("url", "")
        host = data.get("host", "") or (_extract_domain(url) or "")
        port = data.get("port", 0) or (_extract_port(url) or 0)
        if not host:
            continue
        key = (host.lower().strip(), port)
        if key in seen_dynamic:
            continue
        seen_dynamic.add(key)

        if key in static_keys:
            validated.append({
                "domain": host,
                "port": port,
                "url": url,
                "static_confidence": static_index[key].get("confidence", 0.5),
                "dynamic_multiplier": settings.CONFIDENCE_MULTIPLIER_VALIDATED,
                "new_confidence": min(
                    1.0,
                    (static_index[key].get("confidence", 0.5)
                     * settings.CONFIDENCE_MULTIPLIER_VALIDATED),
                ),
            })
            decisions.append(
                f"VALIDATED C2 {host}:{port} — static candidate confirmed by "
                f"runtime URL.openConnection call"
            )
        else:
            certainty = 0.7
            if certainty >= settings.NEW_C2_CONFIDENCE_THRESHOLD:
                new_candidates.append({
                    "domain": host,
                    "port": port,
                    "url": url,
                    "certainty": certainty,
                    "source": "dynamic_only",
                    "needs_review": certainty < 0.95,
                })
                decisions.append(
                    f"NEW C2 CANDIDATE {host}:{port} — observed at runtime, "
                    f"not in static extraction (certainty: {certainty})"
                )

    for key, c2 in static_index.items():
        if key not in seen_dynamic and c2.get("confidence", 0.5) > 0.5:
            contradicted.append({
                "domain": key[0],
                "port": key[1],
                "static_confidence": c2.get("confidence", 0.5),
                "dynamic_multiplier": settings.CONFIDENCE_MULTIPLIER_CONTRADICTED,
                "new_confidence": max(
                    0.1,
                    c2.get("confidence", 0.5)
                    * settings.CONFIDENCE_MULTIPLIER_CONTRADICTED,
                ),
            })
            decisions.append(
                f"CONTRADICTED C2 {key[0]}:{key[1]} — static candidate NOT "
                f"observed at runtime, confidence reduced"
            )

    c2_boost_count = len(validated)
    c2_downgrade_count = len(contradicted)
    new_c2_found = len(new_candidates)

    return {
        "c2_validated": validated,
        "c2_contradicted": contradicted,
        "new_c2_candidates": new_candidates,
        "decisions": decisions,
        "confidence_impact": {
            "c2_boost_count": c2_boost_count,
            "c2_downgrade_count": c2_downgrade_count,
            "new_c2_found": new_c2_found,
            "net_impact": c2_boost_count - c2_downgrade_count,
        },
    }
