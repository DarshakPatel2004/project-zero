import json
import logging
import time
from typing import Dict, Any, List, Optional

from analysis.dynamic.config import settings

logger = logging.getLogger(__name__)


class CaptureResult:
    def __init__(self):
        self.events: List[Dict[str, Any]] = []
        self.byte_count: int = 0
        self.line_count: int = 0
        self.truncated: bool = False
        self.parse_errors: int = 0
        self.last_event_time: float = time.time()
        self.artifacts: Dict[str, List[Dict[str, Any]]] = {
            "method_invoke": [],
            "url_openconnection": [],
            "string_init_bytes": [],
            "string_init_charset": [],
            "cipher_dofinal": [],
            "classloader_loadclass": [],
            "dexclassloader_init": [],
            "unknown": [],
        }

    def to_dict(self) -> Dict[str, Any]:
        return {
            "total_events": len(self.events),
            "byte_count": self.byte_count,
            "line_count": self.line_count,
            "truncated": self.truncated,
            "parse_errors": self.parse_errors,
            "last_event_delta_seconds": round(time.time() - self.last_event_time, 1),
            "artifact_summary": {
                hook_type: len(items)
                for hook_type, items in self.artifacts.items()
            },
        }


def _classify_hook(hook_type: str) -> str:
    mapping = {
        "method_invoke": "method_invoke",
        "url_openconnection": "url_openconnection",
        "string_init_bytes": "string_init_bytes",
        "string_init_charset": "string_init_charset",
        "cipher_dofinal": "cipher_dofinal",
        "classloader_loadclass": "classloader_loadclass",
        "dexclassloader_init": "dexclassloader_init",
    }
    return mapping.get(hook_type, "unknown")


def parse_line(line: str, result: CaptureResult) -> Optional[Dict[str, Any]]:
    line = line.strip()
    if not line:
        return None

    result.line_count += 1
    result.byte_count += len(line.encode("utf-8"))

    if result.byte_count > settings.MAX_OUTPUT_BYTES:
        result.truncated = True
        return None

    if result.line_count > settings.MAX_OUTPUT_LINES:
        result.truncated = True
        return None

    try:
        data = json.loads(line)
    except json.JSONDecodeError:
        result.parse_errors += 1
        return None

    hook_type = data.get("hook", "unknown")
    classification = _classify_hook(hook_type)

    payload = {
        "hook": hook_type,
        "ts": data.get("ts", int(time.time() * 1000)),
        "data": data.get("data", {}),
    }

    result.events.append(payload)
    result.last_event_time = time.time()
    result.artifacts[classification].append(payload)

    return payload


def check_idle_timeout(result: CaptureResult, timeout: int = None) -> bool:
    timeout = timeout or settings.IDLE_TIMEOUT
    elapsed = time.time() - result.last_event_time
    if elapsed > timeout:
        logger.debug(
            "Capture idle for %.1fs (timeout: %ds)",
            elapsed, timeout,
        )
        return True
    return False
