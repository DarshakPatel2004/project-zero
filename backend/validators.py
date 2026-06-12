"""
JSON schema validation for backend events and API payloads.
"""

from typing import Any, Dict

from pydantic import BaseModel, Field, field_validator


class AnalyzeRequest(BaseModel):
    """Request body for POST /analyze."""
    apk_path: str = Field(..., min_length=1)


class SampleStatus(BaseModel):
    """Sample status response."""
    id: str
    name: str
    status: str
    timestamp: str


class WebSocketEventValidator(BaseModel):
    """Validator for WebSocket events emitted by the pipeline."""
    event_type: str
    timestamp: str
    data: Dict[str, Any]

    @field_validator("event_type")
    @classmethod
    def validate_event_type(cls, v: str) -> str:
        from backend.events import VALID_EVENT_TYPES
        if v not in VALID_EVENT_TYPES:
            raise ValueError(f"Invalid event type: {v}")
        return v


def validate_event(event: dict) -> bool:
    """Validate a WebSocket event dict."""
    try:
        WebSocketEventValidator(**event)
        return True
    except Exception:
        return False
