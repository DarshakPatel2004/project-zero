"""
DroidForensix FastAPI Backend

Provides REST API and WebSocket endpoint for real-time analysis streaming.
"""

import asyncio
import json
import os
from contextlib import asynccontextmanager
from pathlib import Path
from typing import Dict, List, Optional, Set

from fastapi import FastAPI, WebSocket, WebSocketDisconnect, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel

from analysis.pipeline import run_pipeline
from backend.events import WebSocketEvent, VALID_EVENT_TYPES
from backend.validators import validate_event
from backend.transformers import (
    load_result,
    load_all_results,
    transform_graph,
    transform_clusters,
    transform_timeline,
    transform_samples_list,
)
from backend.dissection import APKDissector, load_dissection


# ---------------------------------------------------------------------------
# State
# ---------------------------------------------------------------------------

class ConnectionManager:
    """Manages active WebSocket connections."""

    def __init__(self):
        self.active_connections: Set[WebSocket] = set()

    async def connect(self, websocket: WebSocket):
        await websocket.accept()
        self.active_connections.add(websocket)

    def disconnect(self, websocket: WebSocket):
        self.active_connections.discard(websocket)

    async def broadcast(self, message: dict):
        """Broadcast message to all connected clients."""
        if not self.active_connections:
            return
        text = json.dumps(message, default=str)
        disconnected = set()
        for connection in self.active_connections:
            try:
                await connection.send_text(text)
            except Exception:
                disconnected.add(connection)
        for conn in disconnected:
            self.disconnect(conn)


manager = ConnectionManager()

# In-memory store for sample results
sample_results: Dict[str, dict] = {}
sample_status: Dict[str, dict] = {}


# ---------------------------------------------------------------------------
# Event emission
# ---------------------------------------------------------------------------

def make_event_emitter(loop: asyncio.AbstractEventLoop):
    """Create a callback that emits pipeline events via WebSocket."""
    def emit(event_type: str, data: dict):
        if event_type not in VALID_EVENT_TYPES:
            return
        event = WebSocketEvent(event_type=event_type, data=data)
        event_dict = event.to_dict()
        if validate_event(event_dict):
            # Schedule broadcast on the event loop
            asyncio.run_coroutine_threadsafe(
                manager.broadcast(event_dict), loop
            )
    return emit


# ---------------------------------------------------------------------------
# Pydantic models
# ---------------------------------------------------------------------------

class AnalyzeRequest(BaseModel):
    apk_path: str


class SampleInfo(BaseModel):
    id: str
    name: str
    status: str
    timestamp: str


# ---------------------------------------------------------------------------
# Lifespan
# ---------------------------------------------------------------------------

@asynccontextmanager
async def lifespan(app: FastAPI):
    # Startup
    Path("analysis/work").mkdir(parents=True, exist_ok=True)
    Path("reports").mkdir(parents=True, exist_ok=True)
    yield
    # Shutdown
    manager.active_connections.clear()


# ---------------------------------------------------------------------------
# App
# ---------------------------------------------------------------------------

app = FastAPI(title="DroidForensix Backend", version="1.0.0", lifespan=lifespan)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:3000"],
    allow_credentials=True,
    allow_methods=["GET", "POST", "OPTIONS"],
    allow_headers=["Content-Type", "Authorization"],
)


# ---------------------------------------------------------------------------
# REST endpoints
# ---------------------------------------------------------------------------

@app.get("/")
async def health_check():
    return {"status": "ok", "version": "1.0.0", "api_prefix": "/api"}


@app.get("/api/samples")
async def api_list_samples() -> dict:
    """List all analyzed samples with summary fields."""
    results = load_all_results()
    samples = transform_samples_list(results)
    return {"samples": samples, "total": len(samples)}


@app.get("/api/sample/{sample_id}")
async def api_get_sample(sample_id: str) -> dict:
    """Get full analysis report for a sample."""
    result = load_result(sample_id)
    if result is None:
        raise HTTPException(status_code=404, detail="Sample not found")
    return result


@app.get("/api/graph/{sample_id}")
async def api_get_graph(sample_id: str) -> dict:
    """Get 3D graph nodes/edges for a sample."""
    result = load_result(sample_id)
    if result is None:
        raise HTTPException(status_code=404, detail="Sample not found")
    return transform_graph(result)


@app.get("/api/clusters")
async def api_get_clusters() -> dict:
    """Get 3D clustering data for all samples."""
    results = load_all_results()
    return transform_clusters(results)


@app.get("/api/timeline/{sample_id}")
async def api_get_timeline(sample_id: str) -> dict:
    """Get timeline/attack-chain progression for a sample."""
    result = load_result(sample_id)
    if result is None:
        raise HTTPException(status_code=404, detail="Sample not found")
    return transform_timeline(result)


# ---------------------------------------------------------------------------
# APK dissection endpoints
# ---------------------------------------------------------------------------

WORK_DIR = Path("analysis/work")


def _get_sample_apk_path(sample_id: str) -> Optional[Path]:
    """Find the original APK path for a sample from its work directory."""
    result = load_result(sample_id)
    if result is None:
        return None
    sample_name = result.get("metadata", {}).get("sample_name")
    if not sample_name:
        return None

    # Fast paths: common locations
    candidates = [
        WORK_DIR / sample_id / sample_name,
        Path("samples") / "malware" / sample_name,
        Path("samples") / "malware" / "androzoo_drebin" / sample_name,
        Path("samples") / "malware" / "bazaar" / sample_name,
        Path("samples") / "malware" / "contagio" / sample_name,
        Path("samples") / "malware" / "github" / sample_name,
        Path("samples") / "malware" / "koodous" / sample_name,
        Path("samples") / "legitimate" / sample_name,
    ]
    for candidate in candidates:
        if candidate.exists():
            return candidate

    # Fallback: recursive search under samples/ (slower but thorough)
    samples_root = Path("samples")
    if samples_root.exists():
        for candidate in samples_root.rglob(sample_name):
            if candidate.is_file():
                return candidate

    return None


@app.get("/api/sample/{sample_id}/dissection")
async def api_get_dissection(sample_id: str) -> dict:
    """Get full dissected APK structure (cached or on-demand)."""
    result = load_result(sample_id)
    if result is None:
        raise HTTPException(status_code=404, detail="Sample not found")

    # Prefer cached dissection.json
    cached = load_dissection(str(WORK_DIR), sample_id)
    if cached is not None:
        return cached

    apk_path = _get_sample_apk_path(sample_id)
    if apk_path is None:
        raise HTTPException(status_code=404, detail="APK file not found for sample")

    try:
        dissector = APKDissector(str(apk_path), work_dir=str(WORK_DIR))
        return dissector.dissect()
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Dissection failed: {e}")


@app.get("/api/sample/{sample_id}/dissection/manifest")
async def api_get_dissection_manifest(sample_id: str) -> dict:
    """Get parsed AndroidManifest.xml."""
    result = load_result(sample_id)
    if result is None:
        raise HTTPException(status_code=404, detail="Sample not found")

    cached = load_dissection(str(WORK_DIR), sample_id)
    if cached is not None:
        return {"manifest": cached.get("manifest", {})}

    apk_path = _get_sample_apk_path(sample_id)
    if apk_path is None:
        raise HTTPException(status_code=404, detail="APK file not found for sample")

    try:
        dissector = APKDissector(str(apk_path), work_dir=str(WORK_DIR))
        return {"manifest": dissector.extract_manifest()}
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Dissection failed: {e}")


@app.get("/api/sample/{sample_id}/dissection/permissions")
async def api_get_dissection_permissions(sample_id: str) -> dict:
    """Get declared permissions with risk levels."""
    result = load_result(sample_id)
    if result is None:
        raise HTTPException(status_code=404, detail="Sample not found")

    cached = load_dissection(str(WORK_DIR), sample_id)
    if cached is not None:
        return {"permissions": cached.get("permissions", [])}

    apk_path = _get_sample_apk_path(sample_id)
    if apk_path is None:
        raise HTTPException(status_code=404, detail="APK file not found for sample")

    try:
        dissector = APKDissector(str(apk_path), work_dir=str(WORK_DIR))
        return {"permissions": dissector.extract_permissions()}
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Dissection failed: {e}")


@app.get("/api/sample/{sample_id}/dissection/components")
async def api_get_dissection_components(sample_id: str) -> dict:
    """Get activities, services, receivers, providers."""
    result = load_result(sample_id)
    if result is None:
        raise HTTPException(status_code=404, detail="Sample not found")

    cached = load_dissection(str(WORK_DIR), sample_id)
    if cached is not None:
        return {"components": cached.get("components", {})}

    apk_path = _get_sample_apk_path(sample_id)
    if apk_path is None:
        raise HTTPException(status_code=404, detail="APK file not found for sample")

    try:
        dissector = APKDissector(str(apk_path), work_dir=str(WORK_DIR))
        return {"components": dissector.extract_components()}
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Dissection failed: {e}")


@app.get("/api/sample/{sample_id}/dissection/dex")
async def api_get_dissection_dex(sample_id: str) -> dict:
    """Get DEX statistics."""
    result = load_result(sample_id)
    if result is None:
        raise HTTPException(status_code=404, detail="Sample not found")

    cached = load_dissection(str(WORK_DIR), sample_id)
    if cached is not None:
        return {"dex_stats": cached.get("dex_stats", {})}

    apk_path = _get_sample_apk_path(sample_id)
    if apk_path is None:
        raise HTTPException(status_code=404, detail="APK file not found for sample")

    try:
        dissector = APKDissector(str(apk_path), work_dir=str(WORK_DIR))
        return {"dex_stats": dissector.extract_dex_stats()}
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Dissection failed: {e}")


@app.get("/api/sample/{sample_id}/dissection/classes")
async def api_get_dissection_classes(sample_id: str) -> dict:
    """Get list of decompiled Java class names."""
    result = load_result(sample_id)
    if result is None:
        raise HTTPException(status_code=404, detail="Sample not found")

    apk_path = _get_sample_apk_path(sample_id)
    if apk_path is None:
        raise HTTPException(status_code=404, detail="APK file not found for sample")

    try:
        dissector = APKDissector(str(apk_path), work_dir=str(WORK_DIR))
        classes = dissector.list_decompiled_classes()
        return {"classes": classes, "total": len(classes)}
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Dissection failed: {e}")


@app.get("/api/sample/{sample_id}/dissection/code/{class_name}")
async def api_get_class_code(sample_id: str, class_name: str) -> dict:
    """Get decompiled source for a specific Java class."""
    result = load_result(sample_id)
    if result is None:
        raise HTTPException(status_code=404, detail="Sample not found")

    apk_path = _get_sample_apk_path(sample_id)
    if apk_path is None:
        raise HTTPException(status_code=404, detail="APK file not found for sample")

    try:
        dissector = APKDissector(str(apk_path), work_dir=str(WORK_DIR))
        code = dissector.read_class_source(class_name)
        if code is None:
            raise HTTPException(status_code=404, detail="Class source not found")
        return {"class_name": class_name, "code": code}
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Dissection failed: {e}")


@app.get("/api/sample/{sample_id}/dissection/strings")
async def api_get_dissection_strings(sample_id: str) -> dict:
    """Get extracted strings from Step 2 result."""
    result = load_result(sample_id)
    if result is None:
        raise HTTPException(status_code=404, detail="Sample not found")

    strings_path = WORK_DIR / sample_id / "step2_strings.json"
    if not strings_path.exists():
        raise HTTPException(status_code=404, detail="Strings not found for sample")

    try:
        with open(strings_path, "r", encoding="utf-8") as f:
            return json.load(f)
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to load strings: {e}")


# Legacy endpoints (kept for backward compatibility)
@app.get("/samples")
async def list_samples() -> dict:
    """List all processed samples (legacy)."""
    return await api_list_samples()


@app.get("/samples/{sample_id}")
async def get_sample(sample_id: str) -> dict:
    """Get analysis result for a sample (legacy)."""
    return await api_get_sample(sample_id)


@app.post("/analyze")
async def analyze(request: AnalyzeRequest) -> dict:
    """Trigger analysis of an APK (REST fallback)."""
    apk_path = request.apk_path
    if not os.path.exists(apk_path):
        raise HTTPException(status_code=400, detail=f"APK not found: {apk_path}")

    loop = asyncio.get_event_loop()

    def run_analysis():
        emitter = make_event_emitter(loop)
        return run_pipeline(apk_path, event_emitter=emitter)

    # Run pipeline in thread pool to avoid blocking
    task = asyncio.create_task(loop.run_in_executor(None, run_analysis))

    return {"message": "Analysis started", "task": str(task)}


# ---------------------------------------------------------------------------
# WebSocket endpoint
# ---------------------------------------------------------------------------

@app.websocket("/ws")
async def websocket_endpoint(websocket: WebSocket):
    await manager.connect(websocket)
    try:
        while True:
            # Receive client messages (ping/subscribe)
            data = await websocket.receive_text()
            try:
                message = json.loads(data)
                action = message.get("action")
                if action == "ping":
                    await websocket.send_text(json.dumps({"event_type": "pong", "timestamp": ""}))
            except json.JSONDecodeError:
                pass
    except WebSocketDisconnect:
        manager.disconnect(websocket)
    except Exception:
        manager.disconnect(websocket)


if __name__ == "__main__":
    import uvicorn
    uvicorn.run("backend.main:app", host="0.0.0.0", port=8000, reload=True)
