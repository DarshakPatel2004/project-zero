"""
DroidForensix FastAPI Backend

Provides REST API and WebSocket endpoint for real-time analysis streaming.
"""

import asyncio
import json
import os
from contextlib import asynccontextmanager
from pathlib import Path
from typing import Dict, List, Set

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
