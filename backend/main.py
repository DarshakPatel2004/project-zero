"""
DroidForensix FastAPI Backend

Provides REST API and WebSocket endpoint for real-time analysis streaming.
"""

import asyncio
import json
from contextlib import asynccontextmanager
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, List, Optional, Set

from fastapi import FastAPI, WebSocket, WebSocketDisconnect, HTTPException, UploadFile, File, Form
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse, PlainTextResponse, Response
from pydantic import BaseModel
import hashlib
import subprocess
import uuid

from analysis.pipeline import run_pipeline
from analysis.step7_llm_assessment import explain_method
from backend.pdf_report import generate_report
from backend.config import settings
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
from backend import threat_intel as ti
from backend.family_id import identify_family
from backend.obfuscation_view import build_obfuscation_view, deobfuscate_text


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

# In-memory store for upload -> sample mapping and analysis status
upload_registry: Dict[str, dict] = {}
sample_status: Dict[str, dict] = {}


# ---------------------------------------------------------------------------
# Event emission
# ---------------------------------------------------------------------------

def make_event_emitter(loop: asyncio.AbstractEventLoop):
    """Create a callback that emits pipeline events via WebSocket."""
    def emit(event_type: str, data: dict):
        print(f"[EMITTER] {event_type} connections={len(manager.active_connections)}")
        if event_type not in VALID_EVENT_TYPES:
            print(f"[EMITTER] invalid type {event_type}")
            return
        event = WebSocketEvent(event_type=event_type, data=data)
        event_dict = event.to_dict()
        print(f"[EMITTER] event_dict valid={validate_event(event_dict)}")
        if validate_event(event_dict):
            # Schedule broadcast on the event loop
            fut = asyncio.run_coroutine_threadsafe(
                manager.broadcast(event_dict), loop
            )
            fut.add_done_callback(lambda f: print(f"[EMITTER] broadcast done err={f.exception()}"))
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
    settings.WORK_DIR.mkdir(parents=True, exist_ok=True)
    settings.REPORTS_DIR.mkdir(parents=True, exist_ok=True)
    settings.SAMPLES_DIR.mkdir(parents=True, exist_ok=True)
    settings.UPLOADS_DIR.mkdir(parents=True, exist_ok=True)
    yield
    # Shutdown
    manager.active_connections.clear()


# ---------------------------------------------------------------------------
# App
# ---------------------------------------------------------------------------

app = FastAPI(title="DroidForensix Backend", version="1.0.0", lifespan=lifespan)

app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.CORS_ORIGINS + [settings.FRONTEND_URL],
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

WORK_DIR = settings.WORK_DIR


def _get_sample_apk_path(sample_id: str) -> Optional[Path]:
    """Find the original APK path for a sample from its work directory."""
    result = load_result(sample_id)
    if result is None:
        return None

    # Prefer the exact path recorded during analysis.
    recorded_apk = result.get("metadata", {}).get("apk_path")
    if recorded_apk and Path(recorded_apk).exists():
        return Path(recorded_apk)

    sample_name = result.get("metadata", {}).get("sample_name")
    if not sample_name:
        return None

    # Fast paths: common locations
    candidates = [
        WORK_DIR / sample_id / sample_name,
        settings.UPLOADS_DIR / sample_id / sample_name,
        settings.UPLOADS_DIR / sample_id / "file.apk",
        settings.SAMPLES_DIR / "malware" / sample_name,
        settings.SAMPLES_DIR / "malware" / "androzoo_drebin" / sample_name,
        settings.SAMPLES_DIR / "malware" / "bazaar" / sample_name,
        settings.SAMPLES_DIR / "malware" / "contagio" / sample_name,
        settings.SAMPLES_DIR / "malware" / "github" / sample_name,
        settings.SAMPLES_DIR / "malware" / "koodous" / sample_name,
        settings.SAMPLES_DIR / "legitimate" / sample_name,
    ]
    for candidate in candidates:
        if candidate.exists():
            return candidate

    # Fallback: recursive search under samples/ and uploads/ (slower but thorough)
    for base_dir in (settings.SAMPLES_DIR, settings.UPLOADS_DIR):
        if base_dir.exists():
            for candidate in base_dir.rglob(sample_name):
                if candidate.is_file():
                    return candidate
            for candidate in base_dir.rglob("file.apk"):
                if candidate.is_file():
                    return candidate

    return None


def _get_or_create_dissection(sample_id: str) -> dict:
    """Return cached dissection.json or generate and cache it."""
    cached = load_dissection(str(WORK_DIR), sample_id)
    if cached is not None:
        return cached

    apk_path = _get_sample_apk_path(sample_id)
    if apk_path is None:
        raise HTTPException(status_code=404, detail="APK file not found for sample")

    try:
        dissector = APKDissector(str(apk_path), work_dir=str(WORK_DIR))
        data = dissector.dissect()
        # Cache for future requests
        dissection_path = WORK_DIR / sample_id / "dissection.json"
        try:
            with open(dissection_path, "w", encoding="utf-8") as f:
                json.dump(data, f, indent=2, default=str)
        except Exception:
            pass
        return data
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Dissection failed: {e}")


@app.get("/api/sample/{sample_id}/dissection")
async def api_get_dissection(sample_id: str) -> dict:
    """Get full dissected APK structure (cached or on-demand)."""
    result = load_result(sample_id)
    if result is None:
        raise HTTPException(status_code=404, detail="Sample not found")

    return _get_or_create_dissection(sample_id)


@app.get("/api/sample/{sample_id}/dissection/manifest")
async def api_get_dissection_manifest(sample_id: str) -> dict:
    """Get parsed AndroidManifest.xml."""
    result = load_result(sample_id)
    if result is None:
        raise HTTPException(status_code=404, detail="Sample not found")

    data = _get_or_create_dissection(sample_id)
    return {"manifest": data.get("manifest", {})}


@app.get("/api/sample/{sample_id}/dissection/permissions")
async def api_get_dissection_permissions(sample_id: str) -> dict:
    """Get declared permissions with risk levels."""
    result = load_result(sample_id)
    if result is None:
        raise HTTPException(status_code=404, detail="Sample not found")

    data = _get_or_create_dissection(sample_id)
    return {"permissions": data.get("permissions", [])}


@app.get("/api/sample/{sample_id}/dissection/components")
async def api_get_dissection_components(sample_id: str) -> dict:
    """Get activities, services, receivers, providers."""
    result = load_result(sample_id)
    if result is None:
        raise HTTPException(status_code=404, detail="Sample not found")

    data = _get_or_create_dissection(sample_id)
    return {"components": data.get("components", {})}


@app.get("/api/sample/{sample_id}/dissection/dex")
async def api_get_dissection_dex(sample_id: str) -> dict:
    """Get DEX statistics."""
    result = load_result(sample_id)
    if result is None:
        raise HTTPException(status_code=404, detail="Sample not found")

    data = _get_or_create_dissection(sample_id)
    return {"dex_stats": data.get("dex_stats", {})}


@app.get("/api/sample/{sample_id}/dissection/classes")
async def api_get_dissection_classes(sample_id: str) -> dict:
    """Get list of decompiled Java class names."""
    result = load_result(sample_id)
    if result is None:
        raise HTTPException(status_code=404, detail="Sample not found")

    extraction = result.get("extraction", {})
    if not extraction.get("jadx_success"):
        errors = extraction.get("errors", ["JADX decompilation failed"])
        return {
            "classes": [],
            "total": 0,
            "error": "JADX decompilation not available",
            "details": errors,
            "jadx_success": False,
        }

    apk_path = _get_sample_apk_path(sample_id)
    if apk_path is None:
        raise HTTPException(status_code=404, detail="APK file not found for sample")

    # Cache parsed classes to disk — parsing 1500+ files is expensive
    cache_path = WORK_DIR / sample_id / "dissection_classes_cache.json"
    if cache_path.exists():
        try:
            with open(cache_path, "r", encoding="utf-8") as f:
                cached = json.load(f)
            return {"classes": cached, "total": len(cached), "jadx_success": True, "cached": True}
        except Exception:
            pass  # Cache corrupt, rebuild below

    try:
        dissector = APKDissector(str(apk_path), work_dir=str(WORK_DIR))
        import asyncio
        loop = asyncio.get_event_loop()
        classes = await loop.run_in_executor(None, dissector.list_decompiled_class_objects)
        # Write cache
        try:
            with open(cache_path, "w", encoding="utf-8") as f:
                json.dump(classes, f)
        except Exception:
            pass  # Cache write failure is non-fatal
        return {"classes": classes, "total": len(classes), "jadx_success": True}
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


# ---------------------------------------------------------------------------
# Threat intelligence endpoints (Phase 2 enrichment + family identification)
# ---------------------------------------------------------------------------

@app.get("/api/sample/{sample_id}/threat-intel")
async def api_get_threat_intel(sample_id: str) -> dict:
    """Aggregated C2 threat-intel: DNS status, classification, geo, and family."""
    result = load_result(sample_id)
    if result is None:
        raise HTTPException(status_code=404, detail="Sample not found")

    data = ti.build_threat_intel(result, sample_id)
    try:
        data["family"] = identify_family(sample_id, result)
    except Exception as e:  # family ID must never break the dashboard
        data["family"] = {"family": "unknown", "confidence": 0.0,
                          "method": "error", "reasoning": str(e), "candidates": []}
    return data


@app.get("/api/sample/{sample_id}/family")
async def api_get_family(sample_id: str) -> dict:
    """Malware family identification (deterministic + LLM)."""
    result = load_result(sample_id)
    if result is None:
        raise HTTPException(status_code=404, detail="Sample not found")
    return identify_family(sample_id, result)


@app.get("/api/sample/{sample_id}/obfuscation")
async def api_get_obfuscation(sample_id: str) -> dict:
    """Obfuscation analysis view: techniques, DEX entropy, native artifacts."""
    result = load_result(sample_id)
    if result is None:
        raise HTTPException(status_code=404, detail="Sample not found")

    obf = build_obfuscation_view(sample_id, result.get("obfuscation_analysis"))
    return obf


class DeobfuscateRequest(BaseModel):
    text: str
    hint: Optional[str] = None


class ExplainMethodRequest(BaseModel):
    class_name: str
    method_name: str
    method_code: str
    flags: Optional[List[str]] = None


# Static pattern map: keyword → analyst label
_STATIC_PATTERN_LABELS: dict = {
    "invoke": ("reflection", "Dynamic method invocation via reflection"),
    "classloader": ("dynamic_loading", "Runtime class loading — common in dropper/loader malware"),
    "dexclassloader": ("dynamic_loading", "Loads DEX/APK from disk at runtime — strong dropper indicator"),
    "cipher": ("crypto", "Cryptographic operation — check for data encryption/decryption"),
    "base64": ("encoding", "Base64 encoding/decoding — often used to obfuscate payloads"),
    "decode": ("encoding", "Decoding operation — may unwrap an obfuscated payload"),
    "encrypt": ("crypto", "Explicit encryption — check what data is being encrypted and why"),
    "runtime.exec": ("command_exec", "Shell command execution — high-severity indicator"),
    "processbuilder": ("command_exec", "Process spawning — shell command execution path"),
    "httpurlconnection": ("network", "HTTP network call — check destination and payload"),
    "socket": ("network", "Raw socket usage — potential C2 communication channel"),
    "reflect": ("reflection", "Java reflection API — used to hide method calls from static analysis"),
    "permission": ("permissions", "Runtime permission check — note which permission is being gated"),
}


def _annotate_lines(code: str) -> dict[int, dict]:
    """
    Scan code lines for suspicious patterns.
    Returns {line_index: {type, label}} for any line that matches.
    Zero-indexed to match frontend array indexing.
    """
    annotations = {}
    for i, line in enumerate(code.splitlines()):
        lower = line.lower()
        for keyword, (pattern_type, label) in _STATIC_PATTERN_LABELS.items():
            if keyword in lower:
                # First match wins per line — use the most specific keyword
                annotations[i] = {"type": pattern_type, "label": label, "keyword": keyword}
                break
    return annotations


@app.post("/api/sample/{sample_id}/dissection/explain-method")
async def api_explain_method(sample_id: str, request: ExplainMethodRequest) -> dict:
    """
    Return static line annotations (instant) + async LLM summary for a method.
    Static annotations are always present; LLM summary may be empty if LLM is unavailable.
    """
    result = load_result(sample_id)
    if result is None:
        raise HTTPException(status_code=404, detail="Sample not found")

    # Layer 1: static pattern annotations — synchronous, no LLM
    line_annotations = _annotate_lines(request.method_code)

    # Layer 2: LLM explanation — run in thread pool so we don't block the event loop
    import asyncio
    loop = asyncio.get_event_loop()
    try:
        llm_result = await loop.run_in_executor(
            None,
            lambda: explain_method(
                request.class_name,
                request.method_name,
                request.method_code,
                request.flags or [],
            ),
        )
    except Exception as e:
        llm_result = {
            "summary": f"LLM unavailable: {e}",
            "threat_type": "unknown",
            "confidence": 0.0,
        }

    return {
        "class_name": request.class_name,
        "method_name": request.method_name,
        "line_annotations": line_annotations,
        "llm": llm_result,
    }


@app.post("/api/sample/{sample_id}/report/pdf")
async def api_generate_pdf_report(sample_id: str, request: dict) -> Response:
    """
    Generate a full forensic PDF report for a sample.

    Body: { "mode": "quick" | "full" }
    - quick: LLM summaries for top 30 suspicious methods by suspicion score
    - full:  LLM summaries for all suspicious methods (may be slow)
    """
    result = load_result(sample_id)
    if result is None:
        raise HTTPException(status_code=404, detail="Sample not found")

    mode = request.get("mode", "quick")

    # Gather supporting data
    threat_data = ti.build_threat_intel(result, sample_id)
    try:
        from backend.obfuscation_view import build_obfuscation_view
        obfuscation = build_obfuscation_view(sample_id, result)
    except Exception:
        obfuscation = {}

    # Get suspicious classes + methods
    apk_path = _get_sample_apk_path(sample_id)
    annotated_methods = []

    if apk_path:
        try:
            dissector = APKDissector(str(apk_path), work_dir=str(WORK_DIR))
            classes = dissector.list_decompiled_class_objects()

            SUSPICIOUS_KEYWORDS = [
                'invoke', 'Cipher', 'ClassLoader', 'reflect', 'DexClassLoader',
                'Runtime.exec', 'ProcessBuilder', 'HttpURLConnection', 'Base64',
                'decode', 'encrypt', 'socket', 'intent', 'permission',
            ]
            UNWANTED_PATTERNS = [
                'android.support.', 'androidx.', 'com.android.internal.',
                'kotlin.', 'com.google.android.',
            ]

            def suspicion_score(cls_data):
                score = 0
                for method in cls_data.get('methods', []):
                    body = method.get('body', '') or ''
                    name = method.get('name', '') or ''
                    for kw in SUSPICIOUS_KEYWORDS:
                        if kw.lower() in name.lower():
                            score += 2
                        if kw.lower() in body.lower():
                            score += 1
                return score

            # Filter boilerplate and sort by suspicion
            suspicious = [
                c for c in classes
                if suspicion_score(c) > 0
                and not any(p in c.get('name', '') for p in UNWANTED_PATTERNS)
            ]
            suspicious.sort(key=suspicion_score, reverse=True)

            method_limit = None if mode == 'full' else 30
            processed = 0

            for cls in suspicious:
                if method_limit and processed >= method_limit:
                    break
                cls_name = cls.get('name', '')
                for method in cls.get('methods', []):
                    if method_limit and processed >= method_limit:
                        break
                    body = method.get('body', '') or ''
                    name = method.get('name', '') or ''
                    flags = [kw for kw in SUSPICIOUS_KEYWORDS
                             if kw.lower() in name.lower() or kw.lower() in body.lower()]
                    if not flags:
                        continue

                    # Static annotations
                    line_annotations = _annotate_lines(body)

                    # LLM summary — run synchronously here (we're already in executor context)
                    llm_result = explain_method(cls_name, name, body, flags)

                    annotated_methods.append({
                        'class_name':       cls_name,
                        'method_name':      name,
                        'flags':            flags,
                        'line_annotations': line_annotations,
                        'llm':              llm_result,
                    })
                    processed += 1

        except Exception as e:
            # Don't fail the whole report if dissection breaks
            pass

    # Generate PDF
    import asyncio
    loop = asyncio.get_event_loop()
    try:
        pdf_bytes = await loop.run_in_executor(
            None,
            lambda: generate_report(
                sample_id=sample_id,
                sample_result=result,
                threat_data=threat_data,
                obfuscation=obfuscation,
                annotated_methods=annotated_methods,
                mode=mode,
            )
        )
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"PDF generation failed: {e}")

    filename = f"droidforensix_{sample_id[:12]}_{mode}.pdf"
    return Response(
        content=pdf_bytes,
        media_type="application/pdf",
        headers={"Content-Disposition": f'attachment; filename="{filename}"'},
    )


@app.post("/api/sample/{sample_id}/deobfuscate")
async def api_deobfuscate(sample_id: str, request: DeobfuscateRequest) -> dict:
    """Best-effort deobfuscation of a user-supplied string."""
    result = load_result(sample_id)
    if result is None:
        raise HTTPException(status_code=404, detail="Sample not found")

    return deobfuscate_text(request.text, request.hint)


@app.get("/api/sample/{sample_id}/threat-intel/export/csv")
async def api_export_threat_intel_csv(sample_id: str):
    """Export C2 indicators as a CSV blocklist."""
    result = load_result(sample_id)
    if result is None:
        raise HTTPException(status_code=404, detail="Sample not found")
    csv_text = ti.to_csv(result)
    return PlainTextResponse(
        csv_text,
        media_type="text/csv",
        headers={"Content-Disposition": f'attachment; filename="droidforensix_{sample_id[:16]}_blocklist.csv"'},
    )


@app.get("/api/sample/{sample_id}/threat-intel/export/stix")
async def api_export_threat_intel_stix(sample_id: str):
    """Export C2 indicators as a STIX 2.0 bundle."""
    result = load_result(sample_id)
    if result is None:
        raise HTTPException(status_code=404, detail="Sample not found")
    bundle = ti.to_stix(result, sample_id)
    return Response(
        content=json.dumps(bundle, indent=2),
        media_type="application/json",
        headers={"Content-Disposition": f'attachment; filename="droidforensix_{sample_id[:16]}_stix.json"'},
    )


@app.get("/api/sample/{sample_id}/threat-intel/export/yara")
async def api_export_threat_intel_yara(sample_id: str):
    """Export a per-sample YARA rule built from extracted C2 indicators."""
    result = load_result(sample_id)
    if result is None:
        raise HTTPException(status_code=404, detail="Sample not found")
    yara_text = ti.to_yara(result, sample_id)
    return PlainTextResponse(
        yara_text,
        media_type="text/plain",
        headers={"Content-Disposition": f'attachment; filename="droidforensix_{sample_id[:16]}.yar"'},
    )


# Legacy endpoints (kept for backward compatibility)
@app.get("/samples")
async def list_samples() -> dict:
    """List all processed samples (legacy)."""
    return await api_list_samples()


@app.get("/samples/{sample_id}")
async def get_sample(sample_id: str) -> dict:
    """Get analysis result for a sample (legacy)."""
    return await api_get_sample(sample_id)


# ---------------------------------------------------------------------------
# Upload and analysis endpoints
# ---------------------------------------------------------------------------

@app.post("/api/upload")
async def api_upload_file(file: UploadFile = File(...)) -> dict:
    """Upload an APK file and return an upload ID for analysis."""
    upload_id = str(uuid.uuid4())
    upload_dir = settings.UPLOADS_DIR / upload_id
    upload_dir.mkdir(parents=True, exist_ok=True)

    dest_path = upload_dir / "file.apk"
    try:
        with open(dest_path, "wb") as f:
            content = await file.read()
            f.write(content)
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to save uploaded file: {e}")

    # Compute SHA256 for client-side preview
    sha256 = hashlib.sha256(dest_path.read_bytes()).hexdigest()

    upload_registry[upload_id] = {
        "upload_id": upload_id,
        "filename": file.filename,
        "sha256": sha256,
        "path": str(dest_path),
        "status": "uploaded",
    }

    return {
        "upload_id": upload_id,
        "filename": file.filename,
        "sha256": sha256,
        "status": "uploaded",
        "message": "File uploaded successfully. Use POST /api/analyze/{upload_id} to start analysis.",
    }


@app.post("/api/analyze/{upload_id}")
async def api_analyze_upload(upload_id: str) -> dict:
    """Trigger analysis for a previously uploaded APK."""
    upload = upload_registry.get(upload_id)
    if upload is None:
        raise HTTPException(status_code=404, detail="Upload not found")

    apk_path = upload["path"]
    if not Path(apk_path).exists():
        raise HTTPException(status_code=400, detail="Uploaded APK file no longer exists")

    loop = asyncio.get_event_loop()

    def run_analysis():
        emitter = make_event_emitter(loop)
        try:
            sample_status[upload_id] = {"status": "analyzing", "sample_id": None, "error": None, "started_at": datetime.now(timezone.utc).isoformat()}
            result = run_pipeline(apk_path, event_emitter=emitter)
            sample_id = result.get("sample_id")
            # Map upload_id to final sample_id for status lookups
            sample_status[upload_id] = {"status": "completed", "sample_id": sample_id, "error": None, "started_at": sample_status[upload_id].get("started_at")}
            if sample_id:
                upload["sample_id"] = sample_id
            return result
        except Exception as e:
            sample_status[upload_id] = {"status": "failed", "sample_id": None, "error": str(e)}
            raise

    async def run_analysis_async():
        return await loop.run_in_executor(None, run_analysis)

    asyncio.create_task(run_analysis_async())
    upload["status"] = "queued"

    return {
        "upload_id": upload_id,
        "status": "queued",
        "message": "Analysis started. Poll GET /api/sample/{sample_id}/status or listen on /ws for progress.",
    }


@app.post("/analyze")
async def analyze(request: AnalyzeRequest) -> dict:
    """Trigger analysis of an APK by local path (REST fallback / backward compatibility)."""
    apk_path = request.apk_path
    if not Path(apk_path).exists():
        raise HTTPException(status_code=400, detail=f"APK not found: {apk_path}")

    loop = asyncio.get_event_loop()
    job_id = str(uuid.uuid4())

    def run_analysis():
        emitter = make_event_emitter(loop)
        try:
            sample_status[job_id] = {"status": "analyzing", "sample_id": None, "error": None, "started_at": datetime.now(timezone.utc).isoformat()}
            result = run_pipeline(apk_path, event_emitter=emitter)
            sample_id = result.get("sample_id")
            sample_status[job_id] = {"status": "completed", "sample_id": sample_id, "error": None, "started_at": sample_status[job_id].get("started_at")}
            return result
        except Exception as e:
            sample_status[job_id] = {"status": "failed", "sample_id": None, "error": str(e)}
            raise

    async def run_analysis_async():
        return await loop.run_in_executor(None, run_analysis)

    asyncio.create_task(run_analysis_async())

    return {
        "job_id": job_id,
        "status": "queued",
        "message": "Analysis started. Poll GET /api/sample/{sample_id}/status or listen on /ws for progress.",
    }


@app.get("/api/sample/{sample_id}/status")
async def api_get_sample_status(sample_id: str) -> dict:
    """Get analysis status for a sample or upload/job ID."""
    # Check upload/job status first
    if sample_id in sample_status:
        info = sample_status[sample_id]
        return {
            "sample_id": info.get("sample_id") or sample_id,
            "status": info["status"],
            "error": info.get("error"),
            "started_at": info.get("started_at"),
        }

    # Check if final result exists
    result = load_result(sample_id)
    if result is not None:
        return {
            "sample_id": sample_id,
            "status": "completed",
            "severity": result.get("llm_assessment", {}).get("severity"),
            "risk_score": result.get("llm_assessment", {}).get("risk_score"),
        }

    raise HTTPException(status_code=404, detail="Sample or job not found")


# ---------------------------------------------------------------------------
# Diagnostics
# ---------------------------------------------------------------------------

@app.get("/api/diagnostics/jadx")
async def api_diagnostics_jadx() -> dict:
    """Check JADX installation and configuration."""
    jadx_path = settings.JADX_PATH
    path_obj = Path(jadx_path)

    # Check if binary exists
    exists = path_obj.exists()

    # Try to get version
    version = None
    version_error = None
    try:
        if exists:
            result = subprocess.run(
                [jadx_path, "--version"],
                capture_output=True,
                text=True,
                timeout=5
            )
            version = result.stdout.strip() if result.returncode == 0 else None
            if not version:
                version_error = result.stderr.strip() if result.stderr else "Unknown error"
    except Exception as e:
        version_error = str(e)

    return {
        "configured_path": str(jadx_path),
        "exists": exists,
        "is_file": path_obj.is_file() if path_obj.exists() else False,
        "is_executable": path_obj.exists() and path_obj.stat().st_mode & 0o111 != 0,
        "version": version,
        "version_error": version_error,
        "status": "ok" if exists and version else "missing" if not exists else "error",
        "help": "See JADX_SETUP.md for installation instructions"
    }


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