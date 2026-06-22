# DroidForensix Routing Map

This document outlines the routing structure of both the backend FastAPI server and the frontend React application.

---

## 1. Frontend Mappings (State-Based Routing)

The frontend is a Single Page Application (SPA) that manages navigation via an `activeTab` React state in [App.jsx](file:///d:/DroidForensix/frontend/src/App.jsx). This state toggles the display of the corresponding views:

| View Name | Component File | Navigation Hook | Requirements |
|---|---|---|---|
| **Upload & Analyze** | [UploadPanel.jsx](file:///d:/DroidForensix/frontend/src/components/UploadPanel.jsx) | `activeTab === 'upload'` | None (initial landing page). |
| **Analysis Results** | [AnalysisView.jsx](file:///d:/DroidForensix/frontend/src/components/AnalysisView.jsx) | `activeTab === 'analysis'` | A selected sample must exist in state. |
| **Code Dissection** | [DissectionPage.jsx](file:///d:/DroidForensix/frontend/src/components/DissectionPage.jsx) | `activeTab === 'dissection'` | A selected sample must exist in state. |
| **Threat Intelligence**| [ThreatIntelView.jsx](file:///d:/DroidForensix/frontend/src/components/ThreatIntelView.jsx) | `activeTab === 'threat-intel'`| A selected sample must exist in state. |

---

## 2. Backend REST API Routing

The backend FastAPI server exposes the following HTTP endpoints on `http://localhost:8000`:

### Core / System Mappings
- **`GET /`**
  - **Purpose:** System health check.
  - **Auth Required:** No.
  - **Response Schema:**
    ```json
    { "status": "ok", "version": "1.0.0", "api_prefix": "/api" }
    ```

### Sample Listings & Status Mappings
- **`GET /api/samples`** (also matches legacy route `GET /samples`)
  - **Purpose:** Lists all analyzed samples. Loads metadata from `pipeline_result.json` files on disk.
  - **Auth Required:** No.
- **`GET /api/sample/{sample_id}/status`**
  - **Purpose:** Fetches current job execution status (`uploaded`, `queued`, `analyzing`, `completed`, `failed`).
  - **Auth Required:** No.

### Pipeline Reports Mappings
- **`GET /api/sample/{sample_id}`** (also matches legacy route `GET /samples/{sample_id}`)
  - **Purpose:** Fetches the full aggregated JSON analysis report.
  - **Auth Required:** No.
- **`GET /api/graph/{sample_id}`**
  - **Purpose:** Generates nodes and links for 3D threat-chain visualizations.
  - **Auth Required:** No.
- **`GET /api/timeline/{sample_id}`**
  - **Purpose:** Fetches chronological events of the correlated threat chain.
  - **Auth Required:** No.
- **`GET /api/clusters`**
  - **Purpose:** Generates 3D plotting coordinate groups for the global threat comparison scatter chart.
  - **Auth Required:** No.

### APK Dissection Mappings
- **`GET /api/sample/{sample_id}/dissection`**
  - **Purpose:** Returns the structural disassembled information (manifest, permissions, DEX, native libs).
  - **Auth Required:** No.
- **`GET /api/sample/{sample_id}/dissection/manifest`**
  - **Purpose:** Returns AndroidManifest.xml configuration details.
  - **Auth Required:** No.
- **`GET /api/sample/{sample_id}/dissection/permissions`**
  - **Purpose:** Lists permissions with labeled danger categories.
  - **Auth Required:** No.
- **`GET /api/sample/{sample_id}/dissection/components`**
  - **Purpose:** Returns Android manifest component classes.
  - **Auth Required:** No.
- **`GET /api/sample/{sample_id}/dissection/dex`**
  - **Purpose:** Returns class and method count stats of DEX headers.
  - **Auth Required:** No.
- **`GET /api/sample/{sample_id}/dissection/classes`**
  - **Purpose:** Returns parsed class lists.
  - **Auth Required:** No.
- **`GET /api/sample/{sample_id}/dissection/code/{class_name}`**
  - **Purpose:** Reads the raw decompiled source for a specific Java class file.
  - **Auth Required:** No.
- **`GET /api/sample/{sample_id}/dissection/strings`**
  - **Purpose:** Lists all literals extracted by Step 2.
  - **Auth Required:** No.

### Threat Intelligence & Obfuscation Mappings
- **`GET /api/sample/{sample_id}/threat-intel`**
  - **Purpose:** Returns combined indicators details: geolocation, DNS status, and malware family labels.
  - **Auth Required:** No.
- **`GET /api/sample/{sample_id}/family`**
  - **Purpose:** Returns malware family identification consensus calculations.
  - **Auth Required:** No.
- **`GET /api/sample/{sample_id}/obfuscation`**
  - **Purpose:** Returns lists of reflection calls and dynamic loaders.
  - **Auth Required:** No.
- **`POST /api/sample/{sample_id}/deobfuscate`**
  - **Purpose:** Tries Base64/XOR/Hex decoders on a client-submitted string.
  - **Auth Required:** No.

### File Exporter Mappings
- **`GET /api/sample/{sample_id}/threat-intel/export/csv`**
  - **Purpose:** Download C2 list as an indicator blocklist.
  - **Auth Required:** No.
- **`GET /api/sample/{sample_id}/threat-intel/export/stix`**
  - **Purpose:** Download indicators formatted in STIX 2.0 JSON standard.
  - **Auth Required:** No.
- **`GET /api/sample/{sample_id}/threat-intel/export/yara`**
  - **Purpose:** Download custom generated YARA rule.
  - **Auth Required:** No.

### Upload & Analysis Mappings
- **`POST /api/upload`**
  - **Purpose:** Saves multipart uploaded file. Returns an upload ID.
  - **Auth Required:** No.
- **`POST /api/analyze/{upload_id}`**
  - **Purpose:** Queues and runs the 9-step analysis pipeline.
  - **Auth Required:** No.
- **`POST /analyze`**
  - **Purpose:** Direct local analysis triggers using absolute filesystem paths (REST fallback).
  - **Auth Required:** No.

---

## 3. WebSockets Endpoint (`/ws`)

Provides real-time updates of the analysis pipeline.

### Connection
- **URL:** `ws://localhost:8000/ws`
- **Ping Interval:** The client sends `{"action": "ping"}` every 20 seconds. The server responds with `{"event_type": "pong", "timestamp": ""}` to keep the connection alive.

### Broadcast Event Types (Server -> Client)
1. **`analysis_started`**
   - Emitted when pipeline launches.
   ```json
   { "event_type": "analysis_started", "data": { "sample_id": "sha256", "sample_name": "app.apk", "total_steps": 9, "predicted_eta_seconds": 45.0 } }
   ```
2. **`step_started`**
   - Broadcast when a new step in the orchestrator starts.
   ```json
   { "event_type": "step_started", "data": { "sample_id": "sha256", "step_number": 2, "step_name": "String Enumeration", "elapsed_seconds": 4.12 } }
   ```
3. **`step_completed`**
   - Broadcast when a step finishes, providing duration stats.
   ```json
   { "event_type": "step_completed", "data": { "sample_id": "sha256", "step_number": 2, "step_name": "String Enumeration", "duration_seconds": 1.25, "progress_percent": 22 } }
   ```
4. **`metric_updated`**
   - Broadcast when intermediate results update (e.g. string count, C2 count).
   ```json
   { "event_type": "metric_updated", "data": { "sample_id": "sha256", "metric_name": "string_count", "metric_value": 2500 } }
   ```
5. **`analysis_complete`**
   - Broadcast when the 9-step process finishes successfully.
   ```json
   { "event_type": "analysis_complete", "data": { "sample_id": "sha256", "final_verdict": "malware", "risk_score": 85 } }
   ```
6. **`error`**
   - Broadcast when an operation fails.
   ```json
   { "event_type": "error", "data": { "sample_id": "sha256", "error_message": "JADX decompilation timed out", "severity": "high" } }
   ```
