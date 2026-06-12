# DroidForensix API Specification

Backend base URL: `http://localhost:8000`  
WebSocket URL: `ws://localhost:8000/ws`

---

## 1. REST Endpoints

### `GET /`
Health check.

**Response:**
```json
{
  "status": "ok",
  "version": "1.0.0",
  "api_prefix": "/api"
}
```

---

### `GET /api/samples`
List all analyzed samples with summary fields.

**Response:**
```json
{
  "samples": [
    {
      "id": "sha256",
      "name": "sample.apk",
      "sha256": "sha256",
      "package_name": "com.example.app",
      "file_size_bytes": 123456,
      "status": "analyzed",
      "severity": "high",
      "risk_score": 75,
      "primary_threat": "spyware",
      "encodings_count": 12,
      "payloads_count": 10,
      "c2_count": 3,
      "chains_count": 5
    }
  ],
  "total": 56
}
```

---

### `GET /api/sample/{sha256}`
Full analysis report for a single sample.

**Response:** full `pipeline_result.json` object containing:
- `sample_id`
- `metadata`
- `extraction`
- `strings`
- `encodings`
- `payloads`
- `c2_infrastructure`
- `threat_chains`
- `llm_assessment`
- `timeline`

---

### `GET /api/graph/{sha256}`
3D graph nodes and edges for threat-chain visualization.

**Response:**
```json
{
  "sample_id": "sha256",
  "sample_name": "sample.apk",
  "total_nodes": 25,
  "total_edges": 24,
  "nodes": [
    {
      "id": "sample:sha256",
      "type": "sample",
      "label": "sample.apk",
      "confidence": 1.0,
      "color": "#A29BFE"
    },
    {
      "id": "encoded_string:12345",
      "type": "encoded_string",
      "label": "aHR0cHM6Ly9ldmls...",
      "confidence": 0.9,
      "color": "#FF6B6B",
      "source_location": "MainActivity.java:42",
      "chain_id": "chain_001",
      "severity": "high"
    }
  ],
  "edges": [
    {
      "source": "sample:sha256",
      "target": "encoded_string:12345",
      "type": "decode",
      "color": "#4ECDC4"
    }
  ]
}
```

**Node types:** `sample`, `encoded_string`, `decoding_function`, `decoded_artifact`, `usage`, `c2_infrastructure`

**Edge types:** `decode`, `usage`, `exfiltration`

**Colors:**
- encoded_string: `#FF6B6B`
- decoding_function: `#4ECDC4`
- decoded_artifact: `#45B7D1`
- usage: `#96CEB4`
- c2_infrastructure: `#FFEAA7`
- sample: `#A29BFE`

---

### `GET /api/clusters`
3D clustering data for all samples.

**Axes:**
- `x`: encoding complexity (avg entropy + log(encoding count))
- `y`: C2 sophistication (#C2s + protocol/domain/IP diversity)
- `z`: exfiltration volume (#payloads + #chains)

**Response:**
```json
{
  "total_samples": 56,
  "samples": [
    {
      "id": "sha256",
      "name": "sample.apk",
      "x": 5.234,
      "y": 7.0,
      "z": 12.0,
      "family": "FakeInstaller",
      "severity": "high",
      "risk_score": 75,
      "confidence": 0.8,
      "encoding_count": 12,
      "c2_count": 3,
      "payload_count": 10,
      "chain_count": 5
    }
  ]
}
```

---

### `GET /api/timeline/{sha256}`
Attack-chain timeline progression for a sample.

**Response:**
```json
{
  "sample_id": "sha256",
  "sample_name": "sample.apk",
  "total_chains": 3,
  "chains": [
    {
      "chain_id": "chain_001",
      "severity": "high",
      "confidence": 0.85,
      "steps": [
        {
          "step": 1,
          "time": 1,
          "type": "encoded_string",
          "artifact": "aHR0cHM6Ly9ldmls...",
          "confidence": 0.9,
          "source_location": "MainActivity.java:42"
        },
        {
          "step": 2,
          "time": 2,
          "type": "decoding_function",
          "artifact": "decode_base64()",
          "confidence": 0.85,
          "source_location": "Decoder.java:15"
        }
      ]
    }
  ]
}
```

---

### `POST /analyze`
Trigger analysis of an APK (REST fallback). Real-time analysis should use WebSocket.

**Request:**
```json
{
  "apk_path": "/path/to/sample.apk"
}
```

**Response:**
```json
{
  "message": "Analysis started",
  "task": "<asyncio.Task object>"
}
```

---

## 2. WebSocket

### Connection
```javascript
const ws = new WebSocket('ws://localhost:8000/ws');
```

### Client → Server
Currently supports ping:
```json
{"action": "ping"}
```

Server responds with:
```json
{"event_type": "pong", "timestamp": ""}
```

### Server → Client Events
All events follow this schema:
```json
{
  "event_type": "encoding_detected",
  "timestamp": "2026-06-12T12:34:56.789Z",
  "data": { ... }
}
```

### Event Types

#### `analysis_started`
```json
{
  "sample_id": "sha256",
  "sample_name": "sample.apk",
  "total_steps": 7
}
```

#### `extraction_complete`
```json
{
  "sample_id": "sha256",
  "apktool_success": true,
  "jadx_success": true,
  "native_libs_found": ["lib/armeabi/lib.so"]
}
```

#### `strings_enumerated`
```json
{
  "sample_id": "sha256",
  "total_strings": 1543
}
```

#### `encoding_detected`
```json
{
  "sample_id": "sha256",
  "encoding_id": "enc_001",
  "type": "base64",
  "original_string": "aHR0cHM6Ly9ldmls...",
  "confidence": 0.9,
  "entropy": 4.5,
  "source_location": "MainActivity.java:42",
  "decoded_preview": "https://evil-domain.com/c2"
}
```

#### `payload_decoded`
```json
{
  "sample_id": "sha256",
  "payload_id": "pld_001",
  "encoding_id": "enc_001",
  "decoded_content": "https://evil-domain.com/c2",
  "artifacts": [
    {"type": "url", "value": "https://evil-domain.com/c2", "confidence": 0.95}
  ],
  "source_location": "Decoder.java:15"
}
```

#### `c2_extracted`
```json
{
  "sample_id": "sha256",
  "c2_id": "c2_001",
  "payload_id": "pld_001",
  "raw_url": "https://evil-domain.com/c2",
  "protocol": "https",
  "domain": "evil-domain.com",
  "ip": null,
  "port": 443,
  "ip_classification": "n/a",
  "communication_type": "http_request",
  "confidence": 0.85
}
```

#### `threat_chain_created`
```json
{
  "sample_id": "sha256",
  "chain_id": "chain_001",
  "severity": "high",
  "confidence": 0.85,
  "steps": [
    {"step": 1, "type": "encoded_string", "artifact": "...", "source_location": "...", "confidence": 0.9}
  ]
}
```

#### `analysis_complete`
```json
{
  "sample_id": "sha256",
  "total_encodings": 12,
  "total_payloads": 10,
  "total_c2s": 3,
  "total_chains": 5,
  "duration_seconds": 36.5,
  "report_path": "analysis/work/sha256/pipeline_result.json"
}
```

---

## 3. Frontend Integration Notes

### Recommended workflow
1. On app load, call `GET /api/clusters` and render the 3D scatter plot.
2. When user selects a sample, call:
   - `GET /api/sample/{sha256}` for details
   - `GET /api/graph/{sha256}` for threat graph
   - `GET /api/timeline/{sha256}` for timeline
3. Open WebSocket connection to receive live events during active analysis.

### Camera views
- Orbit (default)
- Top-down
- Side view
- Node-focus (center on selected node)

### Node click behavior
- Highlight node
- Show details sidebar with:
  - Type
  - Label
  - Confidence
  - Source location
  - Associated chain/severity

---

## 4. Running the Backend

```bash
cd /home/darshak/DroidForensix
source setenv.sh
source venv/bin/activate
python -m backend.main
```

Server starts on `http://0.0.0.0:8000`.
