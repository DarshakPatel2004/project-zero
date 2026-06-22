# DroidForensix API Map

This document lists the parameters, schemas, validations, and response formats of the FastAPI backend APIs.

---

## 1. Request / Response Schemas (Pydantic Models)

Defined in [backend/main.py](file:///d:/DroidForensix/backend/main.py) and verified by Pydantic:

### AnalyzeRequest
Used in `POST /analyze`:
- **Properties:**
  - `apk_path` (string, required): Absolute Windows path of the target APK file.
- **Example JSON:**
  ```json
  {
    "apk_path": "D:\\DroidForensix\\samples\\malware\\sample.apk"
  }
  ```

### DeobfuscateRequest
Used in `POST /api/sample/{sample_id}/deobfuscate`:
- **Properties:**
  - `text` (string, required): The target string to decode.
  - `hint` (string, optional, nullable): Decoder hint (e.g. "base64", "hex").
- **Example JSON:**
  ```json
  {
    "text": "SGVsbG8gV29ybGQ=",
    "hint": "base64"
  }
  ```

### SampleInfo
Used to serialize history items:
- **Properties:**
  - `id` (string): Unique SHA-256 hash representation.
  - `name` (string): Original file name.
  - `status` (string): Processing state.
  - `timestamp` (string): Analysis date/time.

---

## 2. API Endpoints Details

### A. List Samples
- **Endpoint:** `GET /api/samples`
- **Controller Method:** `api_list_samples`
- **Output Schema:**
  ```json
  {
    "samples": [
      {
        "id": "673f4e...",
        "name": "malware.apk",
        "sha256": "673f4e...",
        "package_name": "com.malware.target",
        "file_size_bytes": 104560,
        "status": "analyzed",
        "severity": "high",
        "risk_score": 85,
        "primary_threat": "trojan",
        "obfuscation_score": 75,
        "obfuscation_level": "high",
        "family": "FakeInstaller",
        "family_confidence": 0.85,
        "encodings_count": 14,
        "payloads_count": 5,
        "c2_count": 2,
        "chains_count": 3
      }
    ],
    "total": 1
  }
  ```

### B. Full Report Data
- **Endpoint:** `GET /api/sample/{sample_id}`
- **Controller Method:** `api_get_sample`
- **Output Schema:** Returns the full JSON contents of `pipeline_result.json` which maps all steps:
  - `sample_id` (string)
  - `metadata` (object): Includes package name, hashes, size, paths.
  - `extraction` (object): Lists jadx/apktool statuses and decompiled classes count.
  - `manifest` (object): Declared target/min SDKs and uses-permissions lists.
  - `strings` (object): Categorized string lists from JADX/Smali.
  - `encodings` (array): Detected Base64/Hex/XOR items.
  - `payloads` (array): Decoded output contents.
  - `c2_infrastructure` (array): Identified servers and C2 addresses.
  - `threat_chains` (array): Linked threat step chains.
  - `llm_assessment` (object): Risk scores and descriptions.
  - `obfuscation_analysis` (object): Obfuscation indicators list.
  - `family_identification` (object): Labeled malware family details.

### C. 3D Graph Data
- **Endpoint:** `GET /api/graph/{sample_id}`
- **Controller Method:** `api_get_graph`
- **Output Schema:**
  ```json
  {
    "sample_id": "sha256",
    "sample_name": "app.apk",
    "total_nodes": 4,
    "total_edges": 3,
    "nodes": [
      { "id": "sample:sha", "type": "sample", "label": "app.apk", "confidence": 1.0, "color": "#A29BFE" },
      { "id": "encoded_string:hash", "type": "encoded_string", "label": "base64_str", "confidence": 0.9, "color": "#FF6B6B" }
    ],
    "edges": [
      { "source": "sample:sha", "target": "encoded_string:hash", "type": "decode", "color": "#4ECDC4" }
    ]
  }
  ```

### D. File Uploader
- **Endpoint:** `POST /api/upload`
- **Controller Method:** `api_upload_file`
- **Input Content-Type:** `multipart/form-data`
- **Output Schema:**
  ```json
  {
    "upload_id": "uuid-v4-string",
    "filename": "sample.apk",
    "sha256": "computed-sha256-string",
    "status": "uploaded",
    "message": "File uploaded successfully..."
  }
  ```

### E. Trigger Analysis
- **Endpoint:** `POST /api/analyze/{upload_id}`
- **Controller Method:** `api_analyze_upload`
- **Output Schema:**
  ```json
  {
    "upload_id": "uuid-v4-string",
    "status": "queued",
    "message": "Analysis started..."
  }
  ```
