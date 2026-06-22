# DroidForensix Repository Overview

**Project:** Static Android Malware Analysis Framework  
**Author:** Darshak Patel  
**Status:** Active (M.Sc. thesis core component)  
**Repository:** https://github.com/DarshakPatel2004/DroidForensix.git

---

## 1. Executive Summary

**DroidForensix** is a fully-automated static analysis pipeline for detecting malicious behavior in Android APKs. It extracts encoded strings, decodes hidden payloads, identifies command-and-control (C2) infrastructure, correlates threat chains, and assesses obfuscation through a 9-step orchestrated workflow. The pipeline is exposed via a FastAPI backend with real-time WebSocket updates and a React frontend featuring 3D visualization of threat chains and obfuscation analysis.

### Key Metrics

| Metric | Value |
|--------|-------|
| **Validation Dataset** | 100 samples (50 Drebin malware + 50 F-Droid benign) |
| **Best Accuracy** | 92.0% |
| **Precision** | 100.0% (zero false positives) |
| **Recall** | 84.0% |
| **F1-Score** | 0.913 |
| **False Negatives** | 8 samples (malware lacking network indicators + obfuscation) |
| **Tests Passing** | 90 / 90 |
| **API Endpoints** | 6+ REST endpoints + 1 WebSocket channel |

### Technology Stack

**Backend:** FastAPI, Celery, PostgreSQL, androguard (DEX analysis), Ollama/OpenAI LLM  
**Frontend:** React 19, Vite, 3D visualization (Three.js)  
**Analysis Tools:** apktool, jadx, YARA patterns, phonenumbers library  
**Testing:** pytest, pytest-asyncio, httpx  

---

## 2. Project Structure

```
DroidForensix/
├── analysis/                    # Core 9-step pipeline
│   ├── pipeline.py              # Orchestrator, event emitter
│   ├── step1_apk_extraction.py
│   ├── step2_string_enumeration.py
│   ├── step3_encoding_detection.py
│   ├── step4_decoding.py
│   ├── step5_c2_extraction.py
│   ├── step6_correlation.py
│   ├── step7_llm_assessment.py
│   ├── step8_obfuscation_analysis.py
│   └── step9_post_process.py
│
├── backend/                     # FastAPI + service layer
│   ├── main.py                  # REST API, WebSocket, upload handlers
│   ├── config.py                # Settings (paths, LLM config)
│   ├── events.py                # WebSocket event types
│   ├── validators.py            # Event schema validation
│   ├── transformers.py          # Result → API response transforms
│   ├── circl_client.py           # CIRCL API integration (threat intel)
│   ├── dissection.py             # APK metadata extraction
│   ├── family_id.py              # Malware family classification
│   ├── threat_intel.py           # External threat intelligence
│   └── obfuscation_view.py       # Obfuscation scoring & visualization
│
├── frontend/                    # React + Vite
│   ├── src/                     # React components
│   ├── public/                  # Static assets
│   ├── vite.config.js
│   └── package.json
│
├── tests/                       # Comprehensive pytest suite
│   ├── test_backend.py
│   ├── test_c2_and_correlation.py
│   ├── test_circl_client.py
│   ├── test_dissection.py
│   ├── test_encoding_detection.py
│   ├── test_llm_obfuscation_anchor.py
│   ├── test_obfuscation_analysis.py
│   └── test_smali_fallback.py
│
├── scripts/                     # Batch processing & data tools
│   ├── download_samples.py      # Drebin, AndroZoo, GitHub malware
│   ├── run_batch_analysis.py    # Process multiple APKs
│   ├── fetch_github_malware.py
│   ├── check_samples.py
│   └── install_windows_tools.py
│
├── requirements.txt             # Python dependencies
├── report.md                    # Detailed validation report (502 lines)
├── FAILURE_ANALYSIS.md          # False negative breakdown
├── VALIDATION_REPORT.md         # Summary metrics & thresholds
└── README.md (implied)          # Project documentation
```

---

## 3. The 9-Step Pipeline

### **Step 1: APK Extraction**
- **Input:** `.apk` file path
- **Output:** Decompiled smali/Java source, manifest, strings
- **Tools:** apktool, jadx (with fallback)
- **Key Action:** Compute sample SHA256 for unique ID
- **Duration:** ~0.5–2s (depends on APK size)

### **Step 2: String Enumeration**
- **Input:** Decompiled source
- **Output:** All string literals, byte arrays, numeric constants, native strings
- **Sources Scanned:**
  - Java string constants
  - Resource files
  - DEX string pools
  - C/C++ native strings (if present)
- **Note:** Filters benign framework sources (android.*, androidx.*, kotlin.*)
- **Duration:** ~0.2–0.5s

### **Step 3: Encoding Detection**
- **Input:** Enumerated strings
- **Output:** Flagged encoded payloads (Base64, hex, XOR, custom encodings)
- **Problem Solved:** Early versions over-matched support library constants as encoded payloads
- **Current Fix:** Source filtering + heuristics to distinguish noise from real obfuscation
- **Duration:** ~0.5–1s

### **Step 4: Payload Decoding**
- **Input:** Detected encoded payloads
- **Output:** Decoded strings, character set analysis, entropy scores
- **Techniques:**
  - Base64 (standard + URL-safe variants)
  - Hex strings
  - XOR with single/multi-byte keys
  - Custom substitution ciphers
- **Duration:** ~0.3–1s

### **Step 5: C2 Extraction**
- **Input:** Decoded strings + decompiled source
- **Output:** IPs, domains, URLs with classification (public/private, benign/malicious)
- **Classification Logic:**
  - Benign: certificate authorities, ad networks, analytics, package repositories
  - Malicious: unregistered domains, known C2 IPs, mismatched protocols
  - Private: 10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16, localhost
- **Integration:** CIRCL API for threat intelligence cross-checking
- **Duration:** ~1–3s

### **Step 6: Threat Chain Correlation**
- **Input:** Encoding detection → decoding results → C2 indicators
- **Output:** Linked threat chains (e.g., "string X was base64-encoded, decoded to domain Y, which is a known C2")
- **Purpose:** Show investigators the *path* from obfuscation to malicious infrastructure
- **Duration:** ~0.2–0.5s

### **Step 7: LLM Assessment**
- **Input:** Full pipeline context (strings, encodings, C2, chains)
- **Output:** Risk score (0–100), confidence, rationale
- **LLM Options:**
  - Ollama (local, privacy-preserving)
  - OpenAI API (higher quality, requires API key)
- **Fallback:** Rule-based scoring if LLM unavailable
- **Rules:**
  - Base64 + C2 → +40 points
  - Reflection/crypto APIs → +20 points
  - Dynamic class loading → +30 points
  - Network socket operations → +25 points
- **Duration:** ~2–5s (LLM inference time)

### **Step 8: Obfuscation Analysis**
- **Input:** Decompiled DEX, method names, cross-references
- **Output:** Obfuscation scores for reflection, crypto, dynamic loading
- **Problem Solved:** Early versions counted Android framework method names as malicious obfuscation
- **Current Fix:** DEX cross-reference analysis to distinguish framework patterns from actual obfuscation
- **Scoring:**
  - Reflection (Class.forName, getMethod): +15 per instance
  - Crypto (javax.crypto, Cipher): +10 per instance
  - Dynamic loading (DexClassLoader, PathClassLoader): +20 per instance
- **Duration:** ~0.5–1s

### **Step 9: Post-Process**
- **Input:** All prior step outputs
- **Output:** Sanity corrections (metasploit stagers, known benign patterns)
- **Actions:**
  - Flag Metasploit payloads (high obfuscation, no C2 = likely stager, not deployed malware)
  - Suppress false positives from benign permission requests
  - Normalize threat chain descriptions for report output
- **Duration:** ~0.1–0.2s

**Total Pipeline Duration:** ~5–15s per APK (varies by size, LLM availability)

---

## 4. Backend API

### REST Endpoints

#### **POST /upload**
- **Purpose:** Accept APK upload and start analysis
- **Request:** Multipart form, file field = APK
- **Response:** `{ "upload_id": "uuid", "sample_id": "sha256", "status": "queued" }`
- **Note:** Stores APK in `settings.UPLOAD_DIR`, triggers async pipeline

#### **GET /results/{sample_id}**
- **Purpose:** Retrieve completed analysis results
- **Response:** Full `pipeline_result.json` with all 9 steps' data
- **Fields:**
  - `step1.extraction`: decompilation success, manifest metadata
  - `step2.strings`: enumerated constants
  - `step3.encoding`: detected payloads
  - `step4.decoded`: recovered strings
  - `step5.c2`: C2 indicators with threat intel
  - `step6.chains`: linked threat chains
  - `step7.llm_assessment`: risk score + rationale
  - `step8.obfuscation`: reflection/crypto/dynamic-loading scores
  - `step9.post_process`: sanity corrections applied
  - `timeline`: execution times per step

#### **GET /graph**
- **Purpose:** Return threat chain graph for visualization
- **Response:** Node/edge lists (nodes = strings/domains/IPs, edges = relationships)
- **Format:** { "nodes": [...], "edges": [...] }

#### **GET /clusters**
- **Purpose:** Return malware family clustering
- **Response:** Grouped samples by family with similarity scores
- **Method:** Louvain algorithm on behavior-based similarity

#### **GET /samples**
- **Purpose:** List all analyzed samples
- **Query Params:** `limit`, `offset`, `status` (pending/done/failed)
- **Response:** Array of sample records with quick stats

#### **GET /dissection/{sample_id}**
- **Purpose:** Return APK metadata (package name, permissions, activities, providers)
- **Response:** Parsed AndroidManifest.xml + DEX class list

#### **WebSocket /ws**
- **Purpose:** Real-time event streaming during analysis
- **Event Types:**
  - `step_started`: Pipeline step beginning
  - `step_completed`: Step finished, partial results
  - `analysis_complete`: Full results ready
  - `error`: Pipeline failure
- **Message Format:** `{ "event_type": "...", "timestamp": "...", "data": {...} }`
- **Use Case:** Frontend subscribes, displays progress bar + live result updates

---

## 5. Frontend

### Technology
- **Framework:** React 19 with hooks
- **Build Tool:** Vite (fast dev server, optimized production builds)
- **Visualization:** Three.js for 3D threat chain graphs
- **Styling:** React inline styles + CSS modules

### Key Components (inferred from tech stack)
1. **Upload UI** – Drag-and-drop APK upload
2. **Progress Dashboard** – Real-time pipeline step display via WebSocket
3. **Results Viewer** – Tabbed interface:
   - Strings & Encoding
   - C2 Infrastructure
   - Threat Chains (3D visualization)
   - Obfuscation Analysis
   - LLM Risk Assessment
   - Sample Metadata
4. **Batch Analysis** – Queue multiple APKs, monitor in-progress jobs

---

## 6. Key Architectural Decisions

### Event-Driven Pipeline
- **Why:** Large APKs can take 10–15s to analyze; frontend needs real-time feedback
- **How:** Each step emits events via callback, backend broadcasts to all WebSocket clients
- **Result:** Users see progress (step 1/9 → step 2/9 → ...) without polling

### Separated Encoding Detection from C2 Extraction
- **Why:** Early design mixed these; encoded data ≠ malicious infrastructure
- **Design:** Step 3 flags suspicious encodings, Step 4 decodes them, Step 5 evaluates if decoded result is a C2 indicator
- **Benefit:** Cleaner signal separation, easier to debug false positives

### Threat Chain Correlation (Step 6)
- **Why:** A single C2 domain is weak signal; linking it to encoding/obfuscation strengthens confidence
- **What It Shows:** "String X (base64) → decoded to 'hacker.com' (known C2 in CIRCL)" = stronger verdict

### LLM-Augmented Fallback
- **Why:** Rule-based scoring is brittle; LLMs generalize better, but may be slow/unavailable
- **Design:** Try LLM first (Ollama local → OpenAI API), fallback to rule-based scoring
- **Result:** Always produces a verdict, but confidence varies

### Obfuscation via DEX Cross-References
- **Why:** Substring matching on method names (e.g., "Cipher", "reflect") catches too much framework noise
- **Fix:** Check if method is from android/androidx framework vs. user-defined code
- **Implementation:** DEX class hierarchy analysis to distinguish framework from app code

---

## 7. Validation & Quality Assurance

### Test Dataset
- **50 Drebin malware samples** – Real Android malware, ground-truth malicious
- **50 F-Droid benign samples** – Legitimate open-source apps
- **Total:** 100 diverse samples spanning different malware families and benign use cases

### Metrics on Validation Set (threshold=55)
- **True Positives:** 42 (malware detected as malicious)
- **True Negatives:** 50 (benign detected as benign)
- **False Positives:** 0 (no legitimate apps flagged)
- **False Negatives:** 8 (malware missed)

**Analysis of False Negatives:** Malware samples with no network indicators (C2) and minimal obfuscation signals. These are likely pre-deployment stagers or obfuscation-resistant trojans.

### Test Suite (90 tests)
- Unit tests for each step (encoding detection, C2 extraction, obfuscation scoring)
- Integration tests for full pipeline on real samples
- API tests (upload, fetch results, WebSocket streaming)
- Threat intel integration tests (CIRCL API mocking)

---

## 8. Configuration

### `backend/config.py`
```python
class Settings(BaseSettings):
    WORK_DIR: Path = Path("analysis/work")
    UPLOAD_DIR: Path = Path("uploads")
    OLLAMA_MODEL: str = "llama2"
    OLLAMA_API_URL: str = "http://localhost:11434"
    OPENAI_API_KEY: Optional[str] = None
    CIRCL_API_URL: str = "https://circl.lu/api/v2"
    VALIDATION_THRESHOLD: int = 55
```

### Environment Variables
- `OPENAI_API_KEY` – Optional; if set, use OpenAI instead of Ollama for LLM
- `CIRCL_API_KEY` – Optional; if set, use authenticated CIRCL requests
- `WORK_DIR` – Working directory for intermediate analysis files
- `UPLOAD_DIR` – Directory to store uploaded APKs

---

## 9. Workflow Example

1. **User uploads APK** → POST /upload
2. **Backend receives file** → Stores in `UPLOAD_DIR`, generates UUID and SHA256
3. **Pipeline starts** → async task via Celery
4. **Step 1:** Extract APK → apktool decompiles
5. **Step 2:** Enumerate strings → pull all constants from DEX
6. **Step 3:** Detect encoding → Base64, hex, XOR patterns
7. **Step 4:** Decode payloads → recover hidden strings
8. **Step 5:** Extract C2 → find IPs/domains, cross-check with CIRCL
9. **Step 6:** Correlate chains → link encoding → decoding → C2
10. **Step 7:** LLM assessment → score risk (0–100)
11. **Step 8:** Obfuscation analysis → reflection/crypto/dynamic-loading scores
12. **Step 9:** Post-process → sanity checks
13. **WebSocket events broadcast** → Frontend updates in real-time
14. **Results saved** → `analysis/work/{sha256}/pipeline_result.json`
15. **User retrieves via** → GET /results/{sample_id}

---

## 10. Known Limitations & Future Work

### Current Limitations
- **No dynamic analysis** – Static only; missed behaviors not encoded in APK
- **LLM latency** – Ollama can be slow on CPU; OpenAI requires internet + credentials
- **Batch processing** – No built-in queue/scheduler for 1000+ APK datasets; requires manual scaling
- **Family clustering** – Early-stage; relies on behavior similarity, not genetic relationships

### Future Enhancements
- **Dynamic analysis integration** – Emulation (QEMU) + syscall tracing
- **Database persistence** – PostgreSQL backend for sample deduplication, family tracking
- **Visualization dashboard** – Real-time heat maps of C2 infrastructure, family phylogeny
- **Mobile-optimized frontend** – Responsive design for field forensics
- **Export to MITRE ATT&CK** – Map findings to threat frameworks

---

## 11. Running the Project

### Prerequisites
```bash
python3.10+
apktool
jadx
ollama (for local LLM)
```

### Installation
```bash
git clone https://github.com/DarshakPatel2004/DroidForensix.git
cd DroidForensix
pip install -r requirements.txt
```

### Run Backend
```bash
uvicorn backend.main:app --reload --host 0.0.0.0 --port 8000
```

### Run Frontend
```bash
cd frontend
npm install
npm run dev  # Dev server at http://localhost:5173
```

### Run Tests
```bash
pytest tests/ -v
```

### Batch Analysis
```bash
python scripts/run_batch_analysis.py --input samples/ --output results/
```

---

## 12. Publication Strategy

**Thesis:** M.Sc. Digital Forensics & Information Security (NFSU, Delhi)  
**Target Submission:** May 2027  
**Publication Venues:**
- DFRWS 2027 (Digital Forensic Research Workshop)
- IEEE S&P / USENIX Security (ambitious)
- Virus Bulletin (industry-focused)
- ACSAC (security conference)

**Key Novelty:**
- First open-source Android malware detector with validated ground-truth dataset
- Threat chain correlation for forensic investigation narratives
- LLM-augmented static analysis with fallback rules

---

## 13. Contact & Repository

- **GitHub:** https://github.com/DarshakPatel2004/DroidForensix.git
- **Author:** Darshak Patel
- **Supervisor:** Ms. Reet Chauhan, NFSU
- **Student ID:** 250246002012

---

**Last Updated:** June 2026  
**Status:** Active development for M.Sc. thesis
