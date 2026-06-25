# DroidForensix Codebase Memory

This document serves as the permanent brain of the **DroidForensix** project, a Windows-native Android malware static-analysis pipeline. It is designed to help new and existing engineers fully understand the system's purpose, design, data flow, architecture, and technology stack.

---

## 1. Project Overview

**DroidForensix** is a high-performance static analysis tool specifically tailored for analyzing Android application packages (APKs) natively on Windows. It decompiles APKs, extracts metadata, identifies obfuscated or encrypted content, isolates command-and-control (C2) servers, maps geographic origins, links threat chains, assesses risks with local LLMs, and attributes samples to malware families.

### Business & Technical Purpose
Security Operations Center (SOC) analysts and malware reverse engineers face difficulties in analyzing Android malware quickly. Mobile threat analysis often requires setting up heavy Linux environments or cloud services. DroidForensix solves this by:
1. Providing a **self-contained portable toolchain** (`tools\`) that runs natively on Windows 10+ without manual setup.
2. Automating the reverse-engineering process in a **9-step orchestrated pipeline**.
3. Combining deterministic analysis (signatures, heuristics, YARA rules) with local AI assessments (Ollama) to triage unknown threats.
4. Supplying a responsive 3-level dashboard (Glance, Triage, Investigation) to speed up analysis.

---

## 2. Tech Stack

### Core Technologies
- **Backend Framework:** FastAPI (Python 3.9+)
- **Server:** Uvicorn
- **Frontend Framework:** React 19 + Vite 8
- **Styling:** Vanilla CSS (no CSS frameworks)
- **Local AI Engine:** Ollama / NVIDIA NIM (supporting mistral:7b-instruct-q4_K_M or Nemotron)
- **Analysis Toolkit:** Androguard (DEX/APK parsing), JADX-CLI (Java decompilation), APKTool (resource unpacking)
- **Database/Storage:** Local File-System JSON Database (No SQL/NoSQL engine is required for database operations; outputs are saved as structured JSONs under `analysis/work/<sha256>/`).

### Detailed Technology Matrix
| Layer | Technology | Details |
|---|---|---|
| **Frontend** | React 19.2.6 | Interactive UI, component-driven, tab-state routing. |
| | Vite 8.0.12 | Dev server, asset bundle compilation. |
| | WebSockets API | Real-time bi-directional pipeline progress tracking. |
| **Backend** | FastAPI >= 0.119 | REST API endpoints, WebSocket connection manager, async tasks execution. |
| | Uvicorn | ASGI server implementation. |
| | Pydantic / Pydantic Settings | Type checking, request schemas validation, configuration management. |
| **Storage** | File-system | Structured JSON storage of pipeline results, dissection files, and caches. |
| | Ground Truth JSONs | Authoritative maps of known labeled hashes (`ground_truth_*.json`). |
| **Static Tooling** | JADX 21.0.3+9 | Bundled Java JRE decompiler batches. |
| | APKTool | Unpacking resources, manifest XML files decoding. |
| | Androguard | Python library for DEX structures parsing, entropy calculation, and smali extraction. |

---

## 3. Repository Structure

```
d:\DroidForensix
├── .github/                       # GitHub Actions CI/CD workflows
├── analysis/                      # Core 9-Step Malware Analysis Pipeline
│   ├── step1_apk_extraction.py    # Unpacking and Decompiling APKs via APKTool & JADX
│   ├── step2_string_enumeration.py# String/Byte array constants extraction and entropy calculations
│   ├── step3_encoding_detection.py# Detects encoded string patterns (Base64, Hex, XOR)
│   ├── step4_decoding.py          # Decodes strings, extracting URLs, domains, and files
│   ├── step5_c2_extraction.py     # Parses C2 endpoints and runs CIRCL pDNS/pSSL verification
│   ├── step6_correlation.py       # Inter-step correlation to map threat chains
│   ├── step7_llm_assessment.py    # Risk assessment using local Ollama or NVIDIA NIM
│   ├── step8_obfuscation_analysis.py # Smali reflection, DCL, and DEX packing analysis
│   ├── step9_post_process.py      # Post-processing corrections for false positives/negatives
│   ├── pipeline.py                # Pipeline orchestrator managing execution flow
│   └── work/                      # Analysis Workspace: stores intermediate and final results
│       └── <sha256>/              # Directory for each analyzed sample hash
│           ├── dissection.json    # Cached structural disassembly details
│           ├── pipeline_result.json # Compiled 9-step analysis report
│           ├── family.json        # Labeled family identification
│           └── ... (intermediate json steps)
├── backend/                       # FastAPI REST API & WebSocket Server
│   ├── main.py                    # REST and WebSocket handlers, async runners, uploaders
│   ├── config.py                  # Pydantic Settings, Windows directory parameters
│   ├── dissection.py              # Structural APK dissection engine
│   ├── family_id.py               # Malware family identifier (Deterministic Heuristics + LLM)
│   ├── threat_intel.py            # Threat Intel exporter (CSV, STIX 2.0, YARA Rule generator)
│   ├── obfuscation_view.py        # Obfuscation view mapper and decoder utilities
│   ├── circl_client.py            # Passive DNS and Passive SSL client wrapper for CIRCL
│   ├── events.py                  # Event definitions
│   └── transformers.py            # Converts reports into 3D graph/timeline/cluster mappings
├── frontend/                      # React Frontend Application
│   ├── src/
│   │   ├── components/            # Visual dashboard components
│   │   │   ├── UploadPanel.jsx    # Upload area, drag-and-drop, and sample list panel
│   │   │   ├── AnalysisView.jsx   # Tab-based dashboard (Overview, Obfuscation, C2, Chains, Manifest)
│   │   │   ├── SmartDissection.jsx# Java class browser, suspicious method filters
│   │   │   ├── ClassSourceViewer.jsx # Renders decompiled code with line indicators
│   │   │   ├── ManifestView.jsx   # Renders details from AndroidManifest.xml
│   │   │   ├── ObfuscationView.jsx# Shows obfuscation stats and dynamic decoders
│   │   │   └── ThreatIntelView.jsx# Renders verification tables and world map geographic pins
│   │   ├── App.jsx                # Layout, WebSockets hook, state transitions
│   │   ├── main.jsx               # React Vite entry point
│   │   └── styles/                # CSS themes and custom layouts
│   └── package.json               # Frontend dependencies list
├── tools/                         # Bundled portable binaries (JDK, JADX, APKTool, Node.js)
├── tests/                         # Pytest test cases
│   ├── test_backend.py
│   ├── test_dissection.py
│   ├── test_c2_and_correlation.py
│   └── ...
├── requirements.txt               # Python package dependencies
├── run_backend.bat                # Batch file to configure JRE and run FastAPI
├── run_frontend.bat               # Batch file to install npm dependencies and run Vite
└── run_ollama.bat                 # Starts Ollama local AI server
```

---

## 4. System Architecture

DroidForensix follows a decoupling design where the backend handles heavy reverse-engineering operations and file management, and the client displays live updates and interactive visualizations.

```
+--------------------------------------------------------+
|                      React UI                          |
|  - App.jsx (useReducer handles WS status)              |
|  - SmartDissection.jsx (Method and source analyzer)    |
|  - ThreatIntelView.jsx (Geo-pins mapping, C2 exports)  |
+--------------------------------------------------------+
              ^                                  |
              | WebSockets                       | HTTP REST APIs
              | (Events Broadcast)               | (Upload / Query / Trigger)
              v                                  v
+--------------------------------------------------------+
|                   FastAPI Server                       |
|  - main.py (Endpoint registration, WebSocket manager)  |
|  - dissection.py (Fast APK zip/androguard dissector)  |
|  - family_id.py (Ensemble family classifier)           |
+--------------------------------------------------------+
              |                                  |
              | Imports                          | Runs Process Executor
              v                                  v
+----------------------------------+   +---------------------------------+
|     9-Step Analysis Pipeline     |   |         Portable Tools          |
|  - pipeline.py (Orchestrator)    |   |  - tools\jadx (Java compiler)   |
|  - step1 -> step9 submodules     |   |  - tools\apktool (Resource)     |
+----------------------------------+   +---------------------------------+
              |                                  |
              +-----------------+----------------+
                                |
                                v
                   +------------------------+
                   | Local File-System DB   |
                   | - work/<sha256>/*.json |
                   | - ground_truth_*.json  |
                   +------------------------+
                                |
                                v
                    +----------------------+
                    |  Ollama Local LLM    |
                    |  (localhost:11434)   |
                    +----------------------+
```

---

## 5. Data Flow (Life of an Analysis)

Below is the execution flow of an APK analysis from upload to completion:

```
[User Uploads APK]
        |
        v
[POST /api/upload] ----------> Saves APK under D:\DroidForensix\uploads\<uuid>\file.apk
        |
        v
[POST /api/analyze/<uuid>] --> Starts async loop in backend and launches run_pipeline()
        |
        |---> [WebSocket Event] -> emits 'analysis_started' with ETA and size metrics
        |
        v
[Step 1: APK Extraction] ----> Unpacks resource/manifest via APKTool, decompiles to Java via JADX
        |                      Extracts native strings. Computes SHA256/MD5 hashes.
        |---> [WebSocket Event] -> emits 'step_completed' (1/9)
        |
        v
[Step 2: String Enumeration] -> Scans Java source, resources and .so strings, computes Shannon entropy
        |---> [WebSocket Event] -> emits 'step_completed' (2/9)
        |
        v
[Step 3: Encoding Detection] -> Identifies Base64, Hex, XOR-encoded indicators using entropy metrics
        |---> [WebSocket Event] -> emits 'step_completed' (3/9)
        |
        v
[Step 4: Payload Decoding] ---> Decodes matching strings. Extracts URLs, IPs, domains, and email addresses.
        |---> [WebSocket Event] -> emits 'step_completed' (4/9)
        |
        v
[Step 5: C2 Extraction] ------> Aggregates unique hosts. Filters out benign SDK/ad networks. Queries CIRCL.
        |---> [WebSocket Event] -> emits 'step_completed' (5/9)
        |
        v
[Step 6: Threat Chains] ------> Traces back: Encoding -> Decoder Class -> Decoded URL -> C2 Server
        |---> [WebSocket Event] -> emits 'step_completed' (6/9)
        |
        v
[Step 7: Obfuscation Analysis] -> Analyzes DEX entropy, class name lengths, reflection usage, dynamic classes
        |---> [WebSocket Event] -> emits 'step_completed' (7/9)
        |
        v
[Step 8: LLM Risk Assessment] -> Feeds aggregated context to local Ollama (Mistral) or NVIDIA NIM
        |                        Returns severity verdict, risk score, recommended actions, narrative.
        |---> [WebSocket Event] -> emits 'step_completed' (8/9)
        |
        v
[Step 9: Family Attribution] -> Runs deterministic heuristics, ground-truth mapping, YARA, and family LLM guess.
        |                       Applies post-processing corrections for stagers or false-positives.
        |---> [WebSocket Event] -> emits 'step_completed' (9/9) & 'analysis_complete'
        |
        v
[Write Results] --------------> Saves pipeline_result.json, dissection.json and family.json in work/<sha256>/
        |
        v
[Vite Frontend] --------------> Receives completion event. Swaps Loading view to ResultView.
                                User can now browse Overview, Obfuscation, C2, and Dissection tabs.
```

---

## 6. Routing Map & APIs

### Frontend Stateful Routing
The frontend does not use standard URL routing paths (no `react-router-dom`). Instead, it maintains page routing using an `activeTab` React state.
- `'upload'` -> Renders `UploadPanel.jsx` (APK Drag-and-drop & history list).
- `'analysis'` -> Renders `AnalysisView.jsx` (Vite's central dashboard tabs: Overview, Obfuscation, C2, Threat Chains, Manifest).
- `'dissection'` -> Renders `DissectionPage.jsx` (Smart Java structure browser, Class searcher, and Code viewer).
- `'threat-intel'` -> Renders `ThreatIntelView.jsx` (Visual indicators verification and Geo-location tracking map).

### Backend REST API Inventory
All endpoints reside on base URL `http://localhost:8000`:

| Method | Route | Purpose | Used By |
|---|---|---|---|
| **GET** | `/` | Health check (verifies service status & API version). | System / App mount |
| **GET** | `/api/samples` | Lists all analyzed samples. Parses all `pipeline_result.json` files and returns lightweight objects. | UploadPanel.jsx |
| **GET** | `/api/sample/{sample_id}` | Returns full `pipeline_result.json` for a specific sample hash. | AnalysisView.jsx / SmartDissection.jsx |
| **GET** | `/api/sample/{sample_id}/dissection` | Returns the full structure (metadata, manifest, components, native libs, resources) parsed from APK without running the full 9-step flow. | DissectionPage.jsx |
| **GET** | `/api/sample/{sample_id}/dissection/manifest` | Returns parsed AndroidManifest.xml metadata. | ManifestView.jsx |
| **GET** | `/api/sample/{sample_id}/dissection/permissions` | Returns declared permissions along with risk levels. | ManifestView.jsx / SmartDissection.jsx |
| **GET** | `/api/sample/{sample_id}/dissection/components` | Returns parsed activities, services, receivers, and content providers. | ManifestView.jsx |
| **GET** | `/api/sample/{sample_id}/dissection/dex` | Returns DEX stats (number of classes, methods, strings, and entropy). | ObfuscationView.jsx |
| **GET** | `/api/sample/{sample_id}/dissection/classes` | Returns class objects lists with methods and network calls. | SmartDissection.jsx |
| **GET** | `/api/sample/{sample_id}/dissection/code/{class}` | Returns the decompiled Java source code for a specific class. | ClassSourceViewer.jsx |
| **GET** | `/api/sample/{sample_id}/dissection/strings` | Returns extracted strings from Step 2. | SmartDissection.jsx |
| **GET** | `/api/sample/{sample_id}/threat-intel` | Returns aggregated C2 threat-intel: DNS status, geo, and family. | ThreatIntelView.jsx |
| **GET** | `/api/sample/{sample_id}/family` | Returns malware family identification details. | ThreatIntelView.jsx |
| **GET** | `/api/sample/{sample_id}/obfuscation` | Returns obfuscation indicators breakdown, DEX entropy, and notes. | ObfuscationView.jsx |
| **POST**| `/api/sample/{sample_id}/deobfuscate` | Decodes text using Base64, Hex, URL, and XOR decoders. | ObfuscationView.jsx |
| **GET** | `/api/sample/{sample_id}/threat-intel/export/csv` | Exports C2 indicators as a CSV blocklist. | ThreatIntelView.jsx (Export btn) |
| **GET** | `/api/sample/{sample_id}/threat-intel/export/stix` | Exports C2 indicators as a STIX 2.0 JSON bundle. | ThreatIntelView.jsx (Export btn) |
| **GET** | `/api/sample/{sample_id}/threat-intel/export/yara` | Exports a custom YARA signature matching C2 indicators. | ThreatIntelView.jsx (Export btn) |
| **POST**| `/api/upload` | Uploads an APK file. Generates a temporary `upload_id`. | UploadPanel.jsx |
| **POST**| `/api/analyze/{upload_id}` | Triggers async pipeline execution for the uploaded APK. | UploadPanel.jsx |
| **GET** | `/api/sample/{sample_id}/status` | Checks the execution status (queued, running, completed, failed). | App.jsx / CLI |
| **GET** | `/api/diagnostics/jadx` | Verifies JADX installation and reports path verification details. | Diagnostics / Admin |
| **WS**  | `/ws` | Real-time analysis WebSocket stream. | App.jsx |

---

## 7. Database & File Storage Architecture

DroidForensix uses a **schema-less, file-system-driven storage** strategy. There are no relational or document database engines running. The data model relies on standard directory trees and file lookups.

### Workspace Directory Layout
```
analysis/work/
├── c2_geo.json                # Shared IP geolocation lookup cache
├── <sha256>/                  # Subdirectory named after sample's SHA-256 hash
│   ├── step1_extraction.json  # Raw paths and files unpacked by JADX & APKTool
│   ├── step2_strings.json     # Lists of categorized string literals and entropies
│   ├── step3_encodings.json   # Detected Base64/Hex/XOR occurrences
│   ├── step4_payloads.json    # Decoded values, extracted domains and URLs
│   ├── step5_c2.json          # Formatted C2 servers (whitelists applied)
│   ├── step6_chains.json      # Traced threats path connections
│   ├── step7_obfuscation.json # Smali reflection counts and native binaries metrics
│   ├── step8_llm.json         # Severity assessments and risk descriptors
│   ├── dissection.json        # APK structural elements cached for the UI
│   ├── family.json            # Final ensemble family classification results
│   └── pipeline_result.json   # Complete aggregated JSON merging all steps
```

### Labeled Datasets
Three JSON files sit at the root to supply deterministic labels to known samples:
- `ground_truth_test_set.json`
- `ground_truth_drebin.json`
- `ground_truth_fdroid.json`

Schema of ground-truth files:
```json
[
  {
    "sha256": "8a946b5a3...",
    "family": "FakeInstaller",
    "label": "malicious"
  }
]
```

---

## 8. Authentication & Security Flow

There is **no user authentication** implemented in DroidForensix (no login flow, sessions, Clerk, Auth.js, or JWT token system). The server assumes it is running on a secure local Windows workspace (`localhost`).

### External Service Authenticators
1. **CIRCL Client:** Uses `CIRCL_USERNAME` and `CIRCL_PASSWORD` via HTTP Basic Auth. It queries `https://www.circl.lu` for passive DNS history and active SSL records.
2. **NVIDIA NIM:** Uses `NVIDIA_NIM_API_KEY` to authenticate against NVIDIA's developer API for LLM analysis.
3. **Local Ollama:** Communicates via local port binding (`http://localhost:11434`), requiring no authentication.

---

## 9. Core Implementation Highlights

### Obfuscation Analysis & Class Scanner (`backend/dissection.py`)
Rather than relying on basic text searches, `dissection.py` uses Regex to extract class declarations, matching method brackets, and parsing smali method references (e.g., `Lcom/example/Main;->methodName()V`). It computes Shannon entropy values for each DEX file to flag suspicious packing patterns.

### Smart Post-Processing Corrections (`analysis/step9_post_process.py`)
Static analysis pipelines often encounter systematic false-positives and false-negatives. DroidForensix includes two custom post-processing sanity corrections:
1. **Metasploit Booster:** Boosts small APKs (< 100 KB) that make heavy use of reflection (>= 3 times) and dynamic class loaders (>= 1 time), or have package structures containing `"com.metasploit.stage"`, raising risk scores to 85.
2. **Benign Downgrader:** Downgrades benign packages (like calculators matching `"com.jovial.jrpn"`) that trigger high severity verdicts due to standard DTD / Android namespace schemas, capping their risk scores at 25.

---

## 10. Technical Debt & Risks

1. **Self-Contained Executable Pathing:** Hardcoded absolute paths (like `D:\DroidForensix`) in `.env` and `backend/config.py`. If the workspace path changes, these variables must be updated manually.
2. **No concurrency control on uploads:** If multiple large APKs are uploaded simultaneously, the backend handles them in parallel via `loop.run_in_executor`, which might bottleneck disk I/O and JADX processes on lower-end systems.
3. **Flaky CIRCL pDNS timeouts:** Passive DNS endpoints are prone to hanging. The `circl_client.py` sets a strict timeout parameter (`DEFAULT_PDNS_TIMEOUT = 8`) to prevent blocking the extraction task.
4. **Local model availability:** The LLM assessment relies on the presence of the `mistral:7b-instruct-q4_K_M` model. If Ollama is down, the orchestrator falls back to a deterministic rule-based evaluation, which lacks a natural-language narrative.
