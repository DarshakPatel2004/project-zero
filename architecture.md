# DroidForensix System Architecture

This document describes the high-level system architecture, deployment strategy, portable tool integrations, local AI subsystems, and key modules of the DroidForensix pipeline.

---

## 1. System Topology

DroidForensix uses a client-server architecture. The frontend React application acts as a thin client running inside a browser sandbox, while the FastAPI server acts as a thick driver orchestrating heavy system processes natively on the host Windows operating system.

```
       +---------------------------------------------+
       |             Vite React Client               |
       |  - Renders UI Views (HTML5 canvas/WebGL)    |
       |  - WebSocket listener (live progress stats) |
       +---------------------------------------------+
                              |
            HTTP Requests     | WebSockets
            & File Uploads    | (Bi-directional)
                              v
       +---------------------------------------------+
       |             FastAPI Web Server              |
       |  - API Controller & Request Router          |
       |  - WebSocket connections coordinator        |
       |  - Multi-threaded Task Executor             |
       +---------------------------------------------+
                              |
        Internal Python APIs  | Subprocesses Execution
        (Zip, Androguard)     | (JRE, JADX, APKTool)
                              v
       +---------------------------------------------+
       |           Malware Analysis Pipeline         |
       |  - step1_apk_extraction (apktool, jadx)    |
       |  - step2 to step6 (static heuristic flows)  |
       |  - step8_obfuscation (smali & entropy maps) |
       +---------------------------------------------+
               |                             |
     Local IPC | API Calls                   | File Reads/Writes
               v                             v
+-----------------------------+     +-----------------------------+
|    Local Ollama Server      |     |    File System Database     |
|   (Mistral GGUF model)      |     |  (Structured JSON reports)  |
+-----------------------------+     +-----------------------------+
```

---

## 2. Component Decomposition

### A. The Frontend App (React + Vite)
The UI is built with React 19. Rather than using external client routers, the page layouts are rendered conditionally depending on the active state selection.
1. **UploadPanel:** Accepts APK files via standard drag-and-drop actions, uploads them to the server, and lists previously analyzed records.
2. **AnalysisView:** The main tabbed dashboard. Consolidates five dedicated result tabs:
   - **Overview:** General LLM narrative, metadata (package, size, hashes), and recommended actions.
   - **Obfuscation:** Obfuscation scoring meter, indicators lists, and string decoder utility.
   - **C2 Infrastructure:** Passive DNS verification summaries, classification tables, and geographic pins.
   - **Threat Chains:** Detailed steps showing how obfuscated variables resolve to C2 domains.
   - **Manifest:** Renders values from AndroidManifest.xml (SDK numbers, intent filters, permissions).
3. **SmartDissection:** Renders decompiled classes. Lists classes matching suspicious keywords or network endpoints.
4. **ClassSourceViewer:** Fetches raw decompiled Java sources and renders them with line numbers.

### B. The Backend App (FastAPI + Uvicorn)
The server is structured to run entirely locally without external database connections.
1. **Main Router (`backend/main.py`):** Holds REST endpoint handlers, maps upload file buffers, and triggers async pipeline threads via `asyncio.create_task()`.
2. **WebSocket Connection Manager:** Manages open connection sessions and broadcasts status reports.
3. **Dissection Driver (`backend/dissection.py`):** Instantiates androguard `APK` and `DEX` helpers to quickly parse headers, declared components, and DEX method tables.
4. **Attribution Engine (`backend/family_id.py`):** Performs a consensus calculation using Ground Truth maps, signature checks, YARA matches, and family LLM prompts to identify malware family labels.
5. **Geographic Mapper (`backend/threat_intel.py`):** Matches active server IPs against coordinates cached in a geographic file lookup table.

### C. Portable Dependencies
To ensure the pipeline is Windows-native and self-contained, the project includes portable tools under `tools\`:
- **tools\jdk\jdk-21.0.3+9-jre:** Portable OpenJRE. Used to run decompiler JARs.
- **tools\jadx:** JADX compiler batch scripts. Parses DEX to Java class files.
- **tools\apktool:** APKTool batches. Decodes binary Android XML files.
- **tools\node\current:** Portable Node.js. Runs Vite's local dev server.

### D. AI Subsystems (Local LLM vs NIM)
DroidForensix can run LLM assessments through two modes:
1. **Ollama (Default):** Runs a local model on `http://localhost:11434`. By default, it uses `mistral:7b-instruct-q4_K_M`.
2. **NVIDIA NIM:** If `NVIDIA_NIM_API_KEY` is present in the environment variables, the engine shifts to the cloud API (`integrate.api.nvidia.com`), using the `nvidia/nemotron-nano-9b-v2` model.

---

## 3. Technology Alignment & Framework Details

| Feature | Selection | Architectural Rationale |
|---|---|---|
| **OS Host** | Windows 10+ | Targeted at analysts running Windows workstations natively. |
| **Server Engine** | FastAPI | High-speed, async request lifecycle, native WebSockets support. |
| **Worker Model** | ThreadPoolExecutor | Relieves the single-threaded event loop by running CPU-heavy decompile/parse steps in separate worker threads. |
| **Client UI** | React | State management handles real-time updates smoothly. |
| **Asset Engine** | Vite | Faster compilation loops compared to legacy Webpack configs. |
| **Storage Engine** | File-system JSON | Simple file read/write operations provide adequate database performance for local triage, eliminating complex database setup. |
