# DroidForensix: Final Draft Document
## Android Malware Static Analysis Framework with Live 3D Dashboard

**Version:** 1.0  
**Date:** June 10, 2026  
**Status:** Specification Locked — Ready for Implementation  
**Target:** M.Sc. Black Book + Blog Post + Research Paper  
**Timeline:** 6–7 Weeks (June 10 – July 25, 2026)  
**Black Book Submission:** May 2027

---

# TABLE OF CONTENTS

1. [Product Requirements Document (PRD)](#1-product-requirements-document-prd)
2. [Technical Requirements Document (TRD)](#2-technical-requirements-document-trd)
3. [Backend Schema & API Specification](#3-backend-schema--api-specification)
4. [Application Flow & Architecture](#4-application-flow--architecture)
5. [Data Models & Schemas](#5-data-models--schemas)
6. [Testing & Validation Framework](#6-testing--validation-framework)
7. [Success Criteria & Deliverables](#7-success-criteria--deliverables)
8. [Phase 2+ Roadmap](#8-phase-2-roadmap)

---

# 1. PRODUCT REQUIREMENTS DOCUMENT (PRD)

## 1.1 Executive Summary

DroidForensix is an end-to-end Android malware static analysis framework that automates the detection, decoding, and correlation of obfuscated strings and C2 infrastructure within Android APKs. The system features a real-time 3D visualization dashboard powered by WebSocket streaming, enabling security researchers to observe threat chains as they are discovered.

**Core Value Proposition:** Reduce manual analysis time from hours to minutes while maintaining >85% accuracy in encoding detection and C2 extraction through a 7-step automated pipeline augmented by local LLM reasoning.

## 1.2 Problem Statement

### Current Pain Points
- **Manual Reverse Engineering Bottleneck:** Security analysts spend 4–8 hours per APK manually decompiling, searching for encoded strings, and tracing C2 infrastructure.
- **Obfuscation Arms Race:** Modern Android malware employs Base64, XOR, custom byte-shifting, and multi-layer encoding to hide C2 URLs and payload delivery mechanisms.
- **Correlation Blindness:** Analysts struggle to connect isolated encoded strings into coherent threat chains showing the full attack progression.
- **No Real-Time Visibility:** Existing tools operate in batch mode; analysts cannot observe discoveries as they happen during analysis.
- **LLM Integration Gap:** No existing open-source tool integrates local LLMs for automated severity assessment and threat narrative generation.

### Target Users
| User Type | Primary Need | Usage Frequency |
|-----------|--------------|-----------------|
| Malware Analysts | Automated string extraction + decoding | Daily |
| Threat Intelligence Teams | C2 infrastructure mapping | Weekly |
| Academic Researchers | Reproducible analysis pipeline | Per-study |
| SOC Analysts | Quick triage of suspicious APKs | Ad-hoc |
| M.Sc. Students | Complete framework for thesis work | Semester-long |

## 1.3 Functional Requirements

### FR-1: APK Ingestion & Decompilation
- **FR-1.1:** Accept APK file upload via API or file-system path.
- **FR-1.2:** Unpack APK using apktool to extract manifest, resources, and DEX files.
- **FR-1.3:** Decompile DEX to Java source using Jadx-CLI with selective deobfuscation (heuristic-based name length filtering).
- **FR-1.4:** Extract native library strings (.so files) using Radare2.
- **FR-1.5:** Generate SHA-256 hash and metadata for each sample.

### FR-2: String Enumeration & Entropy Analysis
- **FR-2.1:** Extract all string literals from decompiled Java files using regex patterns.
- **FR-2.2:** Extract byte arrays and numeric constants from source code.
- **FR-2.3:** Parse Android resources (strings.xml, raw/ directory files).
- **FR-2.4:** Calculate Shannon entropy for each extracted string/byte sequence.
- **FR-2.5:** Output structured JSON per sample containing all strings with metadata.

### FR-3: Encoding Detection & Classification
- **FR-3.1:** Detect Base64 encoding via alphabet validation + decode verification.
- **FR-3.2:** Detect URL-safe Base64 variants.
- **FR-3.3:** Detect hexadecimal encoding patterns.
- **FR-3.4:** Detect XOR encoding through entropy-based brute-force (keys 0–255) with readability validation (>70% printable characters).
- **FR-3.5:** Flag suspected custom encoding for high-entropy strings that fail standard detection.
- **FR-3.6:** Assign confidence score (0.0–1.0) to each detected encoding.
- **FR-3.7:** Validate decoded output for meaningful content (URLs, IPs, domains, readable text).

### FR-4: Payload Decoding & Artifact Extraction
- **FR-4.1:** Apply appropriate decoder based on detected encoding type.
- **FR-4.2:** Extract URLs, IPv4/IPv6 addresses, domain names, and email addresses from decoded output.
- **FR-4.3:** Detect binary payloads via magic byte identification.
- **FR-4.4:** Normalize and post-process extracted artifacts (URL canonicalization, IP validation).
- **FR-4.5:** Boost confidence scores when decoded output validates against known patterns.

### FR-5: C2 Infrastructure Extraction
- **FR-5.1:** Merge decoded payloads with directly extracted strings from source.
- **FR-5.2:** Parse C2 components: protocol (HTTP/HTTPS/DNS/raw), domain, port, path, query parameters.
- **FR-5.3:** Classify IP addresses (private RFC1918, public, VPN/proxy, loopback).
- **FR-5.4:** Infer communication type from code context (HTTP request construction, socket creation, DNS resolution).
- **FR-5.5:** Identify fallback/backup C2s from conditional logic in code.
- **FR-5.6:** Assign confidence score to each C2 extraction.

### FR-6: Threat Chain Correlation
- **FR-6.1:** Build directed dependency graph linking encoded strings → decoding functions → decoded artifacts → usage locations → C2 infrastructure.
- **FR-6.2:** Perform shallow dataflow tracing (maximum 5 steps) to establish causal relationships.
- **FR-6.3:** Handle multiple independent decode paths as separate threat chains.
- **FR-6.4:** Calculate composite confidence score for each chain based on step confidences.
- **FR-6.5:** Output threat chains as structured JSON with severity indicators.

### FR-7: LLM-Powered Assessment
- **FR-7.1:** Connect to local Ollama instance running Llama Primus 8B.
- **FR-7.2:** Format threat chains into analyst-readable context for LLM consumption.
- **FR-7.3:** Generate structured assessment containing: severity (critical/high/medium/low), risk score (0–100), narrative explanation, recommended actions.
- **FR-7.4:** Validate LLM output against JSON schema; retry with stricter prompt if invalid.
- **FR-7.5:** Implement sanity-check layer cross-referencing LLM severity against detected indicators.
- **FR-7.6:** Provide fallback default assessment if LLM fails after retries.

### FR-8: Real-Time 3D Dashboard
- **FR-8.1:** Display live threat graph in 3D space with nodes (encoding, payload, function, C2, config) and edges (decode, usage, exfiltration).
- **FR-8.2:** Support 4 camera views: Threat Graph, Clustering Space, Timeline Animation, Live Status.
- **FR-8.3:** Animate node appearance as analysis progresses (fade-in on detection).
- **FR-8.4:** Enable node interaction: click for details sidebar, hover to highlight connected edges.
- **FR-8.5:** Support filtering by node type and confidence threshold.
- **FR-8.6:** Display 3D clustering view: X=encoding complexity, Y=C2 sophistication, Z=exfiltration volume.
- **FR-8.7:** Display 3D timeline showing attack progression with play/pause/scrub controls.
- **FR-8.8:** Show live metrics: progress bar, encoding count, C2 count, chain count, event log.

### FR-9: Report Generation
- **FR-9.1:** Export complete analysis as JSON (machine-readable, all data).
- **FR-9.2:** Export as interactive HTML (standalone, embeds visualizations).
- **FR-9.3:** Export as PDF (static, with embedded visualizations and narrative).
- **FR-9.4:** Include sample metadata, all threat chains, LLM assessment, and accuracy metrics.

### FR-10: Sample Management
- **FR-10.1:** Maintain sample metadata CSV: {sample_name, sha256, family, vt_detections}.
- **FR-10.2:** Support batch processing of multiple APKs.
- **FR-10.3:** Validate samples against VirusTotal (>15 vendor detections for malware confirmation).

## 1.4 Non-Functional Requirements

### NFR-1: Performance
- **NFR-1.1:** Single APK analysis must complete within 5 minutes for samples <50MB.
- **NFR-1.2:** Dashboard must maintain >30 FPS during 3D rendering with ≤50 nodes.
- **NFR-1.3:** WebSocket event latency must be <100ms from backend to frontend.
- **NFR-1.4:** Batch processing of 50 samples must complete within 24 hours.

### NFR-2: Accuracy
- **NFR-2.1:** Encoding detection precision >85% (manual review of 10 samples).
- **NFR-2.2:** C2 extraction precision >85% (VirusTotal IoC matching).
- **NFR-2.3:** Threat chain correlation precision >80% (manual review).
- **NFR-2.4:** LLM severity assessment accuracy >75% (subjective judgment vs. indicators).
- **NFR-2.5:** Overall pipeline success rate >85% (samples completing all 7 steps).

### NFR-3: Reliability
- **NFR-3.1:** Pipeline must handle corrupted/malformed APKs gracefully with error logging.
- **NFR-3.2:** LLM integration must have 3 retry attempts before fallback.
- **NFR-3.3:** WebSocket connection must auto-reconnect on disconnect with exponential backoff.
- **NFR-3.4:** All analysis steps must be idempotent (re-running produces same results).

### NFR-4: Security
- **NFR-4.1:** Malware samples must be analyzed in isolated project directory (no system-wide exposure).
- **NFR-4.2:** No sample data must leave local machine (all processing local, no cloud upload).
- **NFR-4.3:** LLM queries must not include actual malicious payloads — only metadata and context.
- **NFR-4.4:** LLM inference may run on a separate host machine (e.g., Windows host with GPU) via local network API; only threat chain metadata (no raw payloads) traverses the network.

### NFR-5: Usability
- **NFR-5.1:** Dashboard must be accessible via modern web browser (Chrome, Firefox, Edge) at localhost:3000.
- **NFR-5.2:** 3D visualizations must support mouse controls: rotate (left-drag), zoom (scroll), pan (right-drag).
- **NFR-5.3:** Camera toggle must switch views within 1 second.
- **NFR-5.4:** Event log must display last 5 events with timestamp.

### NFR-6: Scalability (Phase 1)
- **NFR-6.1:** System must handle 50 samples in evaluation dataset.
- **NFR-6.2:** Dashboard must render up to 50 nodes without performance degradation.
- **NFR-6.3:** Single-threaded execution acceptable for Phase 1.

## 1.5 Constraints & Limitations

| Constraint | Impact | Mitigation |
|------------|--------|------------|
| Static analysis only | Runtime-encoded strings undetectable | Phase 2 adds dynamic analysis |
| No fine-tuned LLM | Generic reasoning, potential hallucinations | Prompt engineering + validation layer |
| Single-threaded | Slower batch processing | Acceptable for 50-sample Phase 1 |
| Hardcoded C2 only | Dynamic URL construction (e.g., string concatenation) missed | Document as known limitation |
| Local LLM (8B) | Less powerful than cloud models | Privacy-preserving, no API costs; smaller models (3B) or remote host inference for resource-constrained environments |
| Kali Linux native | VM performance issues; Windows not officially supported | **Primary: Kali bare-metal (mandated). Alternative: Kali VM with Ollama on host (GPU/RAM). Windows native possible but off-supported-path — toolchain debugging required.** |

### 1.5.1 Platform Requirements & Windows Compatibility

The specification mandates a bare-metal Kali Linux installation as the primary host platform. This choice guarantees a zero-config security toolchain. However, alternative environments can be adapted with varying levels of effort.

#### Why Kali Linux is Required
The automated pipeline depends heavily on external security tools that are natively packaged, pre-installed, or highly optimized on Kali:
- **apktool** — APK unpacking and resource decoding
- **jadx** — DEX-to-Java decompilation (CLI version)
- **radare2** — Native library string extraction (.so analysis)
- **ollama** — Local LLM orchestration and model hosting

#### Windows Adaptation Options (Not officially supported in spec)
If Windows must be used as the host platform, the following approaches can be taken:

| Approach | Feasibility | Effort | Notes |
| :--- | :--- | :--- | :--- |
| **WSL2 + Kali Linux** | **Best Alternative** | Medium | Runs actual Kali tools natively in WSL. Good performance, GPU/CUDA pass-through support. |
| **Native Windows Ports** | Possible but Fragile | High | Requires compiling/downloading Windows binaries for each tool and modifying Python subprocess paths. |
| **Docker on Windows** | Sub-optimal | Medium | Adds containerization overhead. Defeats "native toolchain" requirement. |
| **Full Kali VM** | Explicitly Rejected | Low setup / High runtime | VM performance overhead (especially GPU virtualization) makes local LLM inference extremely slow. |

> [!TIP]
> **Recommendation:** If running on Windows, using **WSL2 with Kali Linux** (`wsl --install -d kali-linux`) is the only viable path that satisfies the toolchain requirements without extensive codebase rewrites.

#### Space-Saving Windows Setup
To minimize the storage footprint on a Windows machine to around **3–4 GB** (excluding the LLM model):
1. **Python 3.10+**: ~100 MB
2. **Java JRE** (for apktool/jadx): ~150 MB
3. **apktool.jar + jadx.jar**: ~50 MB
4. **radare2 Windows builds**: ~100 MB
5. **Ollama for Windows**: ~200 MB (+ model size)
6. **Node.js**: ~50 MB

#### Model Size Mitigation Options
A standard 8B model requires ~4.5 GB of storage/VRAM. To reduce this resource pressure:
- **Smaller models**: Use `llama3.2:3b` (~2.0 GB) or `phi3:mini` (~2.3 GB) and adjust prompt complexity.
- **Quantization**: Ollama supports 4-bit quantization automatically (e.g., standard Q4_K_M runs).
- **Disk Offloading**: Configure Ollama to memory-map layers to disk (slower inference, but lower VRAM/RAM overhead).

#### Code Adaptations Required for Windows Native
If avoiding WSL2 and running natively on Windows cmd/PowerShell, the following codebase changes are necessary:
- **Subprocess calls**: Update Python wrappers to handle `.exe` extensions and escape spaces in file paths.
- **Path separators**: Use `os.path` or `pathlib` to avoid hardcoded `/` path separators.
- **Shell commands**: Replace commands relying on `bash -c` syntax with Windows-native equivalents or invoke executables directly.

## 1.6 User Stories


### US-1: Malware Analyst Daily Workflow
> *As a malware analyst, I want to drop an APK into the system and watch a 3D threat graph build in real-time, so that I can identify C2 infrastructure and encoding patterns within minutes instead of hours.*

**Acceptance Criteria:**
- Analyst uploads APK via API or file path
- Within 30 seconds, first encoding detections appear on dashboard
- Within 3 minutes, complete threat chain is visible with C2 nodes
- Analyst can click any node to see source location and confidence score
- Final report auto-generated in JSON + HTML formats

### US-2: Threat Intelligence Mapping
> *As a threat intel analyst, I want to process 50 malware samples and cluster them by C2 sophistication and encoding complexity, so that I can identify campaign relationships and actor TTPs.*

**Acceptance Criteria:**
- Batch upload 50 APKs
- Clustering view shows 3D scatter plot of all samples
- Samples from same family cluster spatially
- Analyst can filter by confidence threshold
- Export clustering data as CSV for external tools

### US-3: Academic Research Reproducibility
> *As an M.Sc. student, I want a fully documented pipeline that I can run on new samples and get consistent, reproducible results with accuracy metrics, so that I can include validated findings in my black book.*

**Acceptance Criteria:**
- All 7 steps produce deterministic output for same input
- Accuracy metrics calculated against manual ground truth
- Reports include methodology, results, and known limitations
- Code is documented with docstrings and architecture diagrams
- GitHub repository ready for submission

### US-4: SOC Quick Triage
> *As a SOC analyst, I want to quickly assess whether a suspicious APK contains active C2 infrastructure and get a severity score, so that I can prioritize incident response.*

**Acceptance Criteria:**
- Upload APK, get LLM severity assessment within 5 minutes
- Dashboard shows red/critical indicators if active C2 detected
- Report includes recommended containment actions
- No specialized malware analysis knowledge required

---

# 2. TECHNICAL REQUIREMENTS DOCUMENT (TRD)

## 2.1 System Architecture Overview

```
┌─────────────────────────────────────────────────────────────────────────┐
│                           DROIDFORENSIX ARCHITECTURE                      │
├─────────────────────────────────────────────────────────────────────────┤
│                                                                         │
│  ┌──────────────┐    ┌──────────────┐    ┌──────────────┐              │
│  │   FRONTEND   |◄──►│   BACKEND    |◄──►│   ANALYSIS   │              │
│  │  (React +    │WS  │  (FastAPI +  │API │  (7-Step     │              │
│  │   Three.js)  │    │  WebSocket)  │    │  Pipeline)   │              │
│  └──────────────┘    └──────────────┘    └──────────────┘              │
│         ▲                   ▲                   ▲                      │
│         │                   │                   │                      │
│    ┌────┴────┐         ┌────┴────┐       ┌────┴────┐                │
│    │ Browser │         │ Ollama  │       │ External│                │
│    │localhost│         │  (LLM)  │       │  Tools  │                │
│    │ :3000   │         │ :11434  │       │         │                │
│    └─────────┘         └─────────┘       └─────────┘                │
│                                          (apktool, jadx, radare2)    │
│                                                                         │
└─────────────────────────────────────────────────────────────────────────┘
```

## 2.2 Technology Stack

### 2.2.1 Core Platform
| Component | Technology | Version | Purpose |
|-----------|------------|---------|---------|
| OS | Kali Linux | Latest (native) | Host platform for security tools |
| Python | CPython | 3.10+ | Analysis pipeline + backend |
| Runtime | Uvicorn | 0.24.0 | ASGI server for FastAPI |

### 2.2.2 Backend
| Component | Technology | Version | Purpose |
|-----------|------------|---------|---------|
| Web Framework | FastAPI | 0.104.1 | REST API + WebSocket server |
| WebSocket | websockets | 12.0 | Real-time event streaming |
| Data Validation | Pydantic | 2.5.0 | Request/response schema validation |
| HTTP Client | requests | 2.31.0 | External API calls (VirusTotal) |
| Phone Validation | phonenumbers | 8.13.0 | Extracted phone number validation |
| LLM Client | ollama | 0.1.0 | Local LLM integration |

### 2.2.3 Frontend
| Component | Technology | Version | Purpose |
|-----------|------------|---------|---------|
| Framework | React | 18.x | UI component architecture |
| Bundler | Vite / CRA | Latest | Build tooling |
| 3D Rendering | Three.js | r150+ | 3D visualization engine |
| Controls | OrbitControls | Three.js addon | Camera rotation/zoom/pan |
| State Management | React Hooks | Built-in | Component state |
| WebSocket Client | Native WebSocket | Browser API | Real-time communication |

### 2.2.4 Analysis Tools (External)
| Tool | Version | Purpose | Integration Method |
|------|---------|---------|-------------------|
| apktool | 2.7.0 | APK unpacking | CLI subprocess |
| Jadx-CLI | Latest | DEX decompilation | CLI subprocess |
| Radare2 | Latest | Native lib analysis | CLI subprocess |
| Ollama | Latest | LLM hosting | HTTP API (configurable host:port) |
| Llama 3.2 3B / 8B | Latest | Threat assessment | Ollama model (configurable) |

### 2.2.5 Data Storage
| Type | Format | Purpose |
|------|--------|---------|
| Analysis Output | JSON | Machine-readable results |
| Sample Metadata | CSV | Sample catalog |
| Reports | JSON/HTML/PDF | Human-readable deliverables |
| Event Stream | WebSocket JSON | Real-time dashboard updates |

## 2.3 Analysis Pipeline Architecture (7 Steps)

```
┌─────────────────────────────────────────────────────────────────────────┐
│                    7-STEP ANALYSIS PIPELINE                               │
├─────────────────────────────────────────────────────────────────────────┤
│                                                                         │
│  ┌─────────┐   ┌─────────┐   ┌─────────┐   ┌─────────┐              │
│  │  STEP 1 |──►│  STEP 2 |──►│  STEP 3 |──►│  STEP 4 │              │
│  │  APK    │   │  String │   │  Encoding│   │  Decode │              │
│  │Extract  │   │  Enum   │   │  Detect  │   │ Payload │              │
│  └─────────┘   └─────────┘   └─────────┘   └─────────┘              │
│       │             │             │             │                      │
│       ▼             ▼             ▼             ▼                      │
│  ┌─────────┐   ┌─────────┐   ┌─────────┐   ┌─────────┐              │
│  │ apktool │   │  Regex  │   │ Pattern │   │ Decoder │              │
│  │  jadx   │   │  Entropy│   │  Match  │   │  Engine │              │
│  │ radare2 │   │  Parser │   │ Validate│   │ Extract │              │
│  └─────────┘   └─────────┘   └─────────┘   └─────────┘              │
│                                                                         │
│  ┌─────────┐   ┌─────────┐   ┌─────────┐                             │
│  │  STEP 5 |──►│  STEP 6 |──►│  STEP 7 │                             │
│  │   C2    │   │  Threat │   │   LLM   │                             │
│  │Extract  │   │  Chain  │   │ Assess  │                             │
│  └─────────┘   └─────────┘   └─────────┘                             │
│       │             │             │                                    │
│       ▼             ▼             ▼                                    │
│  ┌─────────┐   ┌─────────┐   ┌─────────┐                            │
│  │  URL    │   │  Graph  │   │ Ollama  │                            │
│  │  Parse  │   │ Builder │   │ Primus  │                            │
│  │ Classify│   │  Trace  │   │  8B     │                            │
│  └─────────┘   └─────────┘   └─────────┘                            │
│                                                                         │
│  ════════════════════════════════════════════════════════               │
│                    EVENT STREAMING LAYER                                │
│  ════════════════════════════════════════════════════════               │
│                                                                         │
│  encoding_detected ──► payload_decoded ──► c2_extracted              │
│       │                    │                    │                      │
│       ▼                    ▼                    ▼                      │
│  threat_chain_created ──► analysis_complete ──► error               │
│                                                                         │
└─────────────────────────────────────────────────────────────────────────┘
```

## 2.4 Component Specifications

### 2.4.1 Step 1: APK Extraction Module
**Input:** APK file path  
**Output:** Decompiled source tree, native libraries, manifest, resources  
**Sub-components:**
- APK Unpacker: apktool subprocess wrapper
- DEX Decompiler: Jadx-CLI with heuristic deobfuscation (filters names >50 chars)
- Native Extractor: Radare2 string dump for .so files
- Metadata Generator: SHA-256, file size, package name

**Error Handling:**
- Corrupted APK → log error, skip to next sample
- Jadx failure → fallback to apktool smali output
- Missing native libs → continue with empty native_strings

### 2.4.2 Step 2: String Enumeration Module
**Input:** Decompiled source tree, resources, native strings  
**Output:** JSON with categorized strings + entropy scores  
**Sub-components:**
- Java String Extractor: Regex for string literals, byte arrays, numeric constants
- Resource Parser: XML parser for strings.xml, raw file reader
- Entropy Calculator: Shannon entropy H = -Σ p(x) log₂ p(x)
- Output Formatter: Structured JSON with categories

**Categories:**
- `string_literals`: Standard Java strings
- `byte_arrays`: Hex-encoded byte sequences
- `numeric_constants`: Suspicious numeric values (ports, keys)
- `resource_strings`: From strings.xml and raw/
- `native_strings`: From .so files via Radare2

### 2.4.3 Step 3: Encoding Detection Module
**Input:** All enumerated strings with entropy scores  
**Output:** Encoding candidates with type, confidence, decoded preview  
**Algorithm Phases:**

**Phase 1: Pattern Matching**
- Base64 regex: `[A-Za-z0-9+/]{20,}={0,2}`
- URL-safe Base64: `[A-Za-z0-9_-]{20,}`
- Hex regex: `[0-9A-Fa-f]{16,}`
- Alphabet validation: Check character set compliance

**Phase 2: Decode Validation**
- Attempt Base64 decode → check if output is valid UTF-8
- Check decoded output for URLs, IPs, domains
- Boost confidence if meaningful content found

**Phase 3: XOR Brute-Force**
- Trigger only if entropy > 5.0 (high randomness)
- Iterate keys 0–255
- Score each result: % printable ASCII characters
- Accept if >70% printable
- Store top 3 candidate keys with scores

**Phase 4: Custom Encoding Flag**
- High entropy (>7.0) + failed all standard detection → flag as suspected custom
- Pattern analysis: repeating byte sequences, rhythmic structure
- Store for manual analyst review

**Confidence Scoring:**
| Factor | Weight | Description |
|--------|--------|-------------|
| Alphabet match | 0.3 | Character set compliance |
| Decode success | 0.3 | Successful decoding |
| Meaningful output | 0.2 | Contains URLs/IPs/readable text |
| Entropy alignment | 0.2 | Expected entropy for encoding type |

### 2.4.4 Step 4: Decoding & Extraction Module
**Input:** Encoding candidates with detected types  
**Output:** Decoded artifacts (URLs, IPs, domains, binaries)  
**Sub-components:**
- Decoder Router: Maps encoding type to decoder function
- Base64 Decoder: Standard + URL-safe variants
- Hex Decoder: Byte array reconstruction
- XOR Decoder: Applies brute-forced key
- Artifact Extractor: Regex patterns for URLs, IPs, emails, phone numbers
- Binary Detector: Magic byte identification (MZ, ELF, PDF, etc.)
- Post-Processor: URL normalization, IP validation, domain extraction

**Validation Rules:**
- URLs must have valid scheme (http/https) + resolvable domain
- IPs must pass regex + inet_aton validation
- Emails must match RFC 5322 pattern
- Phone numbers validated via phonenumbers library

### 2.4.5 Step 5: C2 Infrastructure Module
**Input:** Decoded artifacts + direct source strings  
**Output:** Structured C2 records with classification  
**Sub-components:**
- URL Parser: Extract protocol, domain, port, path, query
- IP Classifier: Private (10/8, 172.16/12, 192.168/16), public, VPN
- Protocol Inferrer: HTTP from URL scheme, DNS from resolver calls, raw from socket
- Fallback Detector: Code analysis for conditional C2 assignment
- Confidence Scorer: Based on URL structure, IP type, code context

**C2 Record Schema:**
```
c2_record = {
  raw_url: string,
  protocol: "http|https|dns|tcp|udp|raw",
  domain: string | null,
  ip: string | null,
  port: int | null,
  path: string,
  query_params: dict,
  ip_classification: "private|public|vpn|loopback",
  communication_type: "http_request|dns_query|socket|other",
  is_fallback: boolean,
  source_location: "ClassName.java:line",
  confidence: 0.0-1.0
}
```

### 2.4.6 Step 6: Correlation Module
**Input:** All C2 records, decoded artifacts, source locations  
**Output:** Threat chains as directed graphs  
**Sub-components:**
- Dependency Builder: Links strings → functions → artifacts → C2
- Dataflow Tracer: Shallow tracing (max 5 steps) through call graph
- Path Separator: Identifies independent decode paths
- Chain Assembler: Builds sequential threat chains
- Confidence Aggregator: Weighted average of step confidences

**Graph Building Rules:**
1. Start node: Encoded string (highest entropy, detected encoding)
2. Intermediate: Decoding function call location
3. Intermediate: Decoded artifact (URL, IP, binary)
4. Intermediate: Usage location (where artifact is consumed)
5. End node: C2 infrastructure

**Chain Confidence Formula:**
```
chain_confidence = Σ(step_confidence × step_weight) / Σ(step_weight)
where step_weights = [0.15, 0.20, 0.25, 0.20, 0.20] for steps 1-5
```

### 2.4.7 Step 7: LLM Assessment Module
**Input:** Threat chains formatted as readable text  
**Output:** Structured severity assessment  
**Sub-components:**
- Prompt Builder: Formats threat chains into analyst context
- Ollama Client: HTTP POST to localhost:11434/api/generate
- Response Parser: Extracts JSON from LLM output
- Schema Validator: Validates against expected JSON schema
- Sanity Checker: Cross-references severity with indicator count
- Fallback Engine: Default assessment if LLM fails

**System Prompt Design:**
- Role: Expert malware threat analyst
- Task: Assess severity based on provided threat chains
- Constraints: Output must be valid JSON only, no markdown
- Context: Include chain count, C2 count, encoding types, active vs. dormant indicators

**Output Schema:**
```
assessment = {
  severity: "critical|high|medium|low",
  risk_score: 0-100,
  narrative: "explanation string",
  primary_threat: "c2_exfiltration|ransomware|spyware|banking_trojan|other",
  recommended_actions: ["action1", "action2"],
  confidence: 0.0-1.0
}
```

## 2.5 Backend Architecture

### 2.5.1 FastAPI Application Structure
```
backend/
├── main.py          # FastAPI app + WebSocket endpoint + CORS
├── events.py        # Event dataclass definitions + serialization
└── validators.py    # JSON schema validation + event type checking
```

**Endpoints:**
| Method | Path | Purpose | Auth |
|--------|------|---------|------|
| GET | / | Health check | None |
| GET | /ws | WebSocket connection | None |
| POST | /analyze | Trigger analysis (optional REST fallback) | None |
| GET | /samples | List processed samples | None |
| GET | /samples/{id} | Get sample analysis result | None |

### 2.5.2 WebSocket Event System
**Connection Model:**
- Backend maintains list of active WebSocket connections
- Pipeline emits events at key milestones
- Backend broadcasts events to all connected clients
- Frontend receives events and updates React state

**Event Lifecycle:**
```
1. Client connects → WebSocket handshake
2. Pipeline starts → emit "analysis_started"
3. Step 3 detects encoding → emit "encoding_detected"
4. Step 4 decodes payload → emit "payload_decoded"
5. Step 5 extracts C2 → emit "c2_extracted"
6. Step 6 builds chain → emit "threat_chain_created"
7. Step 7 completes → emit "analysis_complete"
8. Any error → emit "error" with context
```

### 2.5.3 CORS Configuration
- Allow origin: `http://localhost:3000`
- Allow methods: GET, POST, OPTIONS
- Allow headers: Content-Type, Authorization
- Allow WebSocket upgrade from localhost:3000

## 2.6 Frontend Architecture

### 2.6.1 React Component Hierarchy
```
App.jsx (Main Container)
├── Camera Toggle (4 views)
├── WebSocket Manager
│   └── State: events, nodes, edges, metrics
├── ThreatGraph.jsx (3D Force-Directed Graph)
│   ├── Node Renderer (colored by type)
│   ├── Edge Renderer (colored by relationship)
│   ├── Interaction Handler (click, hover, filter)
│   └── Detail Sidebar (node info)
├── ClusteringView.jsx (3D Scatter Plot)
│   ├── Point Renderer (per sample)
│   ├── Axis Labels (X, Y, Z)
│   └── Detail Panel (sample info)
├── TimelineView.jsx (3D Path Animation)
│   ├── Path Renderer (threat chain)
│   ├── Animation Controller (play/pause/scrub)
│   └── Chain Selector (toggle between chains)
└── LiveStatus.jsx (Metrics + Event Log)
    ├── Progress Bar
    ├── Metric Boxes (4 counters)
    └── Event Log (last 5 events)
```

### 2.6.2 Three.js Setup
**Scene Configuration:**
- Renderer: WebGLRenderer with antialiasing, alpha: false
- Camera: PerspectiveCamera (fov: 75, near: 0.1, far: 1000)
- Controls: OrbitControls (enableDamping, dampingFactor: 0.05)
- Lighting: AmbientLight (0.4 intensity) + DirectionalLight (0.8 intensity)
- Background: Dark theme (#0a0a0a) for security dashboard aesthetic

**Node Types & Colors:**
| Type | Color | Description |
|------|-------|-------------|
| encoding | #FF6B6B (Red) | Detected encoded string |
| payload | #4ECDC4 (Teal) | Decoded payload artifact |
| function | #45B7D1 (Blue) | Decoding/usage function |
| c2 | #FF4757 (Crimson) | C2 infrastructure |
| config | #FFA502 (Orange) | Configuration artifact |

**Edge Types & Colors:**
| Type | Color | Description |
|------|-------|-------------|
| decode | #A29BFE (Purple) | Encoding → decoded relationship |
| usage | #FD79A8 (Pink) | Function uses artifact |
| exfiltration | #E17055 (Orange) | Data flows to C2 |

### 2.6.3 WebSocket Client
**Connection Logic:**
- Connect to `ws://localhost:8000/ws` on app mount
- Implement exponential backoff reconnect (1s, 2s, 4s, 8s, max 30s)
- Heartbeat ping every 30 seconds
- Message handler routes events to appropriate component state updates

**State Management:**
- `events`: Array of last 50 events (FIFO)
- `nodes`: Map of node_id → node_data (for graph rendering)
- `edges`: Array of edge objects (source, target, type)
- `metrics`: Counter object {encodings, payloads, c2s, chains}
- `currentView`: Active camera view (graph|clustering|timeline|status)

## 2.7 Integration Points

### 2.7.1 Pipeline ↔ Backend Integration
**Communication Method:** Direct Python function calls (async wrapper)  
**Event Emission:** Pipeline calls backend event broadcaster function  
**Synchronization:** Pipeline is synchronous; WebSocket broadcast is async — use asyncio wrapper  
**Error Propagation:** Pipeline exceptions caught → emit "error" event → continue to next sample

### 2.7.2 Backend ↔ Frontend Integration
**Protocol:** WebSocket (ws://)  
**Message Format:** JSON with {event_type, timestamp, data}  
**Connection Lifecycle:**
1. Frontend loads → attempts WebSocket connection
2. Backend accepts → adds to active connections list
3. Pipeline events → broadcast to all connections
4. Frontend disconnects → remove from list, allow reconnect

### 2.7.3 Backend ↔ Ollama Integration
**Protocol:** HTTP POST to `http://${OLLAMA_HOST}:11434/api/generate` (default: `localhost`)  
**Request Format:** JSON with {model, prompt, stream, format}  
**Response Format:** JSON with {response, done}  
**Timeout:** 120 seconds per LLM call  
**Retry Logic:** 3 attempts with exponential backoff, then fallback  

**Deployment Options:**
| Mode | OLLAMA_HOST | Use Case |
|------|-------------|----------|
| Local | `localhost` | Kali bare-metal with GPU |
| VM → Host | `10.0.2.2` (VirtualBox NAT) / `<host-LAN-IP>` (Bridged) | Kali VM, Ollama on Windows host (GPU) (see [Section 2.7.3.1](#2731-architecture-host-ollama--vm-pipeline-setup)) |
| Remote | `<remote-ip>` | Dedicated inference server |

**Model Selection:** Configurable via `OLLAMA_MODEL` env var (default: `llama3.2:3b` for CPU/VM; `llama3.2:8b` for GPU). "Llama Primus" in spec refers to any cyber-finetuned Llama variant.

### 2.7.3.1 Architecture: Host Ollama + VM Pipeline Setup

Running a local 8B LLM inside a virtual machine (VM) presents significant resource constraints. Without GPU pass-through, VMs default to CPU-only inference, resulting in **10x to 30x slower execution** (minutes per prompt instead of seconds). 

To solve this, the recommended hybrid architecture runs the Ollama model on the Windows host (utilizing host GPU/RAM) while the analysis pipeline runs inside the Kali VM.

#### Host Ollama + VM Pipeline Architecture Diagram

```
┌─────────────────────────────────────────────────────────────┐
│                     WINDOWS HOST                             │
│  ┌─────────────────┐    ┌─────────────────────────────────┐ │
│  │   Ollama Server │    │         Your GPU + RAM          │ │
│  │  (port 11434)   │◄───│  Runs Llama 3B/8B at full speed │ │
│  └────────┬────────┘    └─────────────────────────────────┘ │
│           │                                                │
│           │ HTTP API (localhost:11434)                     │
│           ▼                                                │
│  ┌─────────────────┐                                      │
│  │  VM (VirtualBox │                                      │
│  │  / VMware)      │                                      │
│  │  Kali Linux     │                                      │
│  │  Pipeline       │                                      │
│  │  (Python)       │                                      │
│  └────────┬────────┘                                      │
│           │                                                │
│           │ HTTP request to host                           │
└───────────│────────────────────────────────────────────────┘
            │
            ▼
    ┌───────────────┐
    │  Host Network │
    │  (NAT/Bridge) │
    └───────────────┘
```

#### Step-by-Step Setup Instructions

##### 1. Configure and Expose Ollama on Windows Host
By default, Ollama only listens to local requests (`127.0.0.1`). You must bind it to all interfaces (`0.0.0.0`) to allow VM access:
- Set the environment variable `OLLAMA_HOST` to `0.0.0.0:11434`.
  - **PowerShell (Temporary):**
    ```powershell
    $env:OLLAMA_HOST = "0.0.0.0:11434"
    ollama serve
    ```
  - **Windows System-wide (Persistent):** Add `OLLAMA_HOST` with value `0.0.0.0:11434` to System Environment Variables and restart Ollama.
- Pull the model on the host:
  ```cmd
  ollama pull llama3.2:3b
  ```
- Verify connectivity from the host:
  ```cmd
  curl http://localhost:11434/api/tags
  ```

##### 2. Configure Windows Firewall Inbound Rule
To prevent Windows Defender from blocking inbound traffic from the VM, run the following command as **Administrator** in PowerShell:
```powershell
New-NetFirewallRule -DisplayName "Ollama API" -Direction Inbound -LocalPort 11434 -Protocol TCP -Action Allow
```

##### 3. Configure VM Network Mode
Based on your VM network type, identify the host access URL:
- **NAT Mode (Default, Easiest):** VirtualBox maps the host loopback to `10.0.2.2`. 
  - Access URL: `http://10.0.2.2:11434`
- **Bridged Mode:** Access via the host's actual LAN IP (e.g., `192.168.x.x`).
  - Access URL: `http://<host-LAN-IP>:11434`
- **Host-Only Mode:** Access via the host-only adapter gateway (typically `192.168.56.1`).
  - Access URL: `http://192.168.56.1:11434`

##### 4. Configure Kali VM Environment
Inside the Kali VM, point the analysis pipeline environment variable to the host:
```bash
export OLLAMA_HOST="http://10.0.2.2:11434"  # If using VirtualBox NAT
```
Test the connection from the VM:
```bash
curl http://10.0.2.2:11434/api/tags
```

##### 5. Python Pipeline Integration (Step 7)
The standard Python `ollama` client can be instantiated with the custom remote host:
```python
# analysis/step7_llm_assessment.py
import os
import ollama

# Read OLLAMA_HOST from environment, default to localhost
ollama_host = os.environ.get("OLLAMA_HOST", "http://localhost:11434")
client = ollama.Client(host=ollama_host)

response = client.generate(
    model=os.environ.get("OLLAMA_MODEL", "llama3.2:3b"),
    prompt=your_prompt,
    format="json",
    options={"num_ctx": 4096}
)
```

##### Resource Allocation Split
By offloading inference to the host, VM memory and CPU requirements drop drastically:
- **Host (Ollama + Model):** 4–8 GB (RAM/VRAM) + Host CPU/GPU
- **VM (Kali Linux + Pipeline):** 2–4 GB (RAM) + 2 CPU Cores

### 2.7.4 Pipeline ↔ External Tools Integration
**Method:** Python subprocess calls  
**Tools:**
- apktool: subprocess wrapper
- jadx: subprocess wrapper
- radare2: subprocess wrapper
**Error Handling:** Non-zero exit codes logged, fallback paths attempted


---

# 3. BACKEND SCHEMA & API SPECIFICATION

## 3.1 REST API Endpoints

### 3.1.1 Health Check
```
GET /
Response: {"status": "ok", "version": "1.0.0"}
```

### 3.1.2 List Samples
```
GET /samples
Response: {
  "samples": [
    {
      "id": "sha256_hash",
      "name": "sample_name.apk",
      "status": "pending|analyzing|complete|error",
      "timestamp": "2026-06-10T09:16:00Z"
    }
  ]
}
```

### 3.1.3 Get Sample Result
```
GET /samples/{sample_id}
Response: FullAnalysisResult (see 3.3)
```

### 3.1.4 Trigger Analysis (REST Fallback)
```
POST /analyze
Body: {"apk_path": "/path/to/sample.apk"}
Response: {"sample_id": "sha256", "status": "queued"}
```

## 3.2 WebSocket API

### 3.2.1 Connection
```
ws://localhost:8000/ws
```

### 3.2.2 Client → Server Messages
```json
{
  "action": "subscribe|unsubscribe|ping",
  "channel": "all|sample_id"
}
```

### 3.2.3 Server → Client Events

#### Event: analysis_started
```json
{
  "event_type": "analysis_started",
  "timestamp": "2026-06-10T09:16:00.123Z",
  "data": {
    "sample_id": "sha256_hash",
    "sample_name": "malware.apk",
    "total_steps": 7
  }
}
```

#### Event: encoding_detected
```json
{
  "event_type": "encoding_detected",
  "timestamp": "2026-06-10T09:16:05.456Z",
  "data": {
    "sample_id": "sha256_hash",
    "encoding_id": "enc_001",
    "type": "base64|hex|xor|custom",
    "original_string": "aHR0cHM6Ly9...",
    "confidence": 0.92,
    "entropy": 4.8,
    "source_location": "MainActivity.java:42",
    "decoded_preview": "https://evil..."
  }
}
```

#### Event: payload_decoded
```json
{
  "event_type": "payload_decoded",
  "timestamp": "2026-06-10T09:16:10.789Z",
  "data": {
    "sample_id": "sha256_hash",
    "payload_id": "pld_001",
    "encoding_id": "enc_001",
    "decoded_content": "https://evil-domain.com/c2",
    "artifacts": [
      {"type": "url", "value": "https://evil-domain.com/c2", "confidence": 0.95}
    ],
    "source_location": "Decoder.java:15"
  }
}
```

#### Event: c2_extracted
```json
{
  "event_type": "c2_extracted",
  "timestamp": "2026-06-10T09:16:15.012Z",
  "data": {
    "sample_id": "sha256_hash",
    "c2_id": "c2_001",
    "payload_id": "pld_001",
    "raw_url": "https://evil-domain.com:8443/api/data",
    "protocol": "https",
    "domain": "evil-domain.com",
    "ip": "192.0.2.1",
    "port": 8443,
    "path": "/api/data",
    "ip_classification": "public",
    "communication_type": "http_request",
    "is_fallback": false,
    "confidence": 0.88
  }
}
```

#### Event: threat_chain_created
```json
{
  "event_type": "threat_chain_created",
  "timestamp": "2026-06-10T09:16:20.345Z",
  "data": {
    "sample_id": "sha256_hash",
    "chain_id": "chain_001",
    "severity": "critical",
    "confidence": 0.85,
    "steps": [
      {
        "step": 1,
        "type": "encoded_string",
        "artifact": "aHR0cHM6Ly9...",
        "source_location": "MainActivity.java:42",
        "confidence": 0.92
      },
      {
        "step": 2,
        "type": "decoding_function",
        "artifact": "decodeBase64()",
        "source_location": "Decoder.java:15",
        "confidence": 0.90
      },
      {
        "step": 3,
        "type": "decoded_artifact",
        "artifact": "https://evil-domain.com/c2",
        "source_location": "Decoder.java:16",
        "confidence": 0.95
      },
      {
        "step": 4,
        "type": "usage",
        "artifact": "HttpURLConnection",
        "source_location": "NetworkTask.java:88",
        "confidence": 0.85
      },
      {
        "step": 5,
        "type": "c2_infrastructure",
        "artifact": "https://evil-domain.com:8443/api/data",
        "source_location": "NetworkTask.java:89",
        "confidence": 0.88
      }
    ]
  }
}
```

#### Event: analysis_complete
```json
{
  "event_type": "analysis_complete",
  "timestamp": "2026-06-10T09:16:25.678Z",
  "data": {
    "sample_id": "sha256_hash",
    "total_encodings": 12,
    "total_payloads": 8,
    "total_c2s": 3,
    "total_chains": 2,
    "duration_seconds": 145.5,
    "report_path": "/reports/sha256_hash.json"
  }
}
```

#### Event: error
```json
{
  "event_type": "error",
  "timestamp": "2026-06-10T09:16:30.901Z",
  "data": {
    "sample_id": "sha256_hash",
    "step": "step3_encoding_detection",
    "error_type": "decode_failure|timeout|exception",
    "message": "Failed to decode candidate with key 0x41",
    "recoverable": true
  }
}
```

#### Event: metrics_update
```json
{
  "event_type": "metrics_update",
  "timestamp": "2026-06-10T09:16:35.234Z",
  "data": {
    "sample_id": "sha256_hash",
    "current_step": 4,
    "step_progress": 0.65,
    "overall_progress": 0.55,
    "active_encodings": 5,
    "active_payloads": 3,
    "active_c2s": 1,
    "active_chains": 0
  }
}
```

## 3.3 Data Models

### 3.3.1 Sample Metadata
```json
{
  "sample_id": "sha256_hex_string",
  "sample_name": "original_filename.apk",
  "file_size_bytes": 2048576,
  "sha256": "sha256_hex_string",
  "md5": "md5_hex_string",
  "package_name": "com.example.malware",
  "vt_detections": 23,
  "vt_total": 70,
  "family": "BankBot|Anubis|Cerberus|unknown",
  "collection_date": "2026-06-01",
  "analysis_status": "pending|analyzing|complete|error",
  "analysis_timestamp": "2026-06-10T09:16:00Z"
}
```

### 3.3.2 Full Analysis Result
```json
{
  "sample_id": "sha256_hex_string",
  "metadata": { "SampleMetadata" },
  "extraction": {
    "apktool_success": true,
    "jadx_success": true,
    "native_libs_found": ["libnative.so"],
    "decompiled_classes": 145,
    "total_strings_extracted": 3420
  },
  "strings": {
    "string_literals": [{"value": "...", "source": "...", "entropy": 4.2}],
    "byte_arrays": [{"value": "...", "source": "...", "entropy": 6.8}],
    "numeric_constants": [{"value": 443, "source": "..."}],
    "resource_strings": [{"value": "...", "source": "strings.xml"}],
    "native_strings": [{"value": "...", "source": "libnative.so"}]
  },
  "encodings": [
    {
      "encoding_id": "enc_001",
      "type": "base64",
      "original_string": "aHR0cHM6Ly9...",
      "confidence": 0.92,
      "entropy": 4.8,
      "source_location": "MainActivity.java:42",
      "decoded_preview": "https://evil...",
      "validation_status": "valid|invalid|uncertain"
    }
  ],
  "payloads": [
    {
      "payload_id": "pld_001",
      "encoding_id": "enc_001",
      "decoded_content": "https://evil-domain.com/c2",
      "artifacts": [
        {"type": "url", "value": "...", "confidence": 0.95},
        {"type": "ip", "value": "192.0.2.1", "confidence": 0.90}
      ],
      "source_location": "Decoder.java:15",
      "binary_detected": false,
      "magic_bytes": null
    }
  ],
  "c2_infrastructure": [
    {
      "c2_id": "c2_001",
      "payload_id": "pld_001",
      "raw_url": "https://evil-domain.com:8443/api/data",
      "protocol": "https",
      "domain": "evil-domain.com",
      "ip": "192.0.2.1",
      "port": 8443,
      "path": "/api/data",
      "query_params": {"key": "value"},
      "ip_classification": "public",
      "communication_type": "http_request",
      "is_fallback": false,
      "source_location": "NetworkTask.java:89",
      "confidence": 0.88
    }
  ],
  "threat_chains": [
    {
      "chain_id": "chain_001",
      "severity": "critical",
      "confidence": 0.85,
      "steps": [
        {
          "step": 1,
          "type": "encoded_string",
          "artifact": "...",
          "source_location": "...",
          "confidence": 0.92
        }
      ]
    }
  ],
  "llm_assessment": {
    "severity": "critical",
    "risk_score": 92,
    "narrative": "This sample exhibits active C2 communication...",
    "primary_threat": "banking_trojan",
    "recommended_actions": [
      "Block domain evil-domain.com",
      "Monitor for exfiltration patterns",
      "Check for device admin abuse"
    ],
    "confidence": 0.78,
    "raw_llm_output": "..."
  },
  "accuracy_metrics": {
    "encoding_precision": 0.88,
    "c2_precision": 0.85,
    "chain_precision": 0.82,
    "overall_success": true
  },
  "timeline": {
    "started": "2026-06-10T09:16:00Z",
    "completed": "2026-06-10T09:18:25Z",
    "duration_seconds": 145.5,
    "step_durations": {
      "step1": 15.2,
      "step2": 22.1,
      "step3": 35.8,
      "step4": 28.4,
      "step5": 18.6,
      "step6": 12.3,
      "step7": 13.1
    }
  }
}
```

### 3.3.3 3D Graph Data Model
```json
{
  "nodes": [
    {
      "id": "node_001",
      "type": "encoding|payload|function|c2|config",
      "label": "Base64 String",
      "confidence": 0.92,
      "color": "#FF6B6B",
      "position": {"x": 10.5, "y": 20.3, "z": 5.1},
      "metadata": {
        "source_location": "MainActivity.java:42",
        "original_value": "aHR0cHM6Ly9...",
        "entropy": 4.8
      }
    }
  ],
  "edges": [
    {
      "id": "edge_001",
      "source": "node_001",
      "target": "node_002",
      "type": "decode|usage|exfiltration",
      "color": "#A29BFE",
      "label": "decodes to",
      "confidence": 0.90
    }
  ],
  "clusters": [
    {
      "cluster_id": "cluster_001",
      "sample_id": "sha256_hash",
      "center": {"x": 15.0, "y": 25.0, "z": 10.0},
      "radius": 5.0,
      "node_count": 8
    }
  ]
}
```

### 3.3.4 Dashboard State Model
```json
{
  "current_view": "threat_graph|clustering|timeline|live_status",
  "selected_node": "node_001|null",
  "selected_sample": "sha256_hash|null",
  "camera_position": {"x": 0, "y": 50, "z": 100},
  "camera_target": {"x": 0, "y": 0, "z": 0},
  "filters": {
    "node_types": ["encoding", "payload", "function", "c2"],
    "min_confidence": 0.5,
    "show_labels": true
  },
  "metrics": {
    "total_samples": 50,
    "analyzed_samples": 47,
    "total_encodings": 342,
    "total_payloads": 215,
    "total_c2s": 89,
    "total_chains": 124,
    "avg_analysis_time": 142.5
  },
  "recent_events": [
    {
      "event_type": "encoding_detected",
      "timestamp": "2026-06-10T09:16:05Z",
      "summary": "Base64 encoding detected in MainActivity.java"
    }
  ]
}
```


---

# 4. APPLICATION FLOW & ARCHITECTURE

## 4.1 System-Level Flow

```
┌─────────────────────────────────────────────────────────────────────────┐
│                         SYSTEM-LEVEL FLOW                                │
├─────────────────────────────────────────────────────────────────────────┤
│                                                                         │
│  PHASE 1: INITIALIZATION                                                │
│  ═══════════════════════════════════                                    │
│                                                                         │
│  ┌─────────────┐    ┌─────────────┐    ┌─────────────┐               │
│  │  Start      │───►│  Validate   │───►│  Load       │               │
│  │  Backend    │    │  Ollama     │    │  Samples    │               │
│  │  (uvicorn)  │    │  (llama     │    │  (CSV +    │               │
│  │             │    │  primus)    │    │  metadata)  │               │
│  └─────────────┘    └─────────────┘    └─────────────┘               │
│       │                  │                  │                         │
│       ▼                  ▼                  ▼                         │
│  ┌─────────────┐    ┌─────────────┐    ┌─────────────┐               │
│  │  Start      │    │  Verify     │    │  Validate   │               │
│  │  Frontend   │    │  Tools      │    │  Paths      │               │
│  │  (npm start)│    │  (apktool,  │    │  (create    │               │
│  │             │    │  jadx, r2)  │    │  dirs)      │               │
│  └─────────────┘    └─────────────┘    └─────────────┘               │
│                                                                         │
│  PHASE 2: ANALYSIS PIPELINE (Per Sample)                                │
│  ═══════════════════════════════════════════                            │
│                                                                         │
│  ┌─────────────┐    ┌─────────────┐    ┌─────────────┐               │
│  │  Ingest     │───►│  Extract    │───►│  Enumerate  │               │
│  │  APK        │    │  APK        │    │  Strings      │               │
│  │  (file      │    │  (apktool + │    │  (regex +   │               │
│  │  path)      │    │  jadx + r2) │    │  entropy)   │               │
│  └─────────────┘    └─────────────┘    └─────────────┘               │
│       │                  │                  │                         │
│       ▼                  ▼                  ▼                         │
│  ┌─────────────┐    ┌─────────────┐    ┌─────────────┐               │
│  │  Detect     │───►│  Decode     │───►│  Extract    │               │
│  │  Encoding   │    │  Payload    │    │  C2         │               │
│  │  (pattern   │    │  (apply     │    │  (parse +   │               │
│  │  + entropy) │    │  decoder)   │    │  classify)  │               │
│  └─────────────┘    └─────────────┘    └─────────────┘               │
│       │                  │                  │                         │
│       ▼                  ▼                  ▼                         │
│  ┌─────────────┐    ┌─────────────┐                                   │
│  │  Correlate  │───►│  LLM        │                                   │
│  │  Threats    │    │  Assess     │                                   │
│  │  (graph +   │    │  (ollama    │                                   │
│  │  trace)     │    │  generate)  │                                   │
│  └─────────────┘    └─────────────┘                                   │
│                                                                         │
│  PHASE 3: REAL-TIME VISUALIZATION                                       │
│  ════════════════════════════════════════                               │
│                                                                         │
│  ┌─────────────┐    ┌─────────────┐    ┌─────────────┐               │
│  │  Emit       │───►│  Broadcast  │───►│  Receive    │               │
│  │  Event      │    │  via WS     │    │  in React   │               │
│  │  (pipeline) │    │  (backend)  │    │  (frontend) │               │
│  └─────────────┘    └─────────────┘    └─────────────┘               │
│       │                  │                  │                         │
│       ▼                  ▼                  ▼                         │
│  ┌─────────────┐    ┌─────────────┐    ┌─────────────┐               │
│  │  Update     │    │  Render     │    │  Interact   │               │
│  │  Three.js   │    │  3D Scene   │    │  (click,    │               │
│  │  State      │    │  (nodes +   │    │  hover,     │               │
│  │             │    │  edges)     │    │  filter)    │               │
│  └─────────────┘    └─────────────┘    └─────────────┘               │
│                                                                         │
│  PHASE 4: REPORTING & EXPORT                                          │
│  ══════════════════════════════════════                                │
│                                                                         │
│  ┌─────────────┐    ┌─────────────┐    ┌─────────────┐               │
│  │  Generate   │───►│  Export     │───►│  Store      │               │
│  │  Reports    │    │  (JSON +    │    │  in         │               │
│  │  (aggregate │    │  HTML +     │    │  reports/   │               │
│  │  data)      │    │  PDF)       │    │  dir        │               │
│  └─────────────┘    └─────────────┘    └─────────────┘               │
│                                                                         │
└─────────────────────────────────────────────────────────────────────────┘
```

## 4.2 Detailed Pipeline Flow (Per Sample)

### Step 1: APK Extraction Flow
```
Input: /samples/malware.apk
│
├─► apktool d malware.apk -o malware/
│   ├─► AndroidManifest.xml (permissions, components)
│   ├─► res/ (resources, layouts, drawables)
│   ├─► smali/ (Dalvik bytecode)
│   └─► lib/ (native libraries .so)
│
├─► jadx-cli malware/classes.dex -d output/
│   ├─► Java source files (decompiled)
│   ├─► Package structure preserved
│   └─► Selective deobfuscation (filter names >50 chars)
│
├─► radare2 -qq -c "iz" lib/armeabi-v7a/libnative.so
│   └─► String table from native library
│
└─► Metadata generation
    ├─► SHA-256 hash
    ├─► File size
    ├─► Package name (from manifest)
    └─► Output: extraction_result.json

Emit Event: extraction_complete
```

### Step 2: String Enumeration Flow
```
Input: Decompiled source tree + resources + native strings
│
├─► Java String Extractor
│   ├─► Regex: "([^"]*)" for string literals
│   ├─► Regex: {0x[0-9A-Fa-f]{2}, ...} for byte arrays
│   └─► Regex: \d{3,5} for numeric constants (ports, keys)
│
├─► Resource Parser
│   ├─► XML parse strings.xml
│   ├─► Read raw/ directory files
│   └─► Extract res/values/*.xml strings
│
├─► Entropy Calculator
│   └─► H = -Σ p(x) log₂ p(x) for each string
│
└─► Output: strings.json with categories + entropy

Emit Event: strings_enumerated
```

### Step 3: Encoding Detection Flow
```
Input: All strings with entropy scores
│
├─► Phase 1: Pattern Matching
│   ├─► Base64 regex match → alphabet validation
│   ├─► URL-safe Base64 match → alphabet validation
│   └─► Hex regex match → alphabet validation
│
├─► Phase 2: Decode Validation
│   ├─► Attempt Base64 decode
│   │   └─► Valid UTF-8? → confidence boost
│   ├─► Attempt hex decode
│   │   └─► Valid bytes? → confidence boost
│   └─► Check decoded output for URLs/IPs/domains
│       └─► Found meaningful content? → major confidence boost
│
├─► Phase 3: XOR Brute-Force (if entropy > 5.0)
│   ├─► For each key 0–255:
│   │   ├─► XOR decrypt
│   │   └─► Score: % printable ASCII
│   └─► Accept if >70% printable
│       └─► Store top 3 candidates
│
├─► Phase 4: Custom Encoding Flag
│   └─► Entropy > 7.0 + all detection failed
│       └─► Flag: suspected_custom_encoding
│
└─► Output: encodings.json with type, confidence, preview

Emit Event: encoding_detected (per encoding)
```

### Step 4: Decoding & Extraction Flow
```
Input: Encoding candidates with detected types
│
├─► Decoder Router
│   ├─► type=base64 → Base64 decoder
│   ├─► type=hex → Hex decoder
│   ├─► type=xor → XOR decoder (apply best key)
│   └─► type=custom → Skip (manual review needed)
│
├─► Artifact Extractor
│   ├─► URL regex: https?://[^\s"]+ → URL artifacts
│   ├─► IP regex: \d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3} → IP artifacts
│   ├─► Email regex: [RFC 5322 pattern] → Email artifacts
│   ├─► Phone regex: [phonenumbers library] → Phone artifacts
│   └─► Binary detector: magic bytes → Binary artifacts
│
├─► Post-Processor
│   ├─► URL normalization (lowercase, trailing slash)
│   ├─► IP validation (inet_aton)
│   ├─► Domain extraction from URL
│   └─► Confidence boost if validation passes
│
└─► Output: payloads.json with decoded content + artifacts

Emit Event: payload_decoded (per payload)
```

### Step 5: C2 Extraction Flow
```
Input: Decoded artifacts + direct source strings
│
├─► URL Parser
│   ├─► Extract protocol (scheme)
│   ├─► Extract domain (netloc)
│   ├─► Extract port (default or explicit)
│   ├─► Extract path
│   └─► Extract query parameters
│
├─► IP Classifier
│   ├─► 10.0.0.0/8 → private
│   ├─► 172.16.0.0/12 → private
│   ├─► 192.168.0.0/16 → private
│   ├─► 127.0.0.0/8 → loopback
│   ├─► Known VPN ranges → vpn
│   └─► Else → public
│
├─► Protocol Inference
│   ├─► URL scheme = http/https → http_request
│   ├─► Code context: InetAddress → dns_query
│   ├─► Code context: Socket → raw socket
│   └─► Default: other
│
├─► Fallback Detector
│   └─► Code analysis: conditional C2 assignment
│       ├─► if/else with different URLs → is_fallback = true
│       └─► try/catch with backup URLs → is_fallback = true
│
└─► Output: c2_infrastructure.json

Emit Event: c2_extracted (per C2)
```

### Step 6: Correlation Flow
```
Input: All C2 records, payloads, encodings, source locations
│
├─► Dependency Graph Builder
│   ├─► Node: encoded_string (from step 3)
│   ├─► Node: decoding_function (from source location)
│   ├─► Node: decoded_artifact (from step 4)
│   ├─► Node: usage_location (from code context)
│   └─► Node: c2_infrastructure (from step 5)
│
├─► Edge Creation
│   ├─► encoding → function: "decode" edge
│   ├─► function → artifact: "produces" edge
│   ├─► artifact → usage: "consumed_by" edge
│   └─► usage → c2: "exfiltrates_to" edge
│
├─► Dataflow Tracer (max 5 steps)
│   ├─► Start at encoding node
│   ├─► Follow decode edges to functions
│   ├─► Follow produce edges to artifacts
│   ├─► Follow consume edges to usage
│   └─► Follow exfiltrate edges to C2
│
├─► Path Separation
│   └─► Independent paths = separate threat chains
│
├─► Confidence Aggregation
│   └─► Weighted average of step confidences
│
└─► Output: threat_chains.json

Emit Event: threat_chain_created (per chain)
```

### Step 7: LLM Assessment Flow
```
Input: Threat chains formatted as text
│
├─► Prompt Builder
│   ├─► System prompt: "You are an expert malware threat analyst..."
│   ├─► Context: chain count, C2 count, encoding types
│   ├─► Data: formatted threat chains (no raw payloads)
│   └─► Constraint: "Output valid JSON only, no markdown"
│
├─► Ollama Call
│   ├─► POST http://localhost:11434/api/generate
│   ├─► Model: llama-primus:8b
│   ├─► Timeout: 120s
│   └─► Retry: 3 attempts with backoff
│
├─► Response Parser
│   ├─► Extract JSON from response text
│   └─► Handle markdown code blocks if present
│
├─► Schema Validator
│   ├─► Check required fields: severity, risk_score, narrative
│   ├─► Validate severity enum: critical|high|medium|low
│   ├─► Validate risk_score: 0–100 integer
│   └─► If invalid → retry with stricter prompt
│
├─► Sanity Checker
│   ├─► Cross-check: active C2 + "low severity" = flag inconsistency
│   ├─► Cross-check: no C2 + "critical severity" = flag inconsistency
│   └─► Log warnings for debugging
│
├─► Fallback (if all retries fail)
│   └─► Default assessment based on indicator count
│       ├─► Active C2 present → high severity
│       ├─► Multiple encodings → medium severity
│       └─► No indicators → low severity
│
└─► Output: llm_assessment.json

Emit Event: analysis_complete
```

## 4.3 Dashboard Interaction Flow

### 4.3.1 View Switching Flow
```
User clicks camera toggle
│
├─► Current view: ThreatGraph
│   ├─► Save camera position to state
│   └─► Unmount Three.js scene
│
├─► Target view: ClusteringView
│   ├─► Load clustering scene
│   ├─► Create scatter plot geometry
│   ├─► Position points (X, Y, Z from sample metrics)
│   └─► Restore camera to default position
│
└─► Render new view with transition animation
```

### 4.3.2 Node Interaction Flow
```
User hovers over node in ThreatGraph
│
├─► Raycaster detects intersection
├─► Highlight node (scale up, glow effect)
├─► Highlight connected edges (brighten color)
├─► Show tooltip: node type + confidence + label
│
User clicks node
│
├─► Open detail sidebar
├─► Populate with node metadata:
│   ├─► Source location
│   ├─► Original value (truncated)
│   ├─► Entropy score
│   ├─► Confidence score
│   └─► Connected nodes list
├─► Focus camera on selected node
└─► Update URL hash for deep-linking
```

### 4.3.3 Live Event Streaming Flow
```
Backend emits event via WebSocket
│
├─► Frontend receives message
├─► Parse JSON event
├─► Route to appropriate handler:
│   ├─► encoding_detected → add node to graph, update counter
│   ├─► payload_decoded → add node + edge, update counter
│   ├─► c2_extracted → add C2 node, update counter
│   ├─► threat_chain_created → highlight chain path
│   ├─► analysis_complete → show completion banner
│   └─► error → show toast notification
├─► Update React state (triggers re-render)
├─► Three.js scene updates (animated transition)
└─► Event log prepends new entry (FIFO, max 5 visible)
```

## 4.4 Report Generation Flow

```
Analysis complete for sample
│
├─► JSON Report Generator
│   ├─► Serialize FullAnalysisResult to JSON
│   ├─► Pretty-print with indentation
│   └─► Write to reports/{sample_id}.json
│
├─► HTML Report Generator
│   ├─► Load HTML template
│   ├─► Inject JSON data as JavaScript variable
│   ├─► Embed lightweight visualization (Chart.js or D3)
│   ├─► Include threat chain narrative
│   └─► Write to reports/{sample_id}.html
│
├─► PDF Report Generator
│   ├─► Convert HTML to PDF (headless browser or library)
│   ├─► Embed static visualizations (PNG screenshots)
│   ├─► Include cover page with metadata
│   └─► Write to reports/{sample_id}.pdf
│
└─► Batch Report (for 50 samples)
    ├─► Aggregate metrics
    ├─► Cross-sample correlation
    ├─► Family clustering summary
    └─► Accuracy validation table
```


---

# 5. DATA MODELS & SCHEMAS

## 5.1 Entity Relationship Diagram

```
┌─────────────────┐       ┌─────────────────┐       ┌─────────────────┐
│     SAMPLE      │       │    ENCODING     │       │    PAYLOAD      │
├─────────────────┤       ├─────────────────┤       ├─────────────────┤
│ PK sample_id    │◄──────┤ FK sample_id    │◄──────┤ FK encoding_id  │
│ sample_name     │  1:M  │ encoding_id     │  1:1  │ payload_id      │
│ sha256          │       │ type            │       │ decoded_content │
│ file_size       │       │ original_string │       │ artifacts[]     │
│ package_name    │       │ confidence      │       │ source_location │
│ vt_detections   │       │ entropy         │       │ binary_detected │
│ family          │       │ source_location │       └─────────────────┘
│ status          │       │ decoded_preview │              │
│ timestamp       │       └─────────────────┘              │
└─────────────────┘                                        │
       │                                                   │
       │ 1:M                                              │ 1:M
       ▼                                                   ▼
┌─────────────────┐       ┌─────────────────┐       ┌─────────────────┐
│  THREAT_CHAIN   │       │   C2_RECORD     │       │    ARTIFACT     │
├─────────────────┤       ├─────────────────┤       ├─────────────────┤
│ PK chain_id     │◄──────┤ FK payload_id   │◄──────┤ FK payload_id   │
│ FK sample_id    │  1:M  │ c2_id           │  1:M  │ artifact_id     │
│ severity        │       │ raw_url         │       │ type            │
│ confidence      │       │ protocol        │       │ value           │
│ steps[]         │       │ domain          │       │ confidence      │
└─────────────────┘       │ ip              │       └─────────────────┘
                          │ port            │
                          │ path            │
                          │ ip_classification│
                          │ communication_type│
                          │ is_fallback     │
                          │ confidence      │
                          └─────────────────┘

┌─────────────────┐
│  LLM_ASSESSMENT │
├─────────────────┤
│ PK assessment_id│
│ FK sample_id    │
│ severity        │
│ risk_score      │
│ narrative       │
│ primary_threat  │
│ recommended_actions[]│
│ confidence      │
│ raw_llm_output  │
└─────────────────┘
```

## 5.2 JSON Schema Definitions

### 5.2.1 Sample Schema
```json
{
  "$schema": "http://json-schema.org/draft-07/schema#",
  "title": "Sample",
  "type": "object",
  "required": ["sample_id", "sample_name", "sha256", "file_size_bytes", "status"],
  "properties": {
    "sample_id": { "type": "string", "pattern": "^[a-f0-9]{64}$" },
    "sample_name": { "type": "string", "maxLength": 255 },
    "file_size_bytes": { "type": "integer", "minimum": 0 },
    "sha256": { "type": "string", "pattern": "^[a-f0-9]{64}$" },
    "md5": { "type": "string", "pattern": "^[a-f0-9]{32}$" },
    "package_name": { "type": "string" },
    "vt_detections": { "type": "integer", "minimum": 0 },
    "vt_total": { "type": "integer", "minimum": 0 },
    "family": { "type": "string", "enum": ["BankBot", "Anubis", "Cerberus", "unknown"] },
    "collection_date": { "type": "string", "format": "date" },
    "analysis_status": { "type": "string", "enum": ["pending", "analyzing", "complete", "error"] },
    "analysis_timestamp": { "type": "string", "format": "date-time" }
  }
}
```

### 5.2.2 Encoding Schema
```json
{
  "$schema": "http://json-schema.org/draft-07/schema#",
  "title": "Encoding",
  "type": "object",
  "required": ["encoding_id", "type", "original_string", "confidence", "source_location"],
  "properties": {
    "encoding_id": { "type": "string", "pattern": "^enc_[0-9]{3}$" },
    "type": { "type": "string", "enum": ["base64", "hex", "xor", "custom"] },
    "original_string": { "type": "string", "minLength": 1 },
    "confidence": { "type": "number", "minimum": 0.0, "maximum": 1.0 },
    "entropy": { "type": "number", "minimum": 0.0, "maximum": 8.0 },
    "source_location": { "type": "string", "pattern": "^[^:]+\.java:[0-9]+$" },
    "decoded_preview": { "type": "string" },
    "validation_status": { "type": "string", "enum": ["valid", "invalid", "uncertain"] }
  }
}
```

### 5.2.3 Threat Chain Schema
```json
{
  "$schema": "http://json-schema.org/draft-07/schema#",
  "title": "ThreatChain",
  "type": "object",
  "required": ["chain_id", "severity", "confidence", "steps"],
  "properties": {
    "chain_id": { "type": "string", "pattern": "^chain_[0-9]{3}$" },
    "severity": { "type": "string", "enum": ["critical", "high", "medium", "low"] },
    "confidence": { "type": "number", "minimum": 0.0, "maximum": 1.0 },
    "steps": {
      "type": "array",
      "minItems": 1,
      "maxItems": 10,
      "items": {
        "type": "object",
        "required": ["step", "type", "artifact", "source_location", "confidence"],
        "properties": {
          "step": { "type": "integer", "minimum": 1, "maximum": 10 },
          "type": { "type": "string", "enum": ["encoded_string", "decoding_function", "decoded_artifact", "usage", "c2_infrastructure"] },
          "artifact": { "type": "string" },
          "source_location": { "type": "string" },
          "confidence": { "type": "number", "minimum": 0.0, "maximum": 1.0 }
        }
      }
    }
  }
}
```

### 5.2.4 LLM Assessment Schema
```json
{
  "$schema": "http://json-schema.org/draft-07/schema#",
  "title": "LLMAssessment",
  "type": "object",
  "required": ["severity", "risk_score", "narrative", "recommended_actions"],
  "properties": {
    "severity": { "type": "string", "enum": ["critical", "high", "medium", "low"] },
    "risk_score": { "type": "integer", "minimum": 0, "maximum": 100 },
    "narrative": { "type": "string", "minLength": 10, "maxLength": 2000 },
    "primary_threat": { "type": "string", "enum": ["c2_exfiltration", "ransomware", "spyware", "banking_trojan", "other"] },
    "recommended_actions": {
      "type": "array",
      "items": { "type": "string", "minLength": 5 }
    },
    "confidence": { "type": "number", "minimum": 0.0, "maximum": 1.0 }
  }
}
```

### 5.2.5 WebSocket Event Schema
```json
{
  "$schema": "http://json-schema.org/draft-07/schema#",
  "title": "WebSocketEvent",
  "type": "object",
  "required": ["event_type", "timestamp", "data"],
  "properties": {
    "event_type": { "type": "string", "enum": ["analysis_started", "encoding_detected", "payload_decoded", "c2_extracted", "threat_chain_created", "analysis_complete", "error", "metrics_update"] },
    "timestamp": { "type": "string", "format": "date-time" },
    "data": { "type": "object" }
  }
}
```

---

# 6. TESTING & VALIDATION FRAMEWORK

## 6.1 Testing Strategy

### 6.1.1 Unit Testing
| Module | Test Cases | Coverage Target |
|--------|-----------|----------------|
| Step 1: APK Extraction | 10 | 90% |
| Step 2: String Enum | 15 | 90% |
| Step 3: Encoding Detection | 25 | 95% |
| Step 4: Decoding | 20 | 90% |
| Step 5: C2 Extraction | 15 | 90% |
| Step 6: Correlation | 10 | 85% |
| Step 7: LLM Assessment | 8 | 80% |
| Backend Events | 10 | 90% |
| Frontend Components | 12 | 85% |

### 6.1.2 Integration Testing
| Flow | Test Cases | Validation Method |
|------|-----------|-------------------|
| Pipeline end-to-end | 20 | Output JSON validation |
| Backend ↔ Frontend WS | 10 | Event sequence verification |
| Backend ↔ Ollama | 8 | Response schema validation |
| Report generation | 5 | File existence + format check |

### 6.1.3 Accuracy Validation
| Metric | Method | Sample Size | Target |
|--------|--------|-------------|--------|
| Encoding precision | Manual review | 10 samples | >85% |
| Encoding recall | Manual review | 10 samples | >85% |
| C2 precision | VT IoC matching | 50 samples | >85% |
| C2 recall | VT IoC matching | 50 samples | >85% |
| Chain precision | Manual review | 10 samples | >80% |
| LLM severity | Expert judgment | 20 samples | >75% |
| Overall success | Pipeline completion | 50 samples | >85% |

### 6.1.4 Performance Testing
| Scenario | Target | Measurement |
|----------|--------|-------------|
| Single APK (<50MB) | <5 min | Wall-clock time |
| Dashboard 50 nodes | >30 FPS | Chrome DevTools |
| WebSocket latency | <100ms | Ping measurement |
| 50-sample batch | <24 hours | Total wall-clock |
| LLM response | <120s | Timeout threshold |

## 6.2 Validation Checklist

### Pre-Implementation
- [ ] All 50 malware samples collected and validated (VT >15 detections)
- [ ] Sample metadata CSV complete and accurate
- [ ] Ollama installed and model pulled (see deployment options below)
- [ ] All external tools (apktool, jadx, radare2) installed and tested
- [ ] **Environment confirmed:**
  - **Primary:** Kali Linux bare-metal (mandated by spec)
  - **Alternative:** Kali VM + Ollama on host (Windows/Linux) via network (see [Section 2.7.3.1](#2731-architecture-host-ollama--vm-pipeline-setup))
  - **Off-spec:** Windows native (WSL2 recommended; see [Section 1.5.1](#151-platform-requirements--windows-compatibility))
- [ ] Python 3.10+ environment with virtualenv ready
- [ ] Git repository initialized with .gitignore
- [ ] `OLLAMA_HOST` and `OLLAMA_MODEL` environment variables configured

### Per-Step Validation
- [ ] Step 1: 5 APKs decompile successfully (apktool + jadx + radare2)
- [ ] Step 2: All string types extracted (strings, bytes, numbers, resources, native)
- [ ] Step 3: Encoding detection precision >85% on 10 manually reviewed samples
- [ ] Step 4: Payloads decode correctly (validate against known ground truth)
- [ ] Step 5: C2s extracted and classified (match against VT IoCs)
- [ ] Step 6: Threat chains build without errors (graph connectivity verified)
- [ ] Step 7: LLM output valid JSON, severity aligns with indicators

### End-to-End Validation
- [ ] 50-sample run: pipeline completes for all samples
- [ ] Reports generated: JSON, HTML, PDF for all samples
- [ ] Dashboard live streaming: smooth, no lag, all events received
- [ ] Accuracy validation: manual review + VT cross-check documented
- [ ] All 4 camera views functional (graph, clustering, timeline, status)
- [ ] Node interactions working (click, hover, filter, rotate)
- [ ] WebSocket auto-reconnect functional

## 6.3 Accuracy Measurement Methodology

### Encoding Detection
```
Precision = True Positives / (True Positives + False Positives)
Recall = True Positives / (True Positives + False Negatives)
F1 = 2 × (Precision × Recall) / (Precision + Recall)

Ground Truth: Manual analyst review of 10 samples
- TP: System detects encoding that analyst confirms
- FP: System detects encoding that analyst rejects
- FN: Analyst finds encoding that system misses
```

### C2 Extraction
```
Precision = Matching VT IoCs / Total C2s Extracted
Recall = Matching VT IoCs / Total VT IoCs for Sample

Ground Truth: VirusTotal API query for sample hash
- Extract all network IoCs from VT report
- Compare against system-extracted C2s
```

### Threat Chain Correlation
```
Precision = Valid Chains / Total Chains Built

Ground Truth: Manual analyst review
- Analyst traces code paths manually
- Compares against system-generated chains
- Valid = chain accurately represents code flow
```

### LLM Severity Assessment
```
Accuracy = Agreements / Total Assessments

Ground Truth: Expert analyst judgment
- Analyst reviews threat chains + indicators
- Assigns severity independently
- Compares against LLM assessment
- Agreement = same severity category
```

---

# 7. SUCCESS CRITERIA & DELIVERABLES

## 7.1 Phase 1 Success Criteria (Week 7)

| # | Criterion | Target | Measurement |
|---|-----------|--------|-------------|
| 1 | 50 malware samples fully analyzed | 50/50 | Pipeline completion count |
| 2 | All 7 analysis steps functional | 7/7 | Step-by-step test pass |
| 3 | Live 3D dashboard deployed locally | Yes | localhost:3000 accessible |
| 4 | Reports generated (JSON, HTML, PDF) | 3 formats | File existence check |
| 5 | Accuracy validated >80% overall | >80% | Manual + VT validation |
| 6 | Code documented + GitHub ready | Yes | README, docstrings, repo |
| 7 | Blog post outline complete | Yes | Document review |
| 8 | Ready for May 2027 black book | Yes | Advisor sign-off |

## 7.2 Deliverables

### 7.2.1 Code Deliverables
| Deliverable | Location | Format |
|-------------|----------|--------|
| Analysis Pipeline | analysis/ | Python modules |
| Backend API | backend/ | FastAPI app |
| Frontend Dashboard | frontend/ | React + Three.js |
| Test Suite | tests/ | pytest |
| Requirements | requirements.txt | pip dependencies |
| Docker Compose | docker-compose.yml | Container orchestration |

### 7.2.2 Documentation Deliverables
| Deliverable | Content | Format |
|-------------|---------|--------|
| README.md | Installation, usage, architecture | Markdown |
| API Documentation | Endpoints, schemas, examples | Markdown |
| Architecture Diagrams | System, pipeline, data flow | PNG/SVG |
| Testing Report | Accuracy metrics, validation | PDF |
| Known Limitations | Documented constraints | Markdown |

### 7.2.3 Research Deliverables
| Deliverable | Content | Target |
|-------------|---------|--------|
| M.Sc. Black Book | Full thesis with results | May 2027 |
| Blog Post | "Detecting Encoding in Android Malware" | Medium/Personal |
| Research Paper | Conference submission | DFRWS / Virus Bulletin |
| Dataset | 50 analyzed samples (metadata only) | Public/Academic |

### 7.2.4 Report Deliverables (Per Sample)
| Format | Content | Use Case |
|--------|---------|----------|
| JSON | Complete analysis data | Machine processing |
| HTML | Interactive visualization | Browser viewing |
| PDF | Static report with narrative | Sharing/printing |

## 7.3 Timeline & Milestones

| Week | Milestone | Deliverable | Validation |
|------|-----------|-------------|------------|
| 1 | Foundation + Data Pipeline | Steps 1–2 working | 5 samples processed |
| 2 | Encoding Detection | Step 3 >85% precision | 20 samples tested |
| 3 | C2 & Correlation | Steps 4–6 complete | 20 samples with chains |
| 4 | LLM Integration | Step 7 >75% accuracy | 20 samples assessed |
| 5 | Backend + WebSocket | Event streaming live | Real-time dashboard |
| 6 | 3D Dashboard | All 4 views rendering | Interactive testing |
| 7 | Testing + Reports | 50 samples validated | Accuracy report |

---

# 8. PHASE 2+ ROADMAP

## 8.1 Phase 2: Dynamic Analysis Integration (Post-Black Book)

### Goals
- [ ] Android emulator setup (Android Studio Emulator / Genymotion)
- [ ] Frida hook integration for runtime decoding validation
- [ ] Live C2 liveness checks (HTTP ping, DNS resolution)
- [ ] Behavioral clustering (network traffic patterns)
- [ ] Runtime string decryption capture

### New Components
| Component | Technology | Purpose |
|-----------|------------|---------|
| Emulator | Android Studio AVD | Runtime environment |
| Frida | frida-tools | Dynamic instrumentation |
| Traffic Capture | tcpdump / Wireshark | Network analysis |
| Behavior Engine | Custom Python | Pattern matching on runtime data |

### Integration with Phase 1
- Phase 1 static results feed into Phase 2 dynamic validation
- Static C2s tested for liveness during dynamic analysis
- Runtime-decoded strings compared against static predictions
- Combined accuracy score: static + dynamic

## 8.2 Phase 3: Research Publication

### Goals
- [ ] Fine-tune Llama on threat intelligence corpus
- [ ] Comparative threat actor analysis (family attribution)
- [ ] Research paper submission to DFRWS or Virus Bulletin
- [ ] Open-source release on GitHub with documentation

### Research Questions
1. Can encoding detection accuracy be improved to >95% with dynamic validation?
2. Does LLM fine-tuning on threat intel improve severity assessment accuracy?
3. Can threat chains be used for automated family attribution?
4. What is the correlation between encoding complexity and C2 sophistication?

## 8.3 Future Enhancements

| Feature | Description | Priority |
|---------|-------------|----------|
| Multi-threading | Parallel sample processing | High |
| Cloud deployment | Docker + Kubernetes | Medium |
| VT integration | Automated sample validation | Medium |
| YARA rules | Auto-generate detection rules | Medium |
| API rate limiting | Production-ready backend | Low |
| User authentication | Multi-user support | Low |
| Historical trending | Track malware evolution | Low |

---

# APPENDIX A: GLOSSARY

| Term | Definition |
|------|------------|
| APK | Android Package — compiled Android application |
| C2 | Command and Control — server controlling malware |
| DEX | Dalvik Executable — Android bytecode format |
| IoC | Indicator of Compromise — evidence of intrusion |
| LLM | Large Language Model — AI text generation model |
| Shannon Entropy | Measure of randomness in data (0–8 bits) |
| TTP | Tactics, Techniques, Procedures — attacker behavior |
| VT | VirusTotal — malware scanning service |
| WebSocket | Protocol for real-time bidirectional communication |
| XOR | Exclusive OR — bitwise encryption operation |

# APPENDIX B: REFERENCE ARCHITECTURE

```
┌─────────────────────────────────────────────────────────────────────────┐
│                    DROIDFORENSIX REFERENCE ARCHITECTURE                 │
├─────────────────────────────────────────────────────────────────────────┤
│                                                                         │
│  LAYER 1: PRESENTATION (Frontend)                                       │
│  ┌─────────────────────────────────────────────────────────────────┐   │
│  │  React 18 + Three.js r150+                                       │   │
│  │  ├─ ThreatGraph.jsx     (3D force-directed graph)              │   │
│  │  ├─ ClusteringView.jsx  (3D scatter plot)                      │   │
│  │  ├─ TimelineView.jsx    (3D path animation)                  │   │
│  │  └─ LiveStatus.jsx      (Metrics + event log)                  │   │
│  │  WebSocket Client → ws://localhost:8000/ws                      │   │
│  └─────────────────────────────────────────────────────────────────┘   │
│                              ▲                                          │
│                              │ WebSocket (JSON events)                   │
│                              ▼                                          │
│  LAYER 2: APPLICATION (Backend)                                       │
│  ┌─────────────────────────────────────────────────────────────────┐   │
│  │  FastAPI 0.104.1 + Uvicorn 0.24.0                                │   │
│  │  ├─ /ws          (WebSocket endpoint)                            │   │
│  │  ├─ /samples     (REST API)                                    │   │
│  │  ├─ /analyze     (Trigger analysis)                            │   │
│  │  ├─ events.py    (Event definitions)                           │   │
│  │  └─ validators.py (Schema validation)                          │   │
│  │  CORS: localhost:3000                                           │   │
│  └─────────────────────────────────────────────────────────────────┘   │
│                              ▲                                          │
│                              │ Direct function calls + HTTP API          │
│                              ▼                                          │
│  LAYER 3: ANALYSIS (Pipeline)                                           │
│  ┌─────────────────────────────────────────────────────────────────┐   │
│  │  7-Step Python Pipeline                                          │   │
│  │  ├─ step1_apk_extraction.py    (apktool, jadx, radare2)        │   │
│  │  ├─ step2_string_enumeration.py (regex, entropy)               │   │
│  │  ├─ step3_encoding_detection.py (pattern, brute-force)         │   │
│  │  ├─ step4_decoding.py          (decoder engine)                 │   │
│  │  ├─ step5_c2_extraction.py     (URL parse, classify)           │   │
│  │  ├─ step6_correlation.py       (graph builder, tracer)         │   │
│  │  └─ step7_llm_assessment.py    (Ollama integration)            │   │
│  │  pipeline.py (orchestrator)                                    │   │
│  └─────────────────────────────────────────────────────────────────┘   │
│                              ▲                                          │
│                              │ Subprocess calls + HTTP API               │
│                              ▼                                          │
│  LAYER 4: EXTERNAL TOOLS                                                │
│  ┌─────────────────────────────────────────────────────────────────┐   │
│  │  ├─ apktool 2.7.0        (APK unpacking)                       │   │
│  │  ├─ jadx-cli             (DEX decompilation)                   │   │
│  │  ├─ radare2              (Native string extraction)            │   │
│  │  └─ Ollama + llama-primus:8b (LLM inference)                  │   │
│  └─────────────────────────────────────────────────────────────────┘   │
│                              ▲                                          │
│                              │ File system I/O                           │
│                              ▼                                          │
│  LAYER 5: DATA STORAGE                                                  │
│  ┌─────────────────────────────────────────────────────────────────┐   │
│  │  ├─ samples/          (Malware APKs, one per subdirectory)      │   │
│  │  ├─ reports/          (JSON, HTML, PDF outputs)                │   │
│  │  ├─ analysis/        (Intermediate JSON files)                  │   │
│  │  └─ sample_metadata.csv (Catalog of all samples)                │   │
│  └─────────────────────────────────────────────────────────────────┘   │
│                                                                         │
└─────────────────────────────────────────────────────────────────────────┘
```

# APPENDIX C: WEEK-BY-WEEK TASK BREAKDOWN

## Week 1: Foundation + Data Pipeline (Steps 1–2)

### Day 1–2: Environment Setup
- [ ] **Choose deployment mode:**
  - **A. Kali Bare-Metal (Spec Primary):** Install Kali natively, install Ollama + model locally
  - **B. Kali VM + Host Ollama (Recommended for GPU):** Install Kali in VM, install Ollama on host (Windows/Linux), configure `OLLAMA_HOST=10.0.2.2` (VirtualBox NAT) or host LAN IP (see [Section 2.7.3.1](#2731-architecture-host-ollama--vm-pipeline-setup))
  - **C. Windows Native (Off-Spec):** Use WSL2 Kali (preferred) or manual toolchain; debug subprocess/path issues yourself (see [Section 1.5.1](#151-platform-requirements--windows-compatibility))
- [ ] Verify Ollama installation + model available (`ollama pull llama3.2:3b` or `llama3.2:8b`)
- [ ] Create project directory structure
- [ ] Set up Python virtual environment
- [ ] Install all Python dependencies
- [ ] Verify external tools: apktool, jadx, radare2
- [ ] Clone theZoo repository, pull 50+ Android malware APKs
- [ ] Validate samples with VirusTotal (>15 vendor detections)
- [ ] Create sample metadata CSV
- [ ] Configure `OLLAMA_HOST` and `OLLAMA_MODEL` env vars in pipeline

### Day 3–4: Step 1 Implementation
- [ ] Implement APK extraction module
- [ ] Test on 5 samples, verify output structure
- [ ] Handle errors: corrupted APKs, jadx failures

### Day 5–7: Step 2 Implementation
- [ ] Implement string enumeration module
- [ ] Test on 5 samples, verify completeness
- [ ] Validate entropy calculation accuracy

**Deliverable:** 5 samples fully processed through Steps 1–2

## Week 2: Encoding Detection (Step 3)

### Day 1–2: Phase 1–2 (Pattern + Validation)
- [ ] Implement Base64 detection with alphabet validation
- [ ] Implement hex detection
- [ ] Implement URL-safe Base64 detection
- [ ] Add decode validation layer
- [ ] Add meaningful content check

### Day 3–4: Phase 3–4 (XOR + Custom)
- [ ] Implement entropy-based XOR brute-force
- [ ] Implement readability scoring
- [ ] Implement custom encoding flag
- [ ] Add pattern detection for custom encoding

### Day 5–7: Testing + Refinement
- [ ] Test on 20 samples
- [ ] Measure precision, recall, F1
- [ ] Refine thresholds based on results
- [ ] Document edge cases

**Deliverable:** Step 3 functional, accuracy >85%

## Week 3: C2 & Correlation (Steps 4–6)

### Day 1–2: Step 4 (Decoding)
- [ ] Implement decoder router
- [ ] Implement artifact extraction (URL, IP, email, phone)
- [ ] Implement binary detection
- [ ] Add post-processing and validation

### Day 3–4: Step 5 (C2 Extraction)
- [ ] Implement URL parser
- [ ] Implement IP classifier
- [ ] Implement protocol inference
- [ ] Implement fallback detection

### Day 5–7: Step 6 (Correlation)
- [ ] Implement dependency graph builder
- [ ] Implement dataflow tracer (5-step max)
- [ ] Implement path separation
- [ ] Implement confidence aggregation

**Deliverable:** Steps 4–6 complete, 20 samples with threat chains

## Week 4: LLM Integration (Step 7)

### Day 1–2: LLM Setup + Prompt
- [ ] Implement Ollama client
- [ ] Design system prompt
- [ ] Implement threat chain formatting
- [ ] Test basic generation

### Day 3–4: Output Validation
- [ ] Implement JSON schema validator
- [ ] Implement retry logic
- [ ] Implement sanity checker
- [ ] Implement fallback engine

### Day 5–7: Testing + Refinement
- [ ] Test on 20 samples
- [ ] Measure severity accuracy
- [ ] Refine prompt based on results
- [ ] Document LLM behavior

**Deliverable:** Step 7 complete, 20 samples with LLM assessments

## Week 5: Backend + WebSocket (FastAPI)

### Day 1–2: FastAPI Setup
- [ ] Implement FastAPI app
- [ ] Implement WebSocket endpoint
- [ ] Implement event broadcast system
- [ ] Configure CORS

### Day 3–4: Event System
- [ ] Implement event dataclasses
- [ ] Implement event serialization
- [ ] Implement JSON schema validation
- [ ] Implement event type checking

### Day 5–7: Pipeline Integration
- [ ] Modify pipeline to emit events
- [ ] Handle async/sync carefully
- [ ] Test event streaming
- [ ] Verify events reach frontend

**Deliverable:** Backend + event streaming fully functional

## Week 6: Frontend + 3D Dashboard (Three.js + React)

### Day 1–2: React Setup + WebSocket
- [ ] Initialize React app
- [ ] Implement WebSocket client
- [ ] Implement state management
- [ ] Test event reception

### Day 3–4: Three.js + Threat Graph
- [ ] Implement scene setup
- [ ] Implement node rendering
- [ ] Implement edge rendering
- [ ] Implement interactions (click, hover, filter)

### Day 5–6: Remaining Views
- [ ] Implement ClusteringView
- [ ] Implement TimelineView
- [ ] Implement LiveStatus

### Day 7: Polish + Testing
- [ ] Test all interactions
- [ ] Optimize performance
- [ ] Verify live updates
- [ ] Test camera toggle

**Deliverable:** Full 3D dashboard, all 4 visualizations, live streaming

## Week 7: Testing, Reports, Documentation

### Day 1–2: Sample Validation
- [ ] Run full pipeline on 50 samples
- [ ] Manual review: 10 samples
- [ ] VT cross-check: 50 samples
- [ ] Measure accuracy metrics

### Day 3–4: Report Generation
- [ ] Implement JSON export
- [ ] Implement HTML export
- [ ] Implement PDF export
- [ ] Test on 10 samples

### Day 5–6: Documentation
- [ ] Write README.md
- [ ] Document API
- [ ] Add code comments
- [ ] Create architecture diagrams

### Day 7: Blog Post Outline
- [ ] Outline blog post structure
- [ ] Draft case studies (3–5 samples)
- [ ] Document results and metrics
- [ ] Plan future work section

**Deliverable:** Validated pipeline, polished reports, documented code

---

**Document Version:** 1.0  
**Last Updated:** June 10, 2026  
**Status:** Final Draft — Ready for Implementation  
**Next Review:** Weekly during implementation phase

---

*This document serves as the authoritative specification for DroidForensix implementation. All technical decisions, architecture choices, and validation criteria are defined herein. No code implementation details are included — algorithmic approaches are specified at the conceptual level only.*
