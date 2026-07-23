# DroidForensix

**Automated Android malware static-analysis pipeline** — extract C2 infrastructure from bytecode without execution. 63x faster than manual analysis.

[![Python](https://img.shields.io/badge/Python-3.9%2B-blue?logo=python)](https://python.org)
[![License](https://img.shields.io/badge/License-MIT-green)](LICENSE)

**1,711 C2 indicators** extracted from **277 malware samples** across 12 countries. **75% concentrated** in Chinese cloud providers. **63x speedup** over manual analysis (3.2 hours vs. 204 hours).

---

## Key Results

| Metric | Value |
|--------|-------|
| Samples analyzed | 277 (204 timed) |
| C2 indicators extracted | 1,711 |
| Unique IPs | 203 (191 geolocated, 94%) |
| Geographic clusters | 26 across 12 countries |
| Chinese cloud concentration | 75% (Alibaba, Tencent, CHINANET) |
| Pipeline speed (LLM path) | ~1.5 min/sample |
| Pipeline speed (heuristic skip) | ~0.4 min/sample (~40% of samples) |
| Total runtime (204 samples) | 3.2 hours sequential |
| Speedup vs. manual | **63x** |
| Recall (after heuristic fix) | **95%** (recovered from 80%) |

---

## How It Works

```
APK Input → Decompile → Analyze → Extract → Correlate → Geolocate → Score → Report
```

**9-step pipeline:**
1. **Decompose** APK via AndroGuard (manifest, permissions, activities, services)
2. **Decompile** Dalvik bytecode to Java via JADX
3. **Analyze** method calls for suspicious APIs (WebSocket, shell exec, reflection)
4. **Extract** indicators (domains, IPs, hardcoded strings, API endpoints)
5. **Map** permission-to-capability relationships
6. **Correlate** across VT, OTX, Shodan, Censys (parallel threat feeds)
7. **Geolocate** C2 servers, identify cloud provider, cluster by region
8. **Score** confidence based on method call frequency + contextual evidence
9. **Report** structured JSON + PDF with per-phase timing

### Dynamic Validation (Step 19 — Infrastructure Complete)

**Status:** Framework built and validated; disabled by default (`ENABLE_DYNAMIC=false`).

**What's Implemented:**
- Frida-based runtime instrumentation on headless Android emulator
- 5 hook targets: Method.invoke, URL.openConnection, String decoding, Cipher operations, ClassLoader
- Capture engine (line-by-line JSON parsing, 10MB cap, 30s idle timeout)
- Correlator: matches runtime-observed C2 to static candidates, computes confidence deltas (×1.3 validated, ×0.7 contradicted)
- Integration: optional Step 19 in pipeline, graceful fallback if AVD unavailable

**Why Disabled:**
Static analysis on bytecode recovers 95% of actionable indicators across 277 samples. Runtime validation would require malware self-activation in a 60-120s window — a constraint that doesn't hold for real APKs in isolation. The framework is ready for future work with explicit triggers (custom launchers, Frida's spawn mode).

**For Future Work:**
- Phase 2: String decryption correlation — extract Cipher.doFinal() output, match decoded strings against static C2 candidates
- Expected recovery: Additional 5-10% on reflection-based C2 construction patterns
- Timeline: Post-publication (Q2 2027+)

**To Enable (for development):**
```
ENABLE_DYNAMIC=true in .env
python -m analysis.pipeline sample.apk --dynamic
```

---

## Quick Start

### Prerequisites

- **Python 3.9+**
- **Git for Windows**
- **Ollama for Windows** – https://ollama.com/download/windows

The repo ships with portable copies of JADX, APKTool, JDK, and Node.js under `tools\`.

### Setup

```powershell
git clone https://github.com/DarshakPatel2004/DroidForensix.git
cd DroidForensix
python -m venv venv
.\venv\Scripts\Activate.ps1
pip install -r requirements.txt     # flexible deps
# OR for pinned reproducible build:
pip install -r requirements-lock.txt

copy .env.example .env
```

### Run

Open three terminals:

```powershell
# Terminal 1: Ollama
.\run_ollama.bat

# Terminal 2: Backend
.\run_backend.bat

# Terminal 3: Frontend (optional)
.\run_frontend.bat
```

Submit an APK via the dashboard at `http://localhost:5173` (drag-and-drop), or via CLI:

```powershell
curl -X POST http://localhost:8000/analyze \
  -H "Content-Type: application/json" \
  -d '{"apk_path": "samples\\malware\\example.apk"}'
```

Or run headless:

```powershell
.\venv\Scripts\python.exe -m analysis.pipeline samples\malware\example.apk
```

Output written to `analysis/work/<sha256>/pipeline_result.json`.

---

## Dashboard

The React dashboard provides four levels of analysis for each sample:

- **Glance (Level 1):** Threat summary with score, family, red flags
- **Family Attribution:** Collapsible FamilySignalsCard with primary match, confidence breakdown bars (permissions, C2 overlap, obfuscation, code similarity), method badge, candidates, and related samples
- **Triage (Level 2):** MAFIA attribution evidence with confidence breakdown, supporting signals, related samples
- **Investigation (Level 3):** Dissection tabs — Manifest, Permissions, Components, Code (with syntax highlighting), Strings, DEX (with entropy chart), Native Libs
- **Threat Chains:** Interactive threat chain viewer with client-side decoder (Base64, hex, URL, XOR, custom JS) for each decoding step

### Frontend Setup

```powershell
cd frontend
npm install
npm run dev      # serves on http://localhost:5173
```

### Frontend Tests

```powershell
cd frontend
npm run test     # 248 tests across 38 test files — all pass
```

---

## API Endpoints

| Method | Path | Description |
|--------|------|-------------|
| GET | `/` | Health check |
| GET | `/api/samples` | List analyzed samples |
| GET | `/api/sample/{sample_id}` | Full analysis report |
| GET | `/api/sample/{sample_id}/attribution` | MAFIA attribution evidence |
| GET | `/api/sample/{sample_id}/threat-summary` | Threat summary (glance) |
| GET | `/api/sample/{sample_id}/dissection` | Full dissection data |
| GET | `/api/sample/{sample_id}/dissection/{section}` | Per-tab dissection data |
| GET | `/api/sample/{sample_id}/code-analysis/{class}` | Method-level code analysis |
| GET | `/api/graph/{sample_id}` | 3D graph data |
| GET | `/api/clusters` | Clustering data |
| GET | `/api/timeline/{sample_id}` | Attack-chain timeline |
| POST | `/api/upload` | Upload APK for analysis |
| POST | `/analyze` | Trigger APK analysis |
| WS | `/ws` | Real-time analysis events |

---

## Samples

Evaluated on **306 Android APKs** from 49 malware families across 4 sources:

| Source | Count | Description |
|--------|-------|-------------|
| AndroZoo | ~200 | Academic malware corpus |
| MalwareBazaar | ~50 | Community-submitted malware |
| Pendrive | ~30 | Manually collected |
| Modern Eval | ~26 | Modern evaluation set |

**Top families:** Cerberus (16), Hydra (11), TeaBot (11), Ermac (10), SpyNote (8), Anubis (6), Flubot (6)

Full metadata in `sample_metadata.csv`.

---

## Tech Stack

| Layer | Technology |
|-------|-----------|
| Backend | FastAPI, Ollama (Mistral 7B) |
| Decompilation | AndroGuard, JADX, APKTool |
| Threat Intel | VirusTotal, AlienVault OTX, Shodan, Censys, AbuseIPDB |
| Geolocation | MaxMind GeoLite2 |
| Frontend | React, Leaflet, WebSocket, highlight.js, Recharts |
| Hardware | Lenovo LOQ 15 (Ryzen 7435HS, RTX 4050 6GB, 24GB RAM) |

---

## Testing

### Backend (Python)

```powershell
.\venv\Scripts\Activate.ps1
pytest tests\
```

### Frontend (React)

```powershell
cd frontend
npm run test     # 248 tests across 38 test files — all pass
```

---

## Project Structure

```
backend/          — FastAPI server, threat intel, pipeline logic
frontend/         — React dashboard, Leaflet C2 maps, FamilySignalsCard
analysis/         — 9-step pipeline (extraction → decoding → correlation → report)
scripts/          — Batch analysis, data collection utilities
article_assets/   — LinkedIn article screenshots and assets
samples/          — APK sample storage (malware + legitimate)
data/             — GeoIP databases, YARA rules
evaluation/       — Validation metrics, ground truth, FP analysis
tests/            — Python backend tests (pytest)
docs/             — Dashboard guide, codebase reference, superpower plans
```

---

## Research

This is part of an M.Sc. thesis at **National Forensic Sciences University**, supervised by Ms. Reet Chauhan.

- Methodology documented ✓
- Threat feeds integrated ✓
- Code open-source ✓
- Sample APKs from AndroZoo, MalwareBazaar, Drebin ✓
- FP rate validation in progress (~10-15% estimated)
- 95% recall on balanced evaluation set ✓
- 63x speedup over manual analysis (verified on 204 timed samples) ✓

### Known Limitations

- Encrypted native libraries flagged for manual inspection
- Reflection-heavy obfuscation handled by heuristics (not perfect)
- C2-blind malware (zero static artifacts) — documented limitation
- False positive rate: ~10-15% estimated (50-indicator validation underway)
- Comparative aggregator validation (VT/OTX/Shodan baselines) — future work

---

## Publication

Read the full article: **"Static Analysis Beats Sandboxing. Here's How I Analyzed 277 Malware Samples in 3.2 Hours."**

The article emphasizes validated findings: 1,711 C2 indicators, 203 unique IPs across 12 countries with 75% concentration in Chinese cloud providers, 63x speedup over manual analysis, and honest documentation of methodology gaps and ongoing validation.

**Key article sections:**
- The hypothesis: Static analysis extracts infrastructure faster than sandboxing
- Real findings: Coverage, accuracy, performance metrics (all reproducible)
- What I got wrong: Mistakes discovered and fixed (LLM bottleneck, heuristic over-optimization, threat intel layer design)
- Limitations: Encrypted libraries, reflection obfuscation, C2-blind malware
- Next: Threat Synthesis Engine (multi-sample attribution, Q1 2027)

---

## Environment Variables

Copy `.env.example` to `.env`:

```powershell
copy .env.example .env
```

Key variables:

- `OLLAMA_HOST=http://localhost:11434`
- `OLLAMA_MODEL=mistral:7b-instruct-q4_K_M`
- `NVIDIA_NIM_API_KEY` (optional)

---

## License

MIT
