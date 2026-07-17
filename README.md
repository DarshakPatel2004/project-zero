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

Submit an APK:

```powershell
curl -X POST http://localhost:8000/analyze `
  -H "Content-Type: application/json" `
  -d '{"apk_path": "samples\\malware\\example.apk"}'
```

Or run headless:

```powershell
.\venv\Scripts\python.exe -m analysis.pipeline samples\malware\example.apk
```

Output written to `analysis/work/<sha256>/pipeline_result.json`.

---

## API Endpoints

| Method | Path | Description |
|--------|------|-------------|
| GET | `/` | Health check |
| GET | `/api/samples` | List analyzed samples |
| GET | `/api/sample/{sample_id}` | Full analysis report |
| GET | `/api/graph/{sample_id}` | 3D graph data |
| GET | `/api/clusters` | Clustering data |
| GET | `/api/timeline/{sample_id}` | Attack-chain timeline |
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
| Frontend | React, Leaflet, WebSocket |
| Hardware | Lenovo LOQ 15 (Ryzen 7435HS, RTX 4050 6GB, 24GB RAM) |

---

## Testing

```powershell
.\venv\Scripts\Activate.ps1
pytest tests\
```

---

## Project Structure

```
backend/          — FastAPI server, threat intel, pipeline logic
frontend/         — React dashboard, Leaflet C2 maps
analysis/         — Pipeline steps (extraction, decoding, correlation)
scripts/          — Batch analysis, data collection utilities
article_assets/   — LinkedIn article screenshots and assets
samples/          — APK sample storage (malware + legitimate)
data/             — GeoIP databases, YARA rules
evaluation/       — Validation metrics, ground truth, FP analysis
```

---

## Research

This is part of an M.Sc. thesis at **National Forensic Sciences University**, supervised by Ms. Reet Chauhan.

- Methodology documented ✓
- Threat feeds integrated ✓
- Code open-source ✓
- Sample APKs from AndroZoo, MalwareBazaar, Drebin ✓
- FP rate validation in progress (~10-15% estimated)

### Known Limitations

- Encrypted native libraries flagged for manual inspection
- Reflection-heavy obfuscation handled by heuristics (not perfect)
- C2-blind malware (zero static artifacts) — documented limitation
- False positive rate currently TBD (50-indicator validation underway)

---

## Publication

Read the full article: **"I Built an Automated Android Malware Analysis Pipeline. Here's What 277 Real Samples Taught Me."**

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
