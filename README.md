# DroidForensix

Windows-native Android malware static-analysis pipeline.

DroidForensix decompiles APKs with JADX/APKTool, extracts and decodes strings,
correlates threat chains, and assesses risk via a local Ollama LLM — all
running natively on Windows 10+ with Python 3.9+.

## Required Windows Installations

- **Python 3.9+** – https://www.python.org/downloads/ (check "Add Python to PATH")
- **Git for Windows** – https://git-scm.com/download/win (provides Git Bash utilities such as `strings.exe`)
- **Ollama for Windows** – https://ollama.com/download/windows (the local model is configured in `.env`)

The repository now ships with portable copies of the analysis toolchain under
`tools\` so no separate Java/Node/JADX/APKTool installation is required:

- `tools\jdk\jdk-21.0.3+9-jre` – bundled OpenJRE for JADX/APKTool
- `tools\jadx` – JADX decompiler
- `tools\apktool` – APKTool unpacker
- `tools\node\current` – Node.js 22 LTS for the frontend

## Quick Start

### 1. Clone the repository

```powershell
cd D:\
git clone https://github.com/your-org/DroidForensix.git DroidForensix
cd DroidForensix
```

### 2. Create and activate a virtual environment

```powershell
python -m venv venv
.\venv\Scripts\Activate.ps1
```

### 3. Install Python dependencies

```powershell
pip install -r requirements.txt
```

### 4. Configure the Ollama model

Copy the example environment file:

```powershell
copy .env.example .env
```

The default model is set to the locally available
`hf.co/krgl/Llama-Primus-Base_8bit-gguf:latest`. If you prefer a different
model, update `OLLAMA_MODEL` in `.env` and pull it:

```powershell
ollama pull <model-name>
```

### 5. Start the services

Three convenience batch scripts are provided in the repository root. Open a
separate terminal for each and run them from `D:\DroidForensix`:

```powershell
.\run_ollama.bat
```

```powershell
.\run_backend.bat
```

```powershell
.\run_frontend.bat
```

The backend API will be available at `http://localhost:8000` and the frontend
Vite dev server at `http://localhost:5173`.

`run_backend.bat` automatically:

- Activates the Python venv
- Adds the bundled JRE, JADX, and APKTool to `PATH`
- Forces `OLLAMA_HOST=http://localhost:11434` (so it works even if a system
  environment variable points to `0.0.0.0:11434`)
- Starts the FastAPI backend with uvicorn

`run_frontend.bat` automatically installs frontend dependencies if `node_modules`
is missing and then starts the Vite dev server using the bundled Node.js.

## Batch Scripts

| Script | Purpose |
|--------|---------|
| `run_ollama.bat` | Starts the local Ollama service on Windows. |
| `run_backend.bat` | Activates the Python venv, sets up tool PATH/JAVA_HOME/Ollama host, and starts the FastAPI backend. |
| `run_frontend.bat` | Installs frontend dependencies if needed and starts the Vite dev server. |

## Analyzing an APK

Once the backend is running you can POST an APK path:

```powershell
curl -X POST http://localhost:8000/analyze `
  -H "Content-Type: application/json" `
  -d '{"apk_path": "D:\\DroidForensix\\samples\\malware\\example.apk"}'
```

Or run the pipeline directly from Python:

```powershell
.\venv\Scripts\python.exe -m analysis.pipeline D:\DroidForensix\samples\malware\example.apk
```

All intermediate files and the final `pipeline_result.json` are written to
`D:\DroidForensix\analysis\work\<sha256>\`.

## API Endpoints

- `GET  /` – Health check
- `GET  /api/samples` – List analyzed samples
- `GET  /api/sample/{sample_id}` – Full analysis report
- `GET  /api/graph/{sample_id}` – 3D graph data
- `GET  /api/clusters` – Clustering data for all samples
- `GET  /api/timeline/{sample_id}` – Attack-chain timeline
- `POST /analyze` – Trigger analysis of an APK
- `WS   /ws` – Real-time analysis events

## Environment Variables

Copy `.env.example` to `.env` and adjust values as needed:

```powershell
copy .env.example .env
```

Key variables:

- `OLLAMA_HOST=http://localhost:11434`
- `OLLAMA_MODEL=hf.co/krgl/Llama-Primus-Base_8bit-gguf:latest`
- `NVIDIA_NIM_API_KEY` (optional; when set, NIM is preferred over Ollama)

## Testing

Run the test suite with pytest:

```powershell
.\venv\Scripts\Activate.ps1
$env:JAVA_HOME = "D:\DroidForensix\tools\jdk\jdk-21.0.3+9-jre"
$env:PATH = "$env:JAVA_HOME\bin;D:\DroidForensix\tools\jadx\bin;D:\DroidForensix\tools\apktool;D:\DroidForensix\tools\node\current;$env:PATH"
$env:OLLAMA_HOST = "http://localhost:11434"
pytest tests\
```

To verify the Ollama connection manually:

```powershell
.\venv\Scripts\python.exe -c "import requests; print(requests.get('http://localhost:11434/api/tags').json())"
```

## Notes

- All file operations use `pathlib.Path` for cross-platform safety.
- Do not hard-code Linux paths such as `/home/user/...` or `/tmp/`; use
  `settings.WORK_DIR` from `backend/config.py` instead.
- Tool paths in `backend/config.py` point to the bundled `tools\` directory.
  If you already have JADX/APKTool installed elsewhere, edit those paths.
