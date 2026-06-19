# JADX Setup & Troubleshooting

## What is JADX?
JADX is a **dex to Java decompiler** — it extracts and decompiles DEX bytecode from APKs into readable Java source code. This is what powers the "Code" tab in DroidForensix.

## Why is decompiled code not showing?
If you upload an APK and see **"Code Decompilation Failed"**, it means JADX didn't run. Common reasons:

1. **JADX is not installed** on your system
2. **JADX path is incorrect** in `backend/config.py`
3. **JADX binary is not executable** (permissions issue)
4. **JADX timed out** (set to 300s per APK — large APKs may exceed this)

## Installation

### Windows (Recommended for DroidForensix)

#### Option A: Manual Download (Recommended)
1. Download the latest JADX release from: https://github.com/skylot/jadx/releases
2. Extract to: `D:\DroidForensix\tools\jadx`
3. Your final path should be: `D:\DroidForensix\tools\jadx\bin\jadx.bat`

Verify:
```cmd
D:\DroidForensix\tools\jadx\bin\jadx.bat --help
```

#### Option B: Scoop Package Manager
```cmd
scoop install jadx
```
This installs JADX globally. Update `backend/config.py`:
```python
JADX_PATH: str = r"C:\Users\<YourUsername>\scoop\apps\jadx\current\bin\jadx.bat"
```

#### Option C: Chocolatey
```cmd
choco install jadx
```

### Linux / macOS

```bash
# Using package manager
brew install jadx  # macOS

# Or download and extract
wget https://github.com/skylot/jadx/releases/download/v1.x.x/jadx-linux-x.x.x.zip
unzip jadx-linux-x.x.x.zip
export PATH=$PATH:/path/to/jadx/bin

# Update backend/config.py
# JADX_PATH: str = "/path/to/jadx/bin/jadx"
```

## Configuration in DroidForensix

1. After installing JADX, open `backend/config.py`
2. Update the `JADX_PATH` to match your installation:

```python
# Windows
JADX_PATH: str = r"C:\path\to\jadx\bin\jadx.bat"

# Linux / macOS
JADX_PATH: str = "/usr/local/bin/jadx"
```

3. Verify the path exists:
```bash
# Windows (PowerShell)
Test-Path "D:\DroidForensix\tools\jadx\bin\jadx.bat"

# Linux / macOS
which jadx
```

## Troubleshooting

### Verify JADX Works
```bash
# Windows
D:\DroidForensix\tools\jadx\bin\jadx.bat -d ./test_output your_sample.apk

# Linux / macOS
jadx -d ./test_output your_sample.apk
```

### Check Backend Logs
When you upload an APK, check the backend console for errors like:
```
jadx not found; check JADX_PATH in backend/config.py
jadx exit 1: ...
```

### Increase JADX Timeout
If JADX times out on large APKs, increase `STEP_TIMEOUT` in `backend/config.py`:
```python
STEP_TIMEOUT: int = 600  # Increase from 300 to 600 seconds
```

### Java Version
JADX requires **Java 11+**. Verify:
```bash
java -version
```

## After Installing JADX

1. **Restart the DroidForensix backend**
2. **Upload a test APK** — you should now see decompiled code in the Code tab
3. **Check the browser console** for any frontend errors

## Verify Installation in DroidForensix

There's a diagnostic API endpoint (coming soon) to verify JADX:
```bash
curl http://localhost:8000/api/diagnostics/jadx
```

This will return:
- JADX path configured
- Whether the binary exists
- JADX version
- Last 5 decompilation statuses
