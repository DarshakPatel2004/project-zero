# Androguard Integration into DroidForensix

## Current State
- **Analyzer**: `androguard_test.py` (standalone, 500+ lines)
- **Pipeline**: 7-step system (APK extraction → string/entropy analysis → encoding detection → payload decoding → C2 extraction → threat chain → LLM scoring)
- **UI**: React frontend + FastAPI backend
- **Storage**: Disk cache for decompilation results

## Integration Goal
Make androguard a **module within the pipeline**, not a separate tool. Output feeds directly into the existing 7-step system.

---

## Step 1: Project Structure (Windows Path: `D:\DroidForensix`)

```
D:\DroidForensix\
├── backend/
│   ├── main.py                    # FastAPI app
│   ├── requirements.txt           # Dependencies (ADD androguard)
│   ├── core/
│   │   ├── __init__.py
│   │   ├── apk_processor.py       # NEW: Orchestrates all analysis
│   │   ├── androguard_analyzer.py # REFACTOR: androguard_test.py → module
│   │   ├── string_extractor.py    # Existing
│   │   ├── payload_decoder.py     # Existing
│   │   └── threat_chain.py        # Existing
│   ├── routers/
│   │   ├── upload.py
│   │   ├── analysis.py            # NEW: Orchestrate androguard analysis
│   │   └── reports.py
│   ├── models/
│   │   ├── analysis_result.py     # NEW: Unified schema
│   │   └── androguard_result.py   # NEW: Androguard-specific schema
│   └── cache/
│       └── decompilation/
├── frontend/
│   └── ...
└── docs/
    └── pipeline.md
```

---

## Step 2: Refactor androguard_test.py → androguard_analyzer.py

**Key changes:**
1. Remove `main()` and `sys.argv` parsing
2. Create class-based interface: `APKAnalyzer(apk_path) → dict`
3. Return structured results compatible with existing pipeline
4. Add error handling for production use

**File: `backend/core/androguard_analyzer.py`**

```python
from androguard.core.apk import APK
from androguard.core.dex import DEX
from androguard.core.analysis import analysis
from typing import Dict, List, Any
from collections import defaultdict
import zipfile, re, os

class APKAnalyzer:
    """Androguard-based static analysis module for DroidForensix"""
    
    def __init__(self, apk_path: str):
        self.apk_path = apk_path
        self.apk = None
        self.dexes = []
        self.dx = None
        self.results = {
            'metadata': {},
            'permissions': [],
            'fcm_components': [],
            'native_libs': [],
            'jni_methods': [],
            'obfuscated_classes': [],
            'bytecode_methods': [],
            'crypto_usage': [],
            'suspicious_strings': [],
            'network_indicators': [],
            'risk_assessment': {}
        }
    
    def load_dex_files(self) -> bool:
        """Load and parse DEX files. Returns True on success."""
        try:
            self.apk = APK(self.apk_path)
            for dex_data in self.apk.get_all_dex():
                d = DEX(dex_data)
                self.dexes.append(d)
            
            if self.dexes:
                self.dx = analysis.Analysis(self.dexes[0])
                for d in self.dexes[1:]:
                    self.dx.add(d)
            return True
        except Exception as e:
            self.results['error'] = f"DEX load failed: {str(e)}"
            return False
    
    # ... (refactor all analysis methods, keep logic identical)
    
    def run(self) -> Dict[str, Any]:
        """Execute full analysis and return results"""
        if not self.load_dex_files():
            return {'success': False, 'error': self.results['error']}
        
        self.extract_metadata()
        self.analyze_permissions()
        self.find_fcm_components()
        self.extract_native_libraries()
        self.analyze_bytecode_deep()
        self.find_crypto_usage()
        self.analyze_obfuscation()
        self.calculate_risk()
        
        return {
            'success': True,
            'data': self.results
        }
    
    # Keep all existing methods unchanged
```

---

## Step 3: Create APK Processor Orchestrator

**File: `backend/core/apk_processor.py`**

This sits between the API layer and individual analysis modules.

```python
from pathlib import Path
from typing import Dict, Any
from .androguard_analyzer import APKAnalyzer
from .string_extractor import StringExtractor
from .payload_decoder import PayloadDecoder
from .threat_chain import ThreatChainAnalyzer

class APKProcessor:
    """Orchestrates the full 7-step pipeline"""
    
    def __init__(self, apk_path: str, cache_dir: Path = None):
        self.apk_path = apk_path
        self.cache_dir = cache_dir or Path("./cache")
    
    def process(self) -> Dict[str, Any]:
        """
        Execute 7-step pipeline:
        1. Androguard static analysis
        2. String extraction & analysis
        3. Entropy analysis
        4. Encoding detection
        5. Payload decoding
        6. C2 extraction
        7. Threat chain correlation + LLM scoring
        """
        
        # Step 1: Androguard
        androguard_analyzer = APKAnalyzer(self.apk_path)
        androguard_results = androguard_analyzer.run()
        if not androguard_results['success']:
            return {'error': androguard_results['error']}
        
        # Extract findings for downstream steps
        suspicious_strings = androguard_results['data']['suspicious_strings']
        fcm_components = androguard_results['data']['fcm_components']
        native_libs = androguard_results['data']['native_libs']
        
        # Step 2-7: Feed into existing pipeline
        string_extractor = StringExtractor(
            suspicious_strings=suspicious_strings,
            cache_dir=self.cache_dir
        )
        strings_analyzed = string_extractor.run()
        
        # ... continue through remaining steps
        
        return {
            'androguard': androguard_results['data'],
            'strings': strings_analyzed,
            'threat_chain': threat_chain_results,
            # ... all steps
        }
```

---

## Step 4: Update FastAPI Routes

**File: `backend/routers/analysis.py`**

```python
from fastapi import APIRouter, File, UploadFile
from pathlib import Path
from ..core.apk_processor import APKProcessor

router = APIRouter(prefix="/api/analysis", tags=["analysis"])

@router.post("/full")
async def full_analysis(file: UploadFile = File(...)):
    """Execute full 7-step pipeline"""
    
    # Save uploaded file
    apk_path = Path(f"./uploads/{file.filename}")
    with open(apk_path, "wb") as f:
        f.write(await file.read())
    
    # Run processor
    processor = APKProcessor(str(apk_path))
    results = processor.process()
    
    return {
        'status': 'success',
        'data': results
    }

@router.post("/androguard-only")
async def androguard_analysis(file: UploadFile = File(...)):
    """Run just the androguard static analysis"""
    
    apk_path = Path(f"./uploads/{file.filename}")
    with open(apk_path, "wb") as f:
        f.write(await file.read())
    
    analyzer = APKAnalyzer(str(apk_path))
    results = analyzer.run()
    
    return results
```

---

## Step 5: Update requirements.txt

```
# Android Analysis
androguard>=4.0.0
apkutils2>=2.1.0

# Existing dependencies
fastapi==0.104.1
uvicorn==0.24.0
pydantic==2.0.0
ollama==0.0.11
reportlab==4.0.4

# ML/NLP
numpy>=1.24.0
scikit-learn>=1.3.0
xgboost>=2.0.0
tensorflow>=2.14.0

# Utilities
requests>=2.31.0
python-dotenv>=1.0.0
```

---

## Step 6: Update FastAPI main.py

```python
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from contextlib import asynccontextmanager
from .routers import upload, analysis, reports
from .services.ollama_service import OllamaService

# Lifespan event
@asynccontextmanager
async def lifespan(app: FastAPI):
    # Startup
    print("[*] Starting Ollama service...")
    ollama_svc = OllamaService()
    await ollama_svc.ensure_running()
    
    yield
    
    # Shutdown
    print("[*] Cleaning up...")

app = FastAPI(
    title="DroidForensix API",
    version="2.0",
    lifespan=lifespan
)

# CORS
app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:3000"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Routes
app.include_router(upload.router)
app.include_router(analysis.router)
app.include_router(reports.router)

@app.get("/health")
async def health():
    return {"status": "ok"}

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)
```

---

## Step 7: Production Checklist

### Install androguard
```bash
# Windows PowerShell (in your project venv)
pip install androguard>=4.0.0
```

### Handle Windows-specific issues
1. **Path handling**: Use `pathlib.Path` everywhere (already in refactored code)
2. **Temp files**: Store in `%TEMP%` or project `./temp/` folder
3. **Binary parsing**: Androguard handles this, but watch for encoding errors on .so extraction

### Error handling
```python
try:
    analyzer = APKAnalyzer(apk_path)
    results = analyzer.run()
except Exception as e:
    logger.error(f"Androguard failed: {e}")
    # Fallback to lighter analysis or skip androguard step
    return {'error': str(e), 'fallback': True}
```

### Caching strategy
- Cache androguard results by APK hash (same sample = skip re-analysis)
- Store in `./cache/androguard/{apk_hash}.json`
- Key: `apk_hash = hashlib.sha256(apk_bytes).hexdigest()`

---

## Step 8: Update React Frontend (Optional)

**Add androguard tab to analysis view:**

```jsx
// components/AnalysisView.jsx

const tabs = [
  { id: 'androguard', label: 'Static Analysis (Androguard)', component: <AndroguardTab /> },
  { id: 'strings', label: 'Strings & Entropy', component: <StringsTab /> },
  { id: 'threat_chain', label: 'Threat Chain', component: <ThreatChainTab /> },
];

function AndroguardTab() {
  const [data, setData] = useState(null);
  
  return (
    <div>
      <h3>Androguard Static Analysis</h3>
      <div className="grid">
        <PermissionsPanel permissions={data.permissions} />
        <FCMComponentsPanel components={data.fcm_components} />
        <NativeLibsPanel libs={data.native_libs} />
        <ObfuscationPanel classes={data.obfuscated_classes} />
        <RiskAssessmentPanel risk={data.risk_assessment} />
      </div>
    </div>
  );
}
```

---

## Step 9: Testing

```bash
# Test androguard module in isolation
cd D:\DroidForensix\backend
python -c "from core.androguard_analyzer import APKAnalyzer; a = APKAnalyzer('test.apk'); print(a.run())"

# Test via API
curl -X POST http://localhost:8000/api/analysis/androguard-only \
  -F "file=@RTO.apk"

# Test full pipeline
curl -X POST http://localhost:8000/api/analysis/full \
  -F "file=@RTO.apk"
```

---

## Step 10: Documentation

**Update `docs/pipeline.md`:**

```markdown
# DroidForensix 7-Step Pipeline

## Step 1: Static Analysis (Androguard)
- **Input**: APK file
- **Output**: Permissions, FCM components, native libs, JNI methods, obfuscation, risk score
- **Module**: `backend/core/androguard_analyzer.py`
- **Time**: ~5-10s per APK

## Step 2-7: [Existing documentation]
```

---

## Integration Checklist

- [ ] Move `androguard_test.py` → `backend/core/androguard_analyzer.py`
- [ ] Remove CLI code, keep analysis logic
- [ ] Create `apk_processor.py` orchestrator
- [ ] Add androguard to `requirements.txt`
- [ ] Update FastAPI routes to call APKProcessor
- [ ] Test in isolation: `APKAnalyzer(apk_path).run()`
- [ ] Test via API endpoint
- [ ] Add error handling for malformed APKs
- [ ] Cache results by APK hash
- [ ] Update React frontend with androguard tab
- [ ] Update documentation
- [ ] Performance profile (target: <10s per APK)

---

## Why This Approach

| Aspect | Benefit |
|--------|---------|
| **Module-based** | Reusable, testable, easy to swap/upgrade androguard |
| **No duplication** | Feed androguard findings into existing pipeline, not parallel runs |
| **Caching** | Don't re-analyze same APK twice |
| **API-first** | Frontend calls one endpoint, gets all results |
| **Fallback-ready** | If androguard fails, other steps can still run |
| **Windows-safe** | All Path handling via pathlib |

---

## Common Pitfalls & Fixes

### Pitfall 1: Androguard takes 30s per APK
- **Cause**: Bytecode deep analysis on large DEX files
- **Fix**: Make bytecode analysis optional, skip for quick turnaround
```python
def run(self, deep_analysis=False):
    # ...
    if deep_analysis:
        self.analyze_bytecode_deep()
```

### Pitfall 2: Native library string extraction fails
- **Cause**: Binary parsing issues on Windows
- **Fix**: Wrap in try-catch, log, continue
```python
try:
    strings = re.findall(b'[\x20-\x7e]{4,}', content)
except Exception as e:
    logger.warning(f"Native string extraction failed: {e}")
    self.results['native_strings'] = []
```

### Pitfall 3: APK doesn't have certificate
- **Cause**: Self-signed or missing signature
- **Fix**: Already handled in code, just skip
```python
if not cert:
    self.results['certificate_info'] = {'error': 'No cert found'}
```

### Pitfall 4: Cached results go stale
- **Cause**: APK updated but hash same (unlikely but possible)
- **Fix**: Add version checking or TTL
```python
cache_key = f"{apk_hash}_{apk_mtime}"  # Include modification time
```

---

## Next: Frida Integration

Once androguard is integrated, add Frida-based dynamic analysis:

```python
# backend/core/frida_analyzer.py
class FridaAnalyzer:
    def hook_jni_methods(self, package_name, jni_methods):
        """Hook JNI entry points identified by androguard"""
        # Use androguard results to target frida hooks
        pass
    
    def intercept_fcm_messages(self, package_name):
        """Hook FCM receiver if FCM components detected"""
        pass
```

This keeps static + dynamic analysis cleanly separated but connected.
