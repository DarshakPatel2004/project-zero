# DroidForensix Dashboard Implementation Plan
## Comprehensive Roadmap (Phase 0 → Phase 3)

---

## EXECUTIVE SUMMARY

**Phase 0 (NOW — December 2026)**: Core dashboard for dissertation
- Glance Level: Threat summary + red flags
- Triage Level: Attribution evidence + MAFIA confidence explanation
- Investigation Level: Dissection tabs + related samples
- Target: SOC analysts (quick triage + deep investigation)

**Phase 1 (Jan–Jun 2027)**: Operational features
- Side-by-side comparison (malicious vs. benign)
- Export (PDF, JSON, SIEM feeds)
- Collaboration (notes, tags, team sharing)

**Phase 2 (Jul–Dec 2027)**: Intelligence & visualization
- Threat actor profiles
- Family evolution timeline
- 3D threat landscape (50K samples)
- Evasion detection showcase

**Phase 3 (Future)**: Advanced behavioral analysis
- Visual attack chains
- Network traffic prediction
- Risk propagation graphs

---

# PHASE 0: CORE DASHBOARD (December 2026)
## Timeline: 8 weeks (June → August 2026 for dissertation buffer)

### Backend Requirements

#### 1. APK Dissection Engine
**Status**: Kimi in progress
**Deliverable**: `backend/dissection.py`
- APKDissector class using androguard + zipfile
- Methods: extract_metadata, extract_permissions, extract_components, extract_native_libs, extract_resources, extract_dex_stats, extract_file_structure, list_jadx_classes, get_class_code, load_strings
- Save dissection.json to disk after pipeline completes
- Tests: test_dissection.py (5+ test cases)

**Acceptance Criteria**:
- ✅ `pytest tests/test_dissection.py` passes
- ✅ dissection.json saved alongside pipeline_result.json
- ✅ All extraction methods handle missing files gracefully (return empty/null, not crash)

---

#### 2. MAFIA Attribution API Endpoints
**Status**: Design phase
**Deliverable**: `backend/main.py` additions
**New Endpoints**:

```python
# Existing endpoints (verify they work):
GET /api/samples
  Returns: [{ sample_id, package_name, family, threat_score, ... }]

GET /api/sample/{sample_id}
  Returns: { sample_id, package_name, ... pipeline_result.json ... }

# New endpoints for dissection:
GET /api/sample/{sample_id}/dissection
  Returns: full dissection.json

GET /api/sample/{sample_id}/dissection/manifest
GET /api/sample/{sample_id}/dissection/permissions
GET /api/sample/{sample_id}/dissection/components
GET /api/sample/{sample_id}/dissection/strings
GET /api/sample/{sample_id}/dissection/dex
  Returns: granular dissection data (for tab-based frontend)

GET /api/sample/{sample_id}/dissection/classes
  Returns: list of decompiled class names from jadx/sources/

GET /api/sample/{sample_id}/dissection/code/{class_name}
  Returns: source code for a single class

# NEW: Code Analysis endpoints
GET /api/sample/{sample_id}/code-analysis/{class_name}
  Returns: {
    class_name: string,
    methods: [
      {
        name: string,
        risk_level: "LOW|MEDIUM|CRITICAL",
        techniques: ["reflection", "service_dropping", "payload_drop", ...],
        calls: [{ target, line, action }],
        suspicious_lines: [{ line, pattern, code, description, risk }]
      }
    ],
    string_references: { string_value: [{ method, line, usage }] },
    attack_flow: [{ step, method, line, action, description }]
  }

GET /api/sample/{sample_id}/string-references/{string_value}
  Returns: { string, usages: [{ method, line, usage, context }] }

# NEW: MAFIA-specific endpoints
GET /api/sample/{sample_id}/attribution
  Returns: {
    family: "XHelper",
    confidence: 0.95,
    confidence_breakdown: {
      permissions_match: 0.92,
      c2_overlap: 0.98,
      obfuscation_pattern: 0.93,
      code_similarity: 0.94
    },
    supporting_signals: [
      "11/15 permissions match family baseline",
      "C2 domains overlap with 3 known variants",
      "Obfuscation pattern matches family",
      "Code structure similarity: 0.92"
    ],
    related_samples: [
      { sample_id: "abc...", similarity: 0.97 },
      { sample_id: "def...", similarity: 0.89 },
      { sample_id: "ghi...", similarity: 0.76 }
    ]
  }

GET /api/sample/{sample_id}/threat-summary
  Returns: {
    threat_score: 92,
    threat_level: "CRITICAL",
    red_flags: [
      { type: "dangerous_permissions", count: 7 },
      { type: "active_c2_endpoints", count: 3 },
      { type: "obfuscation", level: "HIGH" },
      { type: "evasion_techniques", count: 5 }
    ],
    family: "XHelper",
    confidence: 0.95,
    last_seen: "2024-06-10",
    similar_samples_count: 47
  }
```

**Implementation Notes**:
- Load from existing pipeline_result.json + step2_strings.json + dissection.json
- MAFIA attribution data should come from Step 7 (LLM assessment) + your ensemble classification output
- `confidence_breakdown` is the KEY differentiator—explain the 95% to analysts
- Error handling: 404 for missing samples, 500 with clear error messages

**Acceptance Criteria**:
- ✅ All endpoints return valid JSON
- ✅ `/api/sample/{sample_id}/attribution` shows MAFIA confidence breakdown
- ✅ No regressions in existing `/api/samples` and `/api/sample/{id}` endpoints
- ✅ Tested with 5+ real samples from analysis/work/

---

#### 3. Code Analysis Engine
**Status**: Design phase
**Deliverable**: `backend/code_analysis.py`

This module analyzes decompiled Java code to extract:
- Method-level risk assessment
- Suspicious patterns (reflection, service launching, payload dropping)
- String references and their usage context
- Attack flow reconstruction

```python
from backend.dissection import APKDissector
from analysis.step7_llm_assessment import risk_patterns  # Reuse existing patterns

class CodeAnalyzer:
    def __init__(self, apk_path, work_dir, sample_id):
        self.dissector = APKDissector(apk_path, work_dir)
        self.sample_id = sample_id
        self.work_dir = work_dir
    
    def analyze_class(self, class_name: str) -> dict:
        """Analyze a single decompiled class."""
        source = self.dissector.get_class_code(class_name)
        
        return {
            'class_name': class_name,
            'methods': self._extract_methods(source),
            'string_references': self._extract_string_refs(source),
            'attack_flow': self._reconstruct_attack_flow(source)
        }
    
    def _extract_methods(self, source: str) -> list:
        """Extract methods and assess risk per method."""
        # Parse Java methods
        # For each method:
        #   - Extract method name, lines, calls
        #   - Scan for suspicious patterns (reflection, service drop, payload)
        #   - Assign risk_level (LOW/MEDIUM/CRITICAL)
        #   - Identify suspicious_lines with pattern + description
        pass
    
    def _extract_string_refs(self, source: str) -> dict:
        """Find all string constants and their usage."""
        # For each string in code:
        #   - Extract string value
        #   - Find line number(s)
        #   - Find method(s) using it
        #   - Classify usage (payload_filename, service_name, social_eng, etc.)
        # Return: { "string_value": [{ method, line, usage_type }] }
        pass
    
    def _reconstruct_attack_flow(self, source: str) -> list:
        """Build attack chain from method calls."""
        # Find entry points (onCreate, onStart, etc.)
        # Build call graph
        # Trace paths to malicious calls
        # Return ordered steps: entry → decision → action → malware
        pass

    def _classify_string(self, string_value: str) -> str:
        """Classify string by usage type."""
        # payload_filename: "SMSApp.apk", "payload.dex", etc.
        # service_name: "com.android.battery", etc.
        # social_engineering: "New version", "Update", etc.
        # c2_domain: URLs, IPs
        # file_path: "/data/data/...", etc.
        pass

    def _detect_pattern(self, code_line: str) -> str:
        """Detect malware pattern in code line."""
        # reflection_abuse: declaredField.setAccessible()
        # service_dropping: startService(new Intent(...))
        # payload_drop: extract/install APK
        # anti_analysis: signature check, device check, etc.
        pass
```

**Acceptance Criteria**:
- ✅ Can analyze BaseAActivity and extract m31b() as CRITICAL
- ✅ Identifies "SMSApp.apk" as payload_filename
- ✅ Reconstructs attack flow: onCreate → m31b → m25c → m29e
- ✅ String references mapped to methods and line numbers
- ✅ All suspicious patterns detected (service_drop, payload_drop, reflection, etc.)

---

#### 4. Backend Tests
**Status**: To be written
**Deliverable**: `tests/test_dissection.py` + `tests/test_attribution.py` + `tests/test_code_analysis.py`

```python
# test_code_analysis.py
def test_code_analyzer_on_real_sample():
    """Test CodeAnalyzer on DragRacing sample."""
    
def test_detect_payload_drop_pattern():
    """Identify SMSApp.apk drop in m29e()."""
    
def test_detect_service_spoofing_pattern():
    """Identify com.android.battery service spoofing."""
    
def test_attack_flow_reconstruction():
    """Build correct flow: onCreate → m31b → m25c → m29e."""
    
def test_string_references_mapping():
    """Map "SMSApp.apk" to m29e() line 156."""
    
def test_method_risk_assessment():
    """Classify m31b() as CRITICAL, onCreate() as LOW."""
    
def test_suspicious_line_detection():
    """Detect reflection abuse, service launch, payload extraction."""
```

**Acceptance Criteria**:
- ✅ pytest tests/test_code_analysis.py -v (all pass)
- ✅ Coverage > 80% for code_analysis.py
- ✅ DragRacing sample analysis matches documented behavior

---

#### 5. Backend Tests Checklist (Updated)
**Status**: To be written
**Deliverable**: `tests/test_dissection.py` + `tests/test_attribution.py` + `tests/test_code_analysis.py`

---

### Frontend Requirements

#### 1. Design System
**Status**: Design phase (This document)
**Deliverable**: Design spec document

**Color Palette**:
- Background: #0a0e27 (dark navy)
- Surface: #1a1f3a (slightly lighter)
- Text primary: #e0e6ed (off-white)
- Text secondary: #8a92a8 (muted gray)
- Border: #2a3f5f (subtle blue-gray)
- Accent critical: #ff3333 (threat red)
- Accent warning: #ff9933 (caution orange)
- Accent safe: #33ff33 (safe green)
- Accent info: #3399ff (info blue)

**Typography**:
- Headings: Inter (sans-serif), 600 weight, letter-spacing 0.5px
- Body: Inter (sans-serif), 400 weight
- Monospace: IBM Plex Mono (code, hashes, URLs)
- Hierarchy: 2.5rem (h1) → 1.5rem (h2) → 1rem (h3) → 0.875rem (body) → 0.75rem (caption)

**Spacing Grid**: 8px base
- Padding: 8px, 16px, 24px, 32px, 48px
- Margin: same
- Gap: 16px (grid), 12px (list)

**Animations**:
- Fade transitions: 200ms ease-out
- State changes (severity): 300ms cubic-bezier(0.4, 0, 0.2, 1)
- No spinning loaders; use progress bars instead
- Hover: subtle shadow + 0.4 scale on cards

**Components**:
- ThreatBadge: Shows severity (CRITICAL/HIGH/MEDIUM/LOW) with color-coded background
- ConfidenceBar: Horizontal bar showing 0–100% with color gradient
- PermissionCard: Single permission with risk level, description
- CodeBlock: Monospace code with syntax highlighting
- TabNav: Horizontal tabs with active indicator below
- SampleCard: List item showing sample name, family, threat score, similarity

---

#### 2. Frontend Structure
**Status**: Design phase
**Deliverable**: React components in `frontend/src/`

**Directory Structure**:
```
frontend/src/
├── App.jsx                          # Main app (router setup)
├── main.jsx                         # Vite entry
├── pages/
│   └── SampleDetail.jsx             # /sample/:id (main page)
├── components/
│   ├── SampleSearch.jsx             # Input + search for sample_id
│   ├── ThreatSummary.jsx            # LEVEL 1: Glance (threat overview)
│   ├── AttributionEvidence.jsx      # LEVEL 2: Triage (MAFIA attribution)
│   ├── DissectionTabs.jsx           # LEVEL 3: Investigation (tabs)
│   ├── tabs/
│   │   ├── ManifestTab.jsx
│   │   ├── PermissionsTab.jsx
│   │   ├── ComponentsTab.jsx
│   │   ├── CodeTab.jsx
│   │   ├── StringsTab.jsx
│   │   ├── DEXTab.jsx
│   │   └── NativeLibsTab.jsx
│   ├── RelatedSamples.jsx           # List of similar samples
│   ├── ThreatBadge.jsx              # Reusable threat severity badge
│   ├── ConfidenceBar.jsx            # Confidence percentage with color
│   └── LoadingSpinner.jsx           # Progress indicator
├── styles/
│   ├── App.css                      # Global styles
│   ├── components.css               # Component styles
│   ├── pages.css                    # Page styles
│   └── theme.css                    # Color vars, typography
├── hooks/
│   └── useSampleData.js             # Fetch hook for sample + dissection
├── utils/
│   └── formatters.js                # Format permissions, risk levels, etc.
└── api/
    └── client.js                    # Fetch wrapper with error handling
```

---

#### 3. Page Layouts

**SampleDetail.jsx** (Main page):
```
┌──────────────────────────────────────────────────────────┐
│ DroidForensix                              [Menu] [About] │
├──────────────────────────────────────────────────────────┤
│                                                           │
│ ┌─ LEVEL 1: GLANCE ─────────────────────────────────┐  │
│ │ <ThreatSummary sampleId={id} />                   │  │
│ │ Shows: Score, Family, Red Flags, Actions          │  │
│ └───────────────────────────────────────────────────┘  │
│                                                           │
│ ┌─ LEVEL 2: TRIAGE ─────────────────────────────────┐  │
│ │ <AttributionEvidence sampleId={id} />             │  │
│ │ Shows: Why we think this is XHelper, confidence   │  │
│ └───────────────────────────────────────────────────┘  │
│                                                           │
│ ┌─ LEVEL 3: INVESTIGATION ──────────────────────────┐  │
│ │ <DissectionTabs sampleId={id} />                  │  │
│ │ Tabs: Manifest, Permissions, Components, Code,    │  │
│ │       Strings, DEX, Native Libs                    │  │
│ └───────────────────────────────────────────────────┘  │
│                                                           │
│ ┌─ RELATED SAMPLES ─────────────────────────────────┐  │
│ │ <RelatedSamples sampleId={id} />                  │  │
│ │ Shows: Similar samples (97%, 89%, 76% similar)   │  │
│ └───────────────────────────────────────────────────┘  │
│                                                           │
└──────────────────────────────────────────────────────────┘
```

---

#### 4. Component Specifications

**ThreatSummary.jsx** (LEVEL 1: Glance)
```jsx
Props: { sampleId }
State: { threatData, loading, error }

Renders:
┌─────────────────────────────────────────┐
│ 📦 com.example.malware v1.0             │
│ ────────────────────────────────────── │
│ 🔴 CRITICAL (92/100)                    │
│ Family: XHelper (95% confidence)        │
│ Last seen: 47 similar samples           │
│ Status: Known malware                   │
│                                         │
│ 🚩 RED FLAGS:                           │
│ • Dangerous permissions: 7              │
│ • Active C2 endpoints: 3                │
│ • Obfuscation: HIGH                     │
│ • Evasion techniques: 5 detected        │
│                                         │
│ [INVESTIGATE] [BLOCK] [WATCHLIST]       │
└─────────────────────────────────────────┘

API Calls:
- GET /api/sample/{sampleId}/threat-summary
- GET /api/sample/{sampleId} (for package name, version)

Time: < 2 seconds load
```

**AttributionEvidence.jsx** (LEVEL 2: Triage)
```jsx
Props: { sampleId }
State: { attribution, loading }

Renders:
┌──────────────────────────────────────────────────┐
│ ATTRIBUTION EVIDENCE                             │
│ ──────────────────────────────────────────────── │
│ XHelper (95% confidence)                         │
│                                                  │
│ EVIDENCE:                                        │
│ ✓ Permission match (92%)                        │
│   11/15 permissions match XHelper baseline       │
│                                                  │
│ ✓ C2 overlap (98%)                              │
│   Domains match 3 known XHelper variants         │
│                                                  │
│ ✓ Obfuscation pattern (93%)                     │
│   Reflection/crypto usage consistent with       │
│   known XHelper samples                         │
│                                                  │
│ ✓ Code structure (94%)                          │
│   0.92 similarity to XHelper v2.1                │
│                                                  │
│ RELATED SAMPLES:                                 │
│ • SHA256_abc... (97% similar)                   │
│ • SHA256_def... (89% similar)                   │
│ • SHA256_ghi... (76% similar)                   │
│                                                  │
│ RECOMMENDED ACTIONS:                             │
│ 1. Block package name on app stores              │
│ 2. Sinkhole C2 domains                           │
│ 3. Alert users with XHelper signature            │
└──────────────────────────────────────────────────┘

API Calls:
- GET /api/sample/{sampleId}/attribution
- GET /api/sample/{sampleId}/dissection (for C2 context)

Time: < 1 second load
```

**DissectionTabs.jsx** (LEVEL 3: Investigation)
```jsx
Props: { sampleId }
State: { activeTab, dissectionData, loading }

Tabs:
1. Manifest → ManifestTab (permissions tree, components, intent filters)
2. Permissions → PermissionsTab (dangerous, signature, normal; risk breakdown)
3. Components → ComponentsTab (activities, services, receivers, providers, exported)
4. Code → CodeTab (enhanced with code analysis, attack flow)
5. Strings → StringsTab (searchable, linked to code references)
6. DEX → DEXTab (class/method/string counts, entropy, packing status)
7. Native Libs → NativeLibsTab (armeabi-v7a, arm64-v8a, x86, .so files)

API Calls:
- GET /api/sample/{sampleId}/dissection/{manifest|permissions|...}
  (Or single GET /api/sample/{sampleId}/dissection for all)

Time: < 1 second per tab switch (cached after first load)
```

**CodeTab.jsx** (ENHANCED - Code Analysis + Attack Flow)
```jsx
Props: { sampleId }
State: { selectedClass, classCode, codeAnalysis, attackFlow, loading }

Renders:
┌────────────────────────────────────────────────────────────────┐
│ Code Analysis                                                  │
├─────────────────┬──────────────────────────────────────────────┤
│ CLASS LIST      │ SOURCE CODE VIEWER                            │
│ (searchable)    │ ───────────────────────────────────────────  │
│                 │  1  public class BaseAActivity               │
│ BaseAActivity   │  2      extends Activity {                   │
│ ✓ onCreate()    │  3                                           │
│ ⚠ m31b()        │  4    // Signature verification check        │
│ 🔴 m29e()       │  5    if (this.f33j.equals(                 │
│ 🔴 m25c()       │  6        m30a())) {                         │
│ ⚠ m30a()        │  7      ⚠️ [LINE 7] Signature check         │
│                 │  8      m31b();  // [GOTO m31b]             │
│                 │  9    }                                     │
│                 │ 10                                           │
│                 │ 11    private void m31b() {                 │
│                 │ 12      ...version comparison...            │
│                 │ 13      m25c();  // [GOTO m25c]             │
│                 │ 14      ...                                 │
│                 │ 15      m29e();  // [GOTO m29e]             │
│                 │ 16    }                                     │
│                 │                                              │
│                 │ ────────────────────────────────────────── │
│                 │ INLINE ANALYSIS (hover line 7):            │
│                 │ ⚠️ Signature Verification                  │
│                 │    Pattern: Anti-analysis signature check   │
│                 │    Risk: MEDIUM                             │
│                 │    Context: Validates app cert before       │
│                 │    executing malicious logic                │
│                 │    Related: m30a() [method reference]       │
│                 │                                              │
│ METHOD RISK:    │ STRINGS REFERENCED IN THIS VIEW:           │
│ ───────────────│ ───────────────────────────────────────── │
│ onClick="m31b" │ Line 5: this.f33j                           │
│ 🔴 CRITICAL    │ └─ RSA cert blob (line 33-40)             │
│  Calls:        │                                              │
│  - m25c()      │ Line 13: "com.android.battery"             │
│  - m29e()      │ └─ Service spoofing [MARK DANGEROUS]        │
│  Techniques:   │                                              │
│  - Reflection  │ Line 15: "SMSApp.apk"                      │
│  - Service     │ └─ Payload filename [MARK MALICIOUS]        │
│    dropping    │    [View m29e payload drop code]           │
│  - Payload     │                                              │
│    drop        │ [Copy All] [Export Class] [Mark Suspicious] │
│                 │                                              │
│ ┌──────────────┐│ ATTACK FLOW VISUALIZATION:                 │
│ │[Visualize]   ││ ────────────────────────────────────────  │
│ │[Export]      ││ Step 1: onCreate()                         │
│ │[Raw Code]    ││   └─> Signature check (anti-analysis)      │
│ └──────────────┘│                                              │
│                 │ Step 2: m31b()                             │
│                 │   └─> Version comparison + decision        │
│                 │   └─> Calls m25c() + m29e()               │
│                 │                                              │
│                 │ Step 3: m25c()                             │
│                 │   └─> Launch hidden service                │
│                 │   └─> "com.android.battery.BridgeProvider" │
│                 │        (spoofs Android system service)      │
│                 │                                              │
│                 │ Step 4: m29e()                             │
│                 │   └─> Extract "SMSApp.apk" from resources  │
│                 │   └─> Install secondary payload            │
│                 │   └─ 🔴 MALWARE EXECUTION POINT            │
│                 │                                              │
│                 │ [Expand Steps] [View Call Graph]           │
└────────────────┴──────────────────────────────────────────────┘

Key Features:
1. Syntax highlighting (Java keywords, strings, comments)
2. Risk badges on methods (✓ safe, ⚠ suspicious, 🔴 critical)
3. Inline analysis on hover:
   - Pattern detection (reflection, service dropping, etc.)
   - Risk assessment (LOW/MEDIUM/CRITICAL)
   - Context and meaning
   - Related method links
4. String references shown inline with danger markers:
   - Service names (spoofing)
   - Payload filenames (malware)
   - C2 domains
   - File paths
5. Attack flow visualization:
   - Step-by-step execution chain
   - Entry point highlighting
   - Malware execution markers
   - Interactive (click step to jump to code)
6. Method click navigation:
   - Click method name → jump to definition
   - Click string → highlight all usages
   - Click service name → show spoofing analysis
7. Code actions:
   - Copy source
   - Export class as file
   - Mark as suspicious/malicious
   - Share code snippet

API Calls:
- GET /api/sample/{sampleId}/dissection/classes
  Returns: { classes: ["BaseAActivity", "SystemPlus", ...] }

- GET /api/sample/{sampleId}/dissection/code/{class_name}
  Returns: { class_name, source_code, file_path }

- GET /api/sample/{sampleId}/code-analysis/{class_name}
  Returns: {
    class_name: "BaseAActivity",
    methods: [
      {
        name: "m31b",
        risk_level: "CRITICAL",
        techniques: ["reflection", "service_dropping", "payload_drop", "anti_analysis"],
        calls: [
          { target: "m25c", line: 13, action: "launch hidden service" },
          { target: "m29e", line: 15, action: "drop payload" }
        ],
        suspicious_lines: [
          {
            line: 7,
            pattern: "signature_check",
            code: "if (this.f33j.equals(m30a()))",
            description: "Anti-analysis signature verification",
            risk: "MEDIUM"
          },
          {
            line: 13,
            pattern: "service_launch",
            code: "startService(this.f29e)",
            description: "Hidden service launch (spoofing Android system)",
            risk: "CRITICAL"
          },
          {
            line: 15,
            pattern: "payload_drop",
            code: "C0005b.m41b(..., \"SMSApp.apk\", this)",
            description: "Secondary malware payload drop",
            risk: "CRITICAL"
          }
        ]
      }
    ],
    string_references: {
      "com.android.battery": [
        { method: "m25c", line: 13, usage: "service_spoofing" },
        { method: "m25c", line: 14, usage: "service_spoofing" }
      ],
      "SMSApp.apk": [
        { method: "m29e", line: 156, usage: "payload_filename" }
      ],
      "this.f33j": [
        { method: "onCreate", line: 7, usage: "signature_check" }
      ]
    },
    attack_flow: [
      {
        step: 1,
        method: "onCreate",
        line: 6,
        action: "Entry point - Signature verification",
        description: "App verifies signature before executing malicious logic"
      },
      {
        step: 2,
        method: "m31b",
        line: 11,
        action: "Version check & decision logic",
        description: "Compares versions and decides whether to drop payload"
      },
      {
        step: 3,
        method: "m25c",
        line: 13,
        action: "Launch hidden service",
        description: "Starts com.android.battery.BridgeProvider (spoofs system)"
      },
      {
        step: 4,
        method: "m29e",
        line: 156,
        action: "Extract and drop SMSApp.apk",
        description: "🔴 MALWARE EXECUTION POINT - Installs SMS trojan payload"
      }
    ]
  }

- GET /api/sample/{sampleId}/string-references/{string_value}
  Returns: { string: "SMSApp.apk", usages: [...] }

Time: < 1 second per class (cached), < 500ms for string search
```

**StringsTab.jsx** (Enhanced with Code References)
```jsx
Props: { sampleId }
State: { strings, search, filter, selectedString }

Renders:
┌──────────────────────────────────────────────────────┐
│ Strings Analysis                                     │
├──────────────────────────────────────────────────────┤
│ Search: [___________________] Filter: [All ▼]        │
│                                                      │
│ CRITICAL/MALICIOUS STRINGS:                         │
│ ───────────────────────────────────────────────────  │
│ "SMSApp.apk"               [🔴 PAYLOAD FILENAME]     │
│ └─ Used in: m29e() line 156                         │
│ └─ Context: C0005b.m41b(..., "SMSApp.apk", this)   │
│ └─ Risk: CRITICAL (secondary malware payload)       │
│ └─ [View Code] [Mark] [Copy]                        │
│                                                      │
│ "com.android.battery"      [🔴 SERVICE SPOOFING]     │
│ └─ Used in: m25c() line 13-14                       │
│ └─ Context: this.f29e.setClassName(this.f27c, ...)  │
│ └─ Risk: CRITICAL (impersonates system service)     │
│ └─ [View Code] [Mark] [Copy]                        │
│                                                      │
│ "com.android.battery.BridgeProvider"  [SPOOFING]    │
│ └─ Used in: m25c() line 14                          │
│ └─ Context: Service provider class name             │
│ └─ Risk: CRITICAL (fake system service)             │
│ └─ [View Code] [Mark] [Copy]                        │
│                                                      │
│ SUSPICIOUS STRINGS:                                 │
│ ───────────────────────────────────────────────────  │
│ "发现新版本"               [⚠️  SOCIAL ENGINEERING]  │
│ └─ Meaning: "New version discovered"                │
│ └─ Used in: m25c() [display dialog]                │
│ └─ Risk: MEDIUM (fake update prompt)                │
│ └─ [View Code] [Mark] [Copy]                        │
│                                                      │
│ "1秒闪电更新"              [⚠️  SOCIAL ENGINEERING]  │
│ └─ Meaning: "Lightning update in 1 second"          │
│ └─ Used in: onCreate() [display dialog]             │
│ └─ Risk: MEDIUM (social engineering)                │
│ └─ [View Code] [Mark] [Copy]                        │
│                                                      │
│ BENIGN STRINGS:                                     │
│ ───────────────────────────────────────────────────  │
│ "android.app.Activity"                              │
│ "java.io.File"                                      │
│ [Hide benign strings] [Show all]                    │
│                                                      │
└──────────────────────────────────────────────────────┘

Features:
1. Categorized by risk (critical, suspicious, benign)
2. Each string shows:
   - Value (with language detection for non-ASCII)
   - Usage pattern (payload, service, social eng, etc.)
   - Code location (method, line number)
   - Full code context
   - Risk assessment
3. Click string → jump to code usage
4. Mark strings as malicious/suspicious for reporting
5. Copy string to clipboard
6. Filter by: All, Critical, Suspicious, Benign
7. Search: fuzzy find + regex support

API Calls:
- GET /api/sample/{sampleId}/dissection/strings
  (loads from step2_strings.json)

- GET /api/sample/{sampleId}/string-references/{string_value}
  Returns: { string, usages: [...] }

Time: < 1 second load, < 500ms search
```

**RelatedSamples.jsx**
```jsx
Props: { sampleId }
Renders list of similar samples:
┌─────────────────────────────────┐
│ SHA256_abc... (97% similar)     │
│ Family: XHelper                 │
│ Threat: CRITICAL                │
│ [View]                          │
├─────────────────────────────────┤
│ SHA256_def... (89% similar)     │
│ Family: XHelper                 │
│ Threat: CRITICAL                │
│ [View]                          │
└─────────────────────────────────┘

API Calls:
- GET /api/sample/{sampleId}/attribution (related_samples field)
```

---

#### 5. Frontend Implementation Checklist

**Week 1: Foundation**
- [ ] Set up React router (`react-router-dom`)
- [ ] Create theme.css (color vars, typography)
- [ ] Create App.jsx with router (App → SampleDetail)
- [ ] Create SampleSearch component (input + fetch sample)
- [ ] Create useSampleData hook (fetch from /api/sample/{id})

**Week 2: Level 1 (Glance)**
- [ ] Create ThreatSummary component
- [ ] Create ThreatBadge component
- [ ] Wire to /api/sample/{id}/threat-summary
- [ ] Style with color palette
- [ ] Test with 3 real samples

**Week 3: Level 2 (Triage)**
- [ ] Create AttributionEvidence component
- [ ] Create ConfidenceBar component
- [ ] Wire to /api/sample/{id}/attribution
- [ ] Show supporting signals + related samples
- [ ] Add action buttons (block, watchlist)

**Week 4: Level 3 (Investigation) – Tabs Foundation**
- [ ] Create DissectionTabs shell
- [ ] Implement ManifestTab
- [ ] Implement PermissionsTab (with risk colors)
- [ ] Implement ComponentsTab
- [ ] Create PermissionCard, ComponentCard reusable components

**Week 5: Level 3 (Investigation) – Code Analysis (ENHANCED)**
- [ ] Implement CodeTab with syntax highlighting (Prism.js)
- [ ] Add method list with risk badges (✓ safe, ⚠ suspicious, 🔴 critical)
- [ ] Implement inline analysis on hover (pattern, risk, context)
- [ ] Add string reference highlighting inline
- [ ] Implement attack flow visualization (step-by-step chain)
- [ ] Add method click navigation (click method → jump to code)
- [ ] Implement StringsTab with categorization (critical, suspicious, benign)
- [ ] Add string → code reference links
- [ ] Add string risk classification (payload, service, social_eng, etc.)
- [ ] Implement string usage display (method, line, context)
- [ ] Add copy-to-clipboard for code/strings
- [ ] Add mark/export functionality

**Week 6: Level 3 (Investigation) – DEX & Native**
- [ ] Implement DEXTab (stats table, entropy chart using recharts)
- [ ] Implement NativeLibsTab (table of .so files)
- [ ] Add RelatedSamples component below tabs

**Week 7: Polish & Testing**
- [ ] Responsive design (mobile friendly)
- [ ] Error handling (missing data, 404s)
- [ ] Loading states (spinners, progress bars)
- [ ] Accessibility (keyboard nav, ARIA labels)
- [ ] Browser test (Chrome, Firefox, Safari)

**Week 8: Integration & Demo**
- [ ] End-to-end test with 5 real samples
- [ ] Screenshot/record demo video
- [ ] Create user guide (how to read the dashboard)
- [ ] Final styling polish

---

#### 6. Frontend Testing
**Deliverable**: Manual testing checklist (automated tests optional for Phase 0)

```
[ ] SampleSearch: Can input sample_id and fetch data
[ ] ThreatSummary: Displays threat score, family, red flags
[ ] AttributionEvidence: Shows confidence breakdown + supporting signals
[ ] ManifestTab: Shows permissions, activities, services
[ ] PermissionsTab: Dangerous permissions highlighted, risk breakdown shown
[ ] ComponentsTab: Activities, services, receivers, providers listed
[ ] CodeTab: Classes searchable, risk badges visible
[ ] CodeTab: Inline analysis appears on hover (pattern, risk, context)
[ ] CodeTab: Attack flow visualization shows correct step sequence
[ ] CodeTab: Method click navigation works (jumps to code)
[ ] CodeTab: String references highlighted and clickable
[ ] StringsTab: Strings categorized (critical/suspicious/benign)
[ ] StringsTab: String → code references work (click to view usage)
[ ] StringsTab: Risk classification visible (payload/service/social_eng)
[ ] StringsTab: String search filters correctly
[ ] DEXTab: Stats displayed, entropy shown
[ ] NativeLibsTab: .so files listed by architecture
[ ] RelatedSamples: Similar samples clickable, navigate to new sample
[ ] Error states: 404, 500 errors handled gracefully
[ ] Loading states: Spinners show, data loads progressively
[ ] Mobile: Dashboard readable on 1024px width (tablet)
```

---

### Integration Checklist

**Backend + Frontend Integration**:
```
[ ] Backend endpoints deployed and tested with curl
[ ] Frontend can reach backend (/api/sample/*, /ws/*)
[ ] CORS configured correctly (Frontend on :5173, Backend on :8000)
[ ] Vite proxy configured (vite.config.js)
[ ] All dissection endpoints returning real data
[ ] Attribution endpoint showing MAFIA confidence breakdown
[ ] Error responses properly formatted (JSON)
```

---

### Dissertation Deliverables (Phase 0 Output)

1. **Codebase**:
   - `backend/dissection.py` (APKDissector class)
   - `backend/main.py` (new endpoints)
   - `frontend/src/` (complete React app)
   - `tests/test_dissection.py`, `tests/test_attribution.py`

2. **Documentation**:
   - README.md (updated with dashboard setup)
   - Design system spec (colors, typography, components)
   - User guide (how to use the dashboard)

3. **Demo**:
   - Video walkthrough (upload APK → see all 3 levels)
   - Screenshots of each level
   - Example attribution explanation (why 95% confident?)

4. **Metrics**:
   - Test coverage > 80%
   - All endpoints respond < 1 second (excluding initial Ollama call)
   - Dashboard loads < 2 seconds on first view

---

# PHASE 1: OPERATIONAL FEATURES (Jan–Jun 2027)
## Timeline: 6 weeks (parallel with job search prep)

### Feature #1: Side-by-Side Comparison
**Goal**: Compare malicious sample vs. benign baseline
**Implementation**:
- New endpoint: `GET /api/sample/{sample_id}/compare/{baseline_sample_id}`
- Returns diff of: permissions, strings, native libs, C2s, obfuscation
- UI: Split-screen view, red/green highlighting differences
- Time: 2 weeks

### Feature #2: Export (PDF, JSON, SIEM)
**Goal**: Generate report for team/SIEM
**Implementation**:
- New endpoints: `GET /api/sample/{sample_id}/export/{format}`
  - format: pdf | json | siem
- Use reportlab (PDF generation)
- JSON: Structured threat data
- SIEM: CEF format or syslog event
- Time: 1.5 weeks

### Feature #3: Collaboration (Notes, Tags, Sharing)
**Goal**: Team annotation and sharing
**Implementation**:
- New database table: `sample_annotations` (sample_id, user, note, tags, timestamp)
- Endpoints: POST /api/sample/{id}/notes, GET /api/sample/{id}/notes
- UI: Notes sidebar + tag editing
- Share: Generate link to read-only sample view
- Time: 2.5 weeks

---

# PHASE 2: INTELLIGENCE & VISUALIZATION (Jul–Dec 2027)
## Timeline: 6 weeks

### Feature #5: Threat Actor Profiles
**Goal**: Show who wrote this malware, targeting, infrastructure
**Implementation**:
- New data: threat actor name, description, targeting, known families, infrastructure registrars
- Endpoint: `GET /api/threat-actor/{actor_name}`
- UI: Actor card on family view, links to infrastructure
- Time: 2 weeks

### Feature #8: Family Evolution Timeline
**Goal**: Show how malware family changes over time
**Implementation**:
- New endpoint: `GET /api/family/{family_name}/evolution`
- Returns: [{ version, date, permissions, c2_count, obfuscation_level, samples }]
- UI: Timeline with cards showing family progression
- Time: 2 weeks

### Feature #11: 3D Threat Landscape
**Goal**: Visualize all 50K samples as 3D scatter plot
**Implementation**:
- New endpoint: `GET /api/clusters/3d`
- Returns: { nodes: [{ id, x, y, z, family, threat_score }], edges: [...] }
- Use Three.js + React Three Fiber
- Axes: Encoding complexity, C2 sophistication, Obfuscation score
- Color: Family cluster, Threat level
- Interaction: Click to navigate to sample, hover for details
- Time: 3 weeks

### Feature #12: Evasion Detection Showcase
**Goal**: Show smali fallback + obfuscation anchoring in action
**Implementation**:
- New endpoint: `GET /api/sample/{sample_id}/evasion-analysis`
- Returns: { jadx_success: bool, smali_fallback_used: bool, obfuscation_score, techniques: [...] }
- UI: "How we caught this" section showing decompilation resilience
- Time: 1 week

---

# PHASE 3: ADVANCED BEHAVIORAL (Future)
## Timeline: 8+ weeks

### Feature #6: Visual Attack Chain
**Requires**: Dynamic analysis data (Frida, Cuckoo, etc.)
- Show step-by-step animation of malware execution
- Map code → permissions → network calls → data exfiltration

### Feature #7: Network Traffic Prediction
**Requires**: C2 behavior models
- Predict what network calls this malware will make
- Show likely C2 domains, protocols, exfiltration size

### Feature #9: Risk Propagation
**Requires**: App dependency graph
- If user has App A + App B, combined risk analysis
- Show which apps amplify each other's threat

---

# TECH STACK (All Phases)

**Backend**:
- Python 3.10+
- FastAPI (REST API)
- Androguard 4.1.4 (APK parsing)
- Pydantic (validation)
- pytest (testing)
- reportlab (PDF generation, Phase 1)

**Frontend**:
- React 18+
- React Router 6 (routing)
- Vite (build tool)
- CSS3 (styling, no framework)
- Three.js + React Three Fiber (3D, Phase 2)
- Recharts (charts, Phase 1)
- Highlight.js or Prism (syntax highlighting, Phase 0)

**Database** (Phase 1+):
- SQLite (notes, annotations)
- Or PostgreSQL if scaling

---

# SUCCESS METRICS

**Phase 0 (Dissertation)**:
- ✅ Dashboard loads < 2 seconds
- ✅ All 3 levels working (glance, triage, investigation)
- ✅ MAFIA attribution explained (95% confidence visible)
- ✅ 5+ real samples tested end-to-end
- ✅ Tests pass (> 80% coverage)

**Phase 1 (Operational)**:
- ✅ Analysts prefer comparison over manual inspection
- ✅ PDF reports match dashboard data
- ✅ Team can share findings via links

**Phase 2 (Intelligence)**:
- ✅ 3D landscape is explorable, not slow
- ✅ Family evolution shows actual patterns
- ✅ Threat actor profiles are accurate (OSINT-backed)

---

# RISKS & MITIGATIONS

| Risk | Impact | Mitigation |
|------|--------|-----------|
| Androguard API differences | Backend fails on new APK format | Fallback to zip-only parsing; test with 20 APKs |
| Large 3D visualization (50K samples) | Frontend hangs | Lazy-load clusters; use WebGL; level-of-detail |
| MAFIA attribution data missing | Can't explain 95% confidence | Document exact algorithm in Step 7 output |
| Analyst workflow assumptions wrong | Built wrong tool | User test with 1 SOC analyst early (Phase 0) |
| Timeline slippage | Dissertation delayed | Weekly check-ins; descope Phase 1–3 if needed |

---

# FINAL NOTES

**This roadmap is intentionally phased** because:
1. **Phase 0** is dissertation-ready by December (core + MAFIA showcase)
2. **Phase 1** makes it operational (export, collaboration, comparison)
3. **Phase 2** makes it impressive (3D landscape, evolution, threat actors)
4. **Phase 3** is optional (behavioral features require more infrastructure)

**Each phase is a complete product**:
- Phase 0: Research tool + portfolio piece
- Phase 0+1: SOC operational tool
- Phase 0+1+2: Industry-grade threat analysis platform

**Execution**:
- Phase 0: Kimi (backend) + You (frontend design review) + Claude (component scaffolds)
- Phase 1+: Same team, but with real user feedback
- Phase 2+: Consider open-source or publication

---

**Next Step**: Lock Phase 0 frontend design with me, hand to Kimi for implementation.

Ready?
