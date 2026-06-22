# DroidForensix Dependency Graph

This document catalogs imports, module linkages, and critical files within the DroidForensix system.

---

## 1. Backend Import Hierarchy

Below is the file import dependency flow on the backend. Files at the top depend on modules listed below them:

```
[backend/main.py] (REST & WebSockets Driver)
   ├── [backend/config.py] (Central Environment Settings)
   ├── [backend/events.py] (WebSocket event validator definitions)
   ├── [backend/validators.py] (Validates event payload formats)
   ├── [backend/transformers.py] (Translates reports to graph/clusters views)
   ├── [backend/dissection.py] (Extracts manifest details / reads decompiled source)
   ├── [backend/family_id.py] (Consensus family classification engine)
   │      ├── [backend/config.py]
   │      └── [analysis/step7_llm_assessment.py] (Validates JSON formatting templates)
   ├── [backend/threat_intel.py] (Exports CSV blocks / STIX / YARA rule schemas)
   │      └── [backend/config.py]
   ├── [backend/obfuscation_view.py] (Reflection and DCL view formatter)
   │      ├── [backend/config.py]
   │      └── [analysis/step4_decoding.py] (String decoding helpers)
   └── [analysis/pipeline.py] (Orchestrator driving the 9 steps)
          ├── [backend/config.py]
          ├── [backend/family_id.py]
          ├── [backend/dissection.py]
          └── [analysis/step1_apk_extraction.py] to [analysis/step9_post_process.py]
```

---

## 2. Critical System Files

These files are core components of the system and should not be modified without thorough testing:

1. **[backend/config.py](file:///d:/DroidForensix/backend/config.py)**
   - **Role:** Centralized configuration provider. Holds absolute directories and portable toolkit binary path definitions.
   - **Impact:** Any misconfiguration in this file will break file upload handlers, decompiler binaries lookup, and Ollama connections.

2. **[analysis/pipeline.py](file:///d:/DroidForensix/analysis/pipeline.py)**
   - **Role:** Orchestrates the 9 analysis steps and reports progress events to the websocket emitter.
   - **Impact:** Controls the execution sequence of the static-analysis engine. Changes here can break the real-time progress bar rendering.

3. **[backend/dissection.py](file:///d:/DroidForensix/backend/dissection.py)**
   - **Role:** Provides structural APK dissection features. Uses `androguard` to read components without decompiling the entire DEX.
   - **Impact:** Powers the code dissection page tabs and class method list browser.

4. **[analysis/step9_post_process.py](file:///d:/DroidForensix/analysis/step9_post_process.py)**
   - **Role:** Implements sanity overrides for known false-positives (such as benign calculators) and false-negatives (such as Metasploit stagers).
   - **Impact:** Directly affects final threat classification risk scores and severity verdicts.

---

## 3. Frontend Component Dependencies

Below is the state-passing hierarchy of the React components:

```
[App.jsx] (State reducer handles WebSocket messages)
   ├── [UploadPanel.jsx] (Upload handler, local sample history list)
   ├── [AnalysisView.jsx] (Orchestrates result tabs)
   │      ├── [ObfuscationView.jsx] (Parses reflection metrics & deobfuscator)
   │      ├── [ThreatIntelView.jsx] (DNS verification stats & geo-map pins)
   │      └── [ManifestView.jsx] (Android manifest XML summary list)
   └── [DissectionPage.jsx] (Wrapper for smart code viewing)
          ├── [SmartDissection.jsx] (Suspicious keywords lookup class browser)
          └── [ClassSourceViewer.jsx] (Syntax highlighted Java code viewer)
```
