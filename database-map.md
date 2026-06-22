# DroidForensix Database & Storage Map

This document describes the schema-less, file-system-based database architecture of DroidForensix.

---

## 1. Storage Architecture Overview

DroidForensix uses the local filesystem under the directory configured in `settings.WORK_DIR` (defaulting to `D:\DroidForensix\analysis\work`) as its database. No external database engine (such as MySQL, PostgreSQL, or MongoDB) is needed.

Each analyzed APK sample gets its own directory named after its SHA-256 hash. Inside this directory, the results of the 9-step analysis pipeline are written as individual step JSON files and one final consolidated report.

---

## 2. Workspace Directories & Files Schema

For a given sample with hash `<sha256>`, the following data models are serialized:

### A. `step1_extraction.json`
- **Source:** [step1_apk_extraction.py](file:///d:/DroidForensix/analysis/step1_apk_extraction.py)
- **Attributes:**
  - `sample_id` (string): The SHA-256 hash of the APK.
  - `sample_name` (string): Filename of the uploaded APK.
  - `file_size_bytes` (integer)
  - `sha256` (string)
  - `md5` (string)
  - `package_name` (string)
  - `manifest_info` (object): Version code, target SDK version, uses-permissions.
  - `apktool_success` (boolean)
  - `jadx_success` (boolean)
  - `decompiled_classes` (integer): Total Java source files count.
  - `native_libs_found` (array of strings): Directory paths of extracted `.so` files.
  - `native_strings` (array of objects): Extracted raw strings with their origin library names.

### B. `step2_strings.json`
- **Source:** [step2_string_enumeration.py](file:///d:/DroidForensix/analysis/step2_string_enumeration.py)
- **Attributes:**
  - `sample_id` (string)
  - `total_strings` (integer)
  - `categories` (object): Maps categories (`string_literals`, `byte_arrays`, `numeric_constants`, `resource_strings`, `native_strings`) to arrays of extracted items.
  - **Item Schema:**
    - `category` (string)
    - `value` (string / number)
    - `entropy` (float): Shannon entropy of the value string.
    - `source` (string): Relative file source location (e.g. `MainActivity.java:42`).

### C. `dissection.json`
- **Source:** [dissection.py](file:///d:/DroidForensix/backend/dissection.py)
- **Purpose:** Pre-calculated APK layout detail structures returned directly to the frontend smart dissection tabs.
- **Attributes:**
  - `metadata` (object): Size, targets, SDK levels, multidex indicator.
  - `manifest` (object): App package declarations, permissions, features.
  - `permissions` (array of objects): Declared uses-permissions mapped to classifications (`dangerous`, `signature`, `normal`, `unknown`).
  - `components` (object): Arrays of `activities`, `services`, `receivers`, `providers` along with their export permissions and intent filters.
  - `native_libs` (array of objects): List of `.so` binary paths, sizes, target architectures, and CRC32 checksums.
  - `dex_stats` (object): Summarizes total DEX count, total classes, methods, strings, and overall bytes entropy.

### D. `family.json`
- **Source:** [family_id.py](file:///d:/DroidForensix/backend/family_id.py)
- **Purpose:** Contains consensus family classification outputs.
- **Attributes:**
  - `family` (string): Attributed malware family name (e.g. `FakeInstaller`, `Opfake`).
  - `confidence` (float): Match certainty (0.0 to 1.0).
  - `method` (string): Priority match channel (`ground_truth`, `yara`, `signature`, `llm`).
  - `reasoning` (string): Summary explanation details.
  - `candidates` (array of objects): List of all classified source candidate hits.

---

## 3. Labeled Reference Datasets

Authoritative ground-truth family maps reside in the workspace root:
1. `ground_truth_test_set.json`
2. `ground_truth_drebin.json`
3. `ground_truth_fdroid.json`

### Dataset Records Format
```json
[
  {
    "sha256": "8a946b5a34e0078...",
    "family": "FakeInstaller",
    "label": "malicious"
  }
]
```
During Step 9, [family_id.py](file:///d:/DroidForensix/backend/family_id.py) compiles these files into an in-memory dictionary cache to cross-reference the analyzed sample's hash before proceeding to heuristic signature scans or LLM queries.
