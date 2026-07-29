# Android Sample Sources for DroidForensix

## Tier 1: Premium Sources (API Key Required)

### 1. AndroZoo ⭐ BEST
- **URL:** https://androzoo.uni.lu
- **API Key:** Yes — free for academic/research use
- **Size:** 20+ million APKs (both malware and benign)
- **How to request:**
  1. Go to https://androzoo.uni.lu/access
  2. Fill the form with your university email
  3. Mention "M.Sc. thesis on Android malware static analysis"
  4. Usually approved within 24-48 hours
- **Why it's best:** Massive collection, labeled with VirusTotal detections, sha256 indexed, simple REST API
- **Limit:** 10 downloads per minute

### 2. Koodous
- **URL:** https://koodous.com
- **API Key:** Yes — free for researchers
- **Size:** Curated Android malware, community-driven
- **How to request:**
  1. Create account at https://koodous.com/login
  2. Go to profile → API Key
  3. Email koodous team for higher rate limits if needed
- **Why good:** Community-curated, family labels, YARA rules available
- **Limit:** Rate-limited without approval

### 3. VirusShare
- **URL:** https://virusshare.com
- **API Key:** Requires account registration
- **Size:** Large malware corpus (not Android-specific)
- **How to request:**
  1. Register at https://virusshare.com/register
  2. Request access to Android subset
  3. Usually approved within a few days
- **Note:** Hashes only via API; downloads via torrent

---

## Tier 2: Free / No API Key Required

### 4. Contagio Mobile Dump ⭐ BEST FREE
- **URL:** https://contagiomobile.blogspot.com
- **API Key:** No
- **Size:** Hundreds of mobile malware samples
- **How to download:**
  1. Go to https://contagiomobile.blogspot.com
  2. Navigate to "Mobile Malware Dump" or specific family posts
  3. Download ZIP files (password: `infected`)
  4. Extract APKs manually
- **Why good:** High-quality, family-labeled, direct downloads
- **Limit:** Manual download, not programmatic

### 5. theZoo
- **URL:** https://github.com/ytisf/theZoo
- **API Key:** No
- **Size:** ~200 malware samples (mixed platforms)
- **How to use:**
  ```bash
  git clone https://github.com/ytisf/theZoo.git
  cd theZoo
  python3 theZoo.py
  # Search for android, download
  ```
- **Limit:** Mostly Windows; Android subset is small and outdated

### 6. MalwareBazaar (abuse.ch)
- **URL:** https://bazaar.abuse.ch
- **API Key:** No
- **Size:** Sparse Android coverage (~50-100 APKs)
- **How to use:**
  ```bash
  # Query via API (already scripted in scripts/download_samples.py)
  curl -X POST https://mb-api.abuse.ch/api/v1/ \
    -d 'query=get_taginfo' -d 'tag=apk' -d 'limit=100'
  ```
- **Limit:** Mostly Windows malware; Android samples are rare

---

## Tier 3: Curated GitHub Repos (No API Key)

### 7. AndroidMalware_2019
- **URL:** https://github.com/sk3ptre/AndroidMalware_2019
- **Size:** ~50 APKs from 2019, well-known families
- **How to use:**
  ```bash
  git clone https://github.com/sk3ptre/AndroidMalware_2019.git
  # APKs are in the repo directly
  ```

### 8. Android-Malware-Samples
- **URL:** https://github.com/ashishb/android-malware
- **Size:** ~100 APKs, organized by family
- **How to use:**
  ```bash
  git clone https://github.com/ashishb/android-malware.git
  # Find APKs in subdirectories
  ```

### 9. Drebin Dataset (Academic)
- **URL:** https://www.sec.cs.tu-bs.de/~danarp/drebin/
- **Size:** 5,560 malware samples from 2010-2012
- **How to request:**
  1. Email authors with research purpose
  2. Usually approved for academic use
- **Limit:** Old samples (2010-2012), but historically significant

---

## Tier 4: Benign / Legitimate APKs (Baseline)

### 10. F-Droid
- **URL:** https://f-droid.org
- **API Key:** No
- **Size:** 4,000+ open-source Android apps
- **How to use:** Already scripted in `scripts/download_samples.py`
- **Why needed:** Baseline entropy and string comparison analysis

### 11. APKMirror
- **URL:** https://www.apkmirror.com
- **API Key:** No
- **Size:** Popular commercial apps (WhatsApp, Instagram, etc.)
- **Limit:** No programmatic API; manual download or scraping

---

## Tier 5: Academic / Research Datasets (Registration Usually Required)

### 12. CICAndMal2017 (Canadian Institute for Cybersecurity)
- **URL:** https://www.unb.ca/cic/datasets/android-adware.html
- **API Key:** No — download after registration
- **Size:** ~10,000 Android malware samples (adware, ransomware, scareware, SMS malware)
- **How to request:**
  1. Go to https://www.unb.ca/cic/datasets/android-adware.html
  2. Fill the dataset request form with research purpose
  3. Download links are emailed after approval
- **Why good:** Large, labeled by malware category, includes network traffic captures
- **Limit:** Heavy download (tens of GB); must cite the dataset paper

### 13. AMD (Android Malware Dataset)
- **URL:** http://amd.arguslab.io
- **API Key:** No — direct download
- **Size:** ~24,000 malware samples from 2010–2016
- **How to use:**
  1. Visit http://amd.arguslab.io
  2. Download the dataset (torrent or HTTP)
  3. Samples are organized by family
- **Why good:** Large, family-labeled, widely used in research
- **Limit:** Older samples; dataset is ~120 GB unpacked

### 14. Drebin-215 / CCCS Android Malware Dataset
- **URL:** https://github.com/JJuhnDA/CCCSDataset
- **API Key:** No
- **Size:** 215 Android malware samples with family labels
- **How to use:**
  ```bash
  git clone https://github.com/JJuhnDA/CCCSDataset.git
  # APKs are in subdirectories by family
  ```
- **Why good:** Curated, malware families from real incidents
- **Limit:** Small but high quality

### 15. CIC-MalDroid-2020
- **URL:** https://www.unb.ca/cic/datasets/maldroid-2020.html
- **API Key:** No — registration required
- **Size:** ~12,000 malware + 2,000 benign APKs
- **How to request:**
  1. Go to https://www.unb.ca/cic/datasets/maldroid-2020.html
  2. Complete the dataset request form
- **Why good:** Balanced malware/benign set, family labels, modern samples
- **Limit:** Large download; registration can take a few days

### 16. MalShare
- **URL:** https://malshare.com
- **API Key:** Free API key required
- **Size:** Large repository of malware samples (not Android-specific)
- **How to request:**
  1. Register at https://malshare.com/register.php
  2. Generate an API key from your profile
  3. Query with `type:apk` or Android-specific hashes
- **Why good:** Good for targeted hash lookups
- **Limit:** Mostly Windows; Android samples need active hunting

### 17. VirusTotal Intelligence / Hunting
- **URL:** https://www.virustotal.com
- **API Key:** Premium (academic discounts available)
- **Size:** Massive
- **How to request:**
  1. Academic/researchers can apply for premium access via VirusTotal
  2. Use VT Intelligence queries like `type:apk positives:10+`
- **Why good:** Best for very recent, labeled malware
- **Limit:** Premium; strict rate limits

---

## Tier 6: Additional GitHub Repositories

### 18. AndroidMalware (dkongming)
- **URL:** https://github.com/dkongming/AndroidMalware
- **Size:** ~80 APKs, mixed families
- **How to use:**
  ```bash
  git clone https://github.com/dkongming/AndroidMalware.git
  ```

### 19. malware-samples (maldroid)
- **URL:** https://github.com/maldroid/malware-samples
- **Size:** ~40 APKs, CTF/research oriented
- **How to use:**
  ```bash
  git clone https://github.com/maldroid/malware-samples.git
  ```

### 20. Android-Malware-Samples (CyberNormie)
- **URL:** https://github.com/CyberNormie/MalwareSamples
- **Size:** Mixed; has an Android/ folder
- **How to use:**
  ```bash
  git clone https://github.com/CyberNormie/MalwareSamples.git
  ```

---

## Updated Notes

### MalwareBazaar API Access
As of 2026, `mb-api.abuse.ch` may return `401 Unauthorized` for unauthenticated requests.
Options:
1. Request a free API key at https://bazaar.abuse.ch/account/
2. Set `MALWAREBAZAAR_API_KEY` in `.env` and update `scripts/download_samples.py` to send it
3. Use the web UI for manual download if API access is unavailable

### AndroZoo
The AndroZoo `latest.csv.gz` metadata file is large (~2 GB compressed). Consider keeping it
and reusing it across runs to avoid re-downloading.

---

## Recommended Acquisition Strategy

### Immediate (Today)
1. **GitHub repos** — Run `scripts/fetch_github_malware.py` (~150-250 APKs)
2. **Contagio Mobile** — Download 20-30 APKs manually
3. **MalwareBazaar** — Request API key, then run `scripts/download_samples.py`
4. **F-Droid** — Run `scripts/download_samples.py --legit-only`
5. **CCCSDataset** — Clone `JJuhnDA/CCCSDataset` (~215 APKs)

### Short-term (1-3 days)
6. **AndroZoo** — Submit API key request NOW (best long-term source)
7. **Koodous** — Create account, get API key
8. **CICAndMal2017 / CIC-MalDroid-2020** — Submit dataset request forms
9. **AMD** — Download the AMD torrent/HTTP archive

### Backup
10. **VirusShare** — Register while waiting for AndroZoo
11. **MalShare** — Register for free API key

---

## Sample Target Breakdown

| Source | Count | Type | Status |
|--------|-------|------|--------|
| GitHub `ashishb/android-malware` | 307 | Malware | ✅ Fetched |
| GitHub `sk3ptre/AndroidMalware_2019` | 137 | Malware | ✅ Fetched (passworded ZIPs) |
| CICAndMal2017 (Adware/Scareware/SMSmalware) | 325 | Malware | ✅ Fetched |
| CICAndMal2017 (Ransomware/Benign) | — | Mixed | 🔲 Not found in `CICAndMal2017/` |
| CCCSDataset | ~215 | Malware | 🔲 Manual clone needed |
| Contagio Mobile | ~30 | Malware | 🔲 Manual download |
| MalwareBazaar | ~5-10 | Malware | ⚠️ API key now required |
| F-Droid | 8 | Legitimate | ✅ Fetched |
| AndroZoo-Drebin | 50 | Malware | ✅ Fetched |
| **Total** | **818** | Mixed | |
| AndroZoo / Koodous / CIC remainder | ~100+ | Both | 🔲 API/registration required |

---

## File Organization

```
samples/
├── malware/
│   ├── github/          # From cloned repos (ashishb, sk3ptre, dkongming, etc.)
│   ├── cccs/            # From CCCSDataset
│   ├── contagio/        # From Contagio Mobile
│   ├── bazaar/          # From MalwareBazaar
│   ├── koodous/         # From Koodous
│   └── androzoo/        # From AndroZoo (when approved)
└── legitimate/
    └── fdroid/          # From F-Droid
```

All samples are tracked in `sample_metadata.csv` with source, family, and SHA-256.

## Quick Fetch Commands

```bash
# Activate environment
source venv/bin/activate

# Fetch from GitHub repos (no API key)
python scripts/fetch_github_malware.py

# Fetch from CCCSDataset (no API key)
git clone https://github.com/JJuhnDA/CCCSDataset.git /tmp/cccs
python scripts/fetch_github_malware.py --cccs /tmp/cccs

# Fetch legitimate baseline
python scripts/download_samples.py --legit-only

# Fetch from AndroZoo (requires ANDROZOO_API_KEY)
source .env
python scripts/download_drebin_androzoo.py data/drebin_sha256_family.csv 100

# Fetch from MalwareBazaar (API key may be required)
python scripts/download_samples.py --malware-only
```

---

# Code File Inventory & Pseudocode

## Overview

DroidForensix has **246 code files** organized into an 18-step static analysis pipeline (Python), a FastAPI backend, a React frontend, evaluation/validation scripts, and comprehensive tests.

---

## 1. Analysis Pipeline (`analysis/`)

Core 18-step pipeline that unpacks, analyzes, and scores Android APKs.

### `pipeline.py` — Pipeline Orchestrator
```
FUNCTION run_pipeline(apk_path, work_dir, websocket):
    FOR each of 18 steps:
        validate_inputs(step, data)
        emit_websocket_progress(step)
        result = run_step_with_timeout(step, data, timeout=600s)
        handle_errors(result)
    RETURN aggregated_report
```

### `step1_apk_extraction.py` — APK Extraction
```
FUNCTION extract_apk(apk_path, work_dir):
    sha256 = compute_sha256(apk_path)
    md5 = compute_md5(apk_path)
    apktool_decode(apk_path → smali/resources)
    jadx_decompile(apk_path → java source)
    extract_native_lib_strings(apk)
    RETURN {sha256, md5, smali_dir, java_dir, native_strings}
```

### `step2_string_enumeration.py` — String Enumeration
```
FUNCTION enumerate_strings(decompile_dir):
    FOR each .java source:
        extract_string_literals()      // "..." in code
        extract_byte_arrays()          // byte[]{...}
        extract_numeric_constants()    // 0x..., large ints
    
    FOR each .smali source:
        extract_smali_strings()        // const-string
    
    FOR each resource file:
        extract_resource_strings()     // strings.xml, etc.
    
    FOR each native lib:
        extract_native_strings()
    
    FOR each extracted string:
        entropy = shannon_entropy(string)
        classify(string, entropy)
    
    RETURN {all_strings, high_entropy_strings, byte_arrays, numeric_constants}
```

### `step3_encoding_detection.py` — Encoding Detection
```
FUNCTION detect_encoding(strings):
    FOR each string:
        confidence = 0
        
        IF matches base64 alphabet:
            confidence += try_base64_decode(string)
        IF matches hex alphabet:
            confidence += try_hex_decode(string)
        IF matches XOR patterns:
            confidence += try_xor_decode(string)
        
        IF source is "const-string" or "smali":
            suspicious = TRUE
        IF entropy > 6.0:
            suspicious = TRUE
        
        classify_encoding(string, confidence, suspicious)
    
    RETURN {detected_encodings: [{string, encoding, confidence, suspicious}]}
```

### `step4_decoding.py` — Payload Decoding
```
FUNCTION decode_payloads(detected_encodings):
    FOR each detected encoding:
        decoded = multi_layer_decode(string, max_depth=5)
        
        artifacts = extract_artifacts(decoded):
            urls     = find_urls(decoded)
            ips      = find_ips(decoded)
            domains  = find_domains(decoded)
            emails   = find_emails(decoded)
            phones   = find_phone_numbers(decoded)
        
        magic_bytes = detect_binary_payload(decoded)
    
    RETURN {decoded_payloads, artifacts, binary_payloads}
```

### `step5_c2_extraction.py` — C2 Extraction (1324 lines)
```
FUNCTION extract_c2_infrastructure(urls, ips, domains):
    FOR each endpoint:
        IF is_benign_url(endpoint):  SKIP (ad networks, CDNs, known-good)
        IF is_ad_network(endpoint):  SKIP
        
        protocol = extract_protocol(endpoint)
        domain   = extract_domain(endpoint)
        port     = extract_port(endpoint)
        path     = extract_path(endpoint)
        
        ip_class = classify_ip(domain):  // hosted, vpn, residential, etc.
        
        confidence = calculate_c2_confidence(protocol, ip_class, path_patterns)
        
        circl_enrich(domain)  // passive DNS/SSL via CIRCL API
    
    RETURN [C2_Record {protocol, domain, port, path, ip_class, confidence}]
```

### `step6_correlation.py` — Threat Chain Correlation
```
FUNCTION build_threat_chains(encoded_strings, decoded_payloads, c2_records):
    FOR each decoded_payload:
        chain = {
            source: encoded_string,
            decoding_steps: [base64 → hex → ...],
            decoded: payload_text,
            linked_c2s: find_c2s_in_payload(payload_text, c2_records),
            composite_confidence: avg(c2_confidences),
            severity: calculate_severity(chain)
        }
    
    RETURN [ThreatChain]
```

### `step7_llm_assessment.py` — LLM Assessment (1422 lines)
```
FUNCTION assess_with_llm(threat_chains, context):
    // Primary: NVIDIA NIM API
    // Fallback: Ollama (mistral:7b)
    // Last resort: rule-based fallback
    
    prompt = build_prompt(threat_chains, context)
    
    TRY:
        response = call_nvidia_nim(prompt)
    CATCH:
        TRY:
            response = call_ollama(prompt)
        CATCH:
            response = fallback_assessment(threat_chains)
    
    validated = validate_json_response(response)
    sanity_checked = sanity_check(validated)
    
    RETURN {severity, explanation, confidence}
```

### `step8_obfuscation_analysis.py` — Obfuscation Analysis (784 lines)
```
FUNCTION analyze_obfuscation(apk_path, dex_data):
    // Androguard DEX analysis
    classes    = androguard_analyze_dex(apk_path)
    reflection = find_reflection_usage(classes)     // forName, invoke
    dcl        = find_dynamic_code_loading(classes)  // DexClassLoader
    native     = find_native_loading(classes)        // System.loadLibrary
    crypto     = find_crypto_apis(classes)           // Cipher, SecretKey
    
    // DEX entropy & packing
    dex_entropy = calculate_dex_entropy(apk_path)
    packing     = detect_dex_packing(apk_path)
    
    obf_score = calculate_obfuscation_score(reflection, dcl, native, crypto, packing)
    
    RETURN {reflection_count, dcl_count, native_count, crypto_count, dex_entropy, obf_score}
```

### `step9_post_process.py` — Post-Processing (485 lines)
```
FUNCTION post_process_result(result):
    // Correct false positives
    IF result.severity == "medium" AND result.c2_count == 0:
        correct_metasploit_stager(result)  // Metasploit stagers score Medium with 0 C2
    
    IF result.has_dtd_urls OR result.has_namespace_urls:
        correct_benign_false_positive(result)  // Benign apps flagged due to DTD/namespace URLs
    
    IF result.decoded_count > 0 AND result.c2_count == 0:
        correct_decoding_no_c2(result)
    
    RETURN corrected_result
```

### `step10_binary_packing.py` — Binary Packing Detection
```
FUNCTION detect_binary_packing(apk_path):
    signals = []
    
    IF dex_section_size_anomaly():     signals += "oversized_dex_section"
    IF dex_entropy > 7.5:              signals += "high_entropy_code"
    IF dex_in_dex_nesting():           signals += "dex_in_dex"
    IF dex_header_missing():           signals += "missing_dex"
    IF native_lib_size > 50MB:         signals += "oversized_native_lib"
    IF suspicious_dex_name():          signals += "suspicious_dex_name"
    
    RETURN {is_packed: len(signals) > 0, signals, packing_score}
```

### `step11_string_clustering.py` — String Clustering
```
FUNCTION cluster_high_entropy_strings(strings):
    clusters = []
    FOR each pair (s1, s2) WHERE entropy > 6.0:
        similarity = string_similarity(s1, s2)  // edit-distance based
        IF similarity > 0.7:
            merge_into_cluster(clusters, s1, s2)
    
    FOR each cluster:
        type = classify_obfuscation_type(cluster)  // base64, hex, encrypted, binary, plaintext
    
    RETURN clusters_with_types
```

### `step12_reflective_tracing.py` — Reflective Tracing
```
FUNCTION find_reflective_calls(source_files):
    patterns = [
        "forName", "getDeclaredMethod", "getMethod",
        "Method.invoke", "getDeclaredField", "setAccessible"
    ]
    
    FOR each source_file:
        FOR each pattern in patterns:
            find_matches(pattern, source_file)
            resolve_to_sensitive_api(match)
    
    RETURN [{reflection_call, target_api, file, line}]
```

### `step13_native_elf_analysis.py` — Native ELF Analysis
```
FUNCTION analyze_native_libraries(apk_path):
    elf_files = extract_elf_files_from_apk(apk_path)
    
    FOR each elf in elf_files:
        header = parse_elf_header(elf)
        entropy = shannon_entropy(elf.sections)
        is_obfuscated = detect_elf_obfuscation(elf)
        symbols = extract_symbols(elf)
        crypto_symbols = match_crypto_symbols(symbols)
        anti_debug = match_anti_analysis_symbols(symbols)
    
    RETURN {elf_count, obfuscated_elfs, crypto_apis, anti_analysis_techniques}
```

### `step14_network_protocol_analysis.py` — Network Protocol Analysis
```
FUNCTION analyze_network_protocols(endpoints):
    FOR each endpoint:
        classification = classify_endpoint(endpoint)
        // classification: "c2", "sdk", "benign", "unknown"
    
    RETURN {classified_endpoints, protocol_stats}
```

### `step15_reflective_permission_correlation.py` — Permission Correlation
```
FUNCTION correlate_reflective_permission_usage(reflective_calls, manifest_permissions):
    permission_map = {
        "SMS"      → ["TelephonyManager", "SmsManager"],
        "PHONE"    → ["TelephonyManager", "CallLog"],
        "LOCATION" → ["LocationManager"],
        "CAMERA"   → ["Camera"],
        "STORAGE"  → ["File", "FileOutputStream"]
    }
    
    FOR each reflective call:
        target_class = extract_class_name(call)
        category = find_category(target_class, permission_map)
        IF category:
            declared = find_permission_for_category(category, manifest_permissions)
            correlation = {call, category, declared_permission, has_permission: bool(declared)}
    
    RETURN correlations
```

### `step16_certificate_analysis.py` — Certificate Analysis
```
FUNCTION analyze_certificate(apk_path):
    cert_files = extract_meta_inf_certs(apk_path)
    
    FOR each cert:
        parsed = parse_x509_certificate(cert)
        issuer = parsed.issuer
        subject = parsed.subject
        validity = {from: parsed.notBefore, to: parsed.notAfter}
        fingerprint = sha256(cert.der_data)
        
        is_known_bad = check_known_bad_certificate(fingerprint)
    
    RETURN {issuer, subject, validity, fingerprint, is_known_bad}
```

### `step17_family_clustering.py` — Family Clustering
```
FUNCTION cluster_family(apk_path, known_index):
    // MinHash over method signatures
    methods = extract_method_signatures(apk_path)
    signature = build_minhash_signature(methods, permutations=128)
    
    similarities = []
    FOR each known in index:
        sim = jaccard_similarity(signature, known.signature)
        IF sim > 0.7:
            similarities += {known.family, sim}
    
    index.add(apk_path, signature)  // persist for future matching
    
    RETURN best_match_family, similarity_scores
```

### `step18_threat_synthesis.py` — Threat Synthesis
```
FUNCTION synthesize_threat_profile(steps_10_to_17):
    weights = {
        binary_packing: 0.25,
        reflective_calls: 0.15,
        permission_mismatches: 0.15,
        c2_endpoints: 0.20,
        high_entropy_strings: 0.10,
        native_obfuscation: 0.10,
        certificate_anomalies: 0.05
    }
    
    zero_day_risk = weighted_sum(steps_10_to_17, weights)
    
    RETURN {threat_profile, zero_day_risk_score, contributing_factors}
```

### `decoding_engine.py` — Multi-Layer Decoding (904 lines)
```
FUNCTION multi_layer_decode(text, max_depth=5):
    depth = 0
    results = [{text, entropy, encoding: "raw"}]
    
    WHILE depth < max_depth:
        entropy = classify_entropy(text)
        
        IF entropy == "base64_like":
            text = base64_decode(text)
        ELIF entropy == "hex_like":
            text = hex_decode(text)
        ELIF entropy == "xor_like":
            text = xor_decode(text)
        ELSE:
            BREAK
        
        results += {text, entropy, encoding}
        depth += 1
    
    artifacts = extract_urls_ips_domains(text)
    
    RETURN {decoded_text, decoding_chain: results, artifacts}
```

### `hardcoded_secrets.py` — Hardcoded Secrets Detection (829 lines)
```
FUNCTION analyze_hardcoded_secrets(source_files, strings):
    patterns = {
        "AWS Key":        /AKIA[0-9A-Z]{16}/,
        "Google API Key": /AIza[0-9A-Za-z\-_]{35}/,
        "JWT":            /eyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+/,
        "Private Key":    /-----BEGIN (RSA |EC |DSA )?PRIVATE KEY-----/,
        "DB Connection":  /(mysql|postgresql|mongodb):\/\/[^@]+@/,
        "OAuth Secret":   /client_secret["\s:=]+["']([^"']+)["']/
    }
    
    FOR each source_file:
        FOR each pattern_group, pattern in patterns:
            matches = pattern.findall(source_file.content)
            FOR each match:
                decoded = auto_decode_secret(match)
                risk = classify_risk(decoded, context)
                secrets += {type: pattern_group, value: mask(match), risk, file, line}
    
    RETURN secrets
```

### `ip_validation.py` — IP Validation Framework
```
FUNCTION calculate_ip_legitimacy_score(ip):
    // Multi-layer validation
    IF is_reserved_ip(ip):     RETURN 0.0  // 10.x, 192.168.x, etc.
    IF is_private_range(ip):   RETURN 0.1
    IF is_cdn_edge(ip):        RETURN 0.3  // Cloudflare, Akamai, etc.
    
    // Behavioral scoring
    score = 1.0
    score -= has_suspicious_port(ip) ? 0.3 : 0
    score -= has_malware_history(ip) ? 0.4 : 0
    score += has_legitimate_service(ip) ? 0.2 : 0
    
    RETURN clamp(score, 0.0, 1.0)
```

### `retry_utils.py` — Retry Utilities
```
FUNCTION safe_decompile_apk(apk_path, max_retries=3, timeout=600):
    FOR attempt in 1..max_retries:
        TRY:
            result = run_with_timeout(jadx_decompile, apk_path, timeout)
            RETURN result
        CATCH TimeoutError:
            log("Attempt {attempt}: JADX timed out, retrying...")
            sleep(backoff(attempt))  // exponential backoff
        CATCH DecompilationError as e:
            log("Attempt {attempt}: Decompilation failed: {e}")
    
    RAISE DecompilationError("All {max_retries} attempts failed")
```

---

## 2. Backend (`backend/`)

FastAPI-based REST API and WebSocket server.

### `main.py` — FastAPI Backend (1633 lines)
```
// REST Endpoints:
GET  /                                     → health check
POST /api/upload                           → receive APK file, save to uploads/
POST /api/analyze                          → trigger run_pipeline(apk_path)
GET  /api/samples                          → list all analyzed samples
GET  /api/sample/{id}                      → get analysis results for sample
GET  /api/dissection/{id}                  → get APK dissection metadata
GET  /api/threat-intel                     → aggregated threat intelligence
GET  /api/report/pdf/{id}                  → generate/download PDF report
WS   /ws                                   → real-time progress streaming

FUNCTION on_upload(file):
    sha256 = compute_sha256(file)
    save_to_uploads(file, sha256)
    RETURN {sha256, filename}

FUNCTION on_analyze(sha256):
    emit_websocket("started")
    result = run_pipeline(apk_path, work_dir, websocket)
    cache_result(sha256, result)
    emit_websocket("completed")
    RETURN result

FUNCTION on_sample_detail(id):
    result = load_result(id)
    dissection = load_dissection(id)
    family = identify_family(result)
    RETURN {result, dissection, family}
```

### `config.py` — Configuration
```
CLASS Settings(BaseSettings):
    // Paths
    WORK_DIR: Path = "D:/DroidForensix/work"
    SAMPLES_DIR: Path = "D:/DroidForensix/samples"
    UPLOADS_DIR: Path = "D:/DroidForensix/uploads"
    
    // LLM Providers
    OLLAMA_HOST: str = "http://localhost:11434"
    NVIDIA_NIM_API_KEY: str = ""
    NVIDIA_NIM_ENDPOINT: str = ""
    OPENROUTER_API_KEY: str = ""
    
    // Analysis
    PIPELINE_TIMEOUT: int = 600
    MAX_CONCURRENT_ANALYSES: int = 2
    
    // GeoIP
    GEOIP_DB_PATH: Path = "D:/DroidForensix/data/GeoLite2-City.mmdb"
```

### `dissection.py` — APK Dissector (805 lines)
```
CLASS APKDissector:
    FUNCTION dissect(apk_path):
        a = androguard.APK(apk_path)
        d = androguard.DEX(apk_path)
        
        RETURN {
            package_name: a.get_package(),
            permissions: a.get_permissions(),
            activities: a.get_activities(),
            services: a.get_services(),
            receivers: a.get_receivers(),
            providers: a.get_providers(),
            native_libs: a.get_files().filter(.so),
            min_sdk: a.get_min_sdk_version(),
            target_sdk: a.get_target_sdk_version(),
            dex_stats: {
                class_count: len(d.get_classes()),
                method_count: len(d.get_methods()),
                field_count: len(d.get_fields())
            },
            file_structure: list_apk_contents(apk_path)
        }
```

### `family_id.py` — Family Identification (948 lines)
```
FUNCTION identify_family(pipeline_result):
    // 1. Check ground_truth lookup first
    family = ground_truth_lookup(sha256)
    IF family: RETURN family
    
    // 2. Multi-dimensional signature matching
    FOR each (family_name, signature) in FAMILY_SIGNATURES:
        matched_signals = 0
        
        IF strings_match(signature.string_patterns):    matched_signals += 1
        IF c2s_match(signature.c2_domains):              matched_signals += 1
        IF permissions_meet_threshold(signature.permissions, signature.min_permissions):
            matched_signals += 1
        IF class_count_in_range(signature.class_count_min, signature.class_count_max):
            matched_signals += 1
        IF native_libs_match(signature.has_native_libs):  matched_signals += 1
        
        IF matched_signals >= signature.min_matches:
            candidates += {family_name, matched_signals, signature.confidence}
    
    // 3. Tiebreaker: highest matched_signals wins
    best = max(candidates, key=matched_signals)
    IF best.matched_signals >= best.min_matches:
        RETURN best.family_name
    
    RETURN "Unknown"
```

FAMILY_SIGNATURES includes 19 families: DroidKungFu, FakeInst, FakeInstaller, Opfake, BaseBridge, SpyNote, SpyMax, BankBot, GinMaster, Dowgin, Geinimi, SendPay, Zsone, Plankton, MobileTx, Iconosys, Kmin, FakeDoc, Jiagu.

### `code_analysis.py` — Code Analysis (400 lines)
```
CLASS CodeAnalyzer:
    FUNCTION analyze(decompiled_dir):
        methods = _parse_method_bodies(decompiled_dir)
        
        FOR each method:
            techniques = _detect_techniques(method)
            // reflection, service_dropping, payload_dropping, etc.
            calls = _extract_calls(method)
            risk = _assess_risk(method, techniques, calls)
        
        FOR each string literal:
            context = _classify_string(string)  // URL, command, package, etc.
        
        attack_flows = _reconstruct_attack_flow(methods, strings)
        
        RETURN {methods_analyzed, techniques, risk_score, attack_flows}
```

### `elf_analyzer.py` — ELF Binary Analyzer (1022 lines)
```
CLASS ELFBreaker:
    FUNCTION analyze(elf_path):
        elf = ELFFile(elf_path)
        
        RETURN {
            header: {
                class: elf.ei_class,         // 32-bit / 64-bit
                endian: elf.ei_data,          // little / big
                entry: elf.e_entry,
                type: elf.e_type              // DYN, EXEC, REL, etc.
            },
            sections: parse_sections(elf),    // .text, .data, .bss, .rodata
            symbols: parse_symbols(elf),      // exported, imported, hidden
            is_packed: detect_packing(elf),   // UPX, custom packers
            anti_analysis: detect_anti_analysis(elf),
            embedded_blobs: find_embedded_blobs(elf),
            suspicious_strings: find_suspicious_strings(elf),
            // deobfuscation:
            decoded_strings: deobfuscate_strings(elf)
        }
```

### `threat_intel.py` — Threat Intelligence (606 lines)
```
FUNCTION build_threat_intel(all_samples):
    intel = {
        c2_endpoints: extract_all_c2s(all_samples),
        geoip: enrich_with_geoip(c2_endpoints),
        isp: enrich_with_isp(c2_endpoints),
        families: aggregate_family_stats(all_samples),
        timelines: build_timelines(all_samples)
    }
    
    RETURN {intel, csv_export, stix_export, yara_export}
```

### `pdf_report.py` / `pdf_report_enhanced.py` — PDF Report Generator
```
FUNCTION generate_pdf_report(sample_id, report_type="quick"|"full"):
    data = load_sample_data(sample_id)
    
    pdf = ReportLab Canvas
    
    pdf.add_section("Sample Metadata")
    pdf.add_table([sha256, package_name, file_size, ...])
    
    pdf.add_section("LLM Assessment")
    pdf.add_text(data.assessment.explanation)
    
    pdf.add_section("Obfuscation Analysis")
    pdf.add_table(data.obfuscation.signals)
    
    pdf.add_section("C2 Infrastructure")
    FOR each c2 in data.c2s:
        pdf.add_record([c2.domain, c2.ip, c2.confidence, c2.geoip])
    
    pdf.add_section("Suspicious Classes")
    pdf.add_list(data.suspicious_classes)
    
    IF report_type == "full":
        pdf.add_section("Threat Intelligence")
        pdf.add_section("STIX Export)
        pdf.add_section("Certificate Analysis")
        pdf.add_section("Native Library Analysis")
        pdf.add_section("Hardcoded Secrets")
    
    RETURN pdf_bytes
```

### `transformers.py` — Data Transformers
```
FUNCTION transform_graph(pipeline_result):
    // Build 3D visualization graph
    nodes = []
    edges = []
    
    // String → Encoded → Decoded → C2 chains
    FOR each chain in threat_chains:
        nodes += Node(id=chain.source, group="string")
        nodes += Node(id=chain.decoded, group="decoded")
        FOR each c2 in chain.c2s:
            nodes += Node(id=c2.domain, group="c2")
            edges += Edge(chain.source → chain.decoded)
            edges += Edge(chain.decoded → c2.domain)
    
    RETURN {nodes, edges}

FUNCTION transform_clusters(all_results):
    // t-SNE or PCA for 3D scatter
    FOR each result in all_results:
        features = extract_feature_vector(result)
        coords = reduce_dimensions(features, dims=3)
        points[x, y, z, label=sample.family, sha=sample.sha]
    
    RETURN points
```

### `circl_client.py` — CIRCL Client
```
CLASS CIRCLClient:
    FUNCTION __init__():
        auth = HTTPBasicAuth(CIRCL_USER, CIRCL_PASS)
        session = requests.Session(auth=auth)
        rate_limiter = RateLimiter(1 req/sec)
    
    FUNCTION enrich_c2s(c2_records):
        FOR each c2:
            IF c2.domain:
                pssl = query_ssl(c2.domain)   // hash, seen_date, ...
                pdns = query_dns(c2.domain)    // IP, first/last seen
                c2.enrich({pssl, pdns})
        
        RETURN enriched_c2s
```

### `obfuscation_view.py` — Obfuscation View Builder
```
FUNCTION build_obfuscation_view(step8_result):
    FOR each technique:
        smali_refs = _parse_smali_method(technique.smali_location)
    
    RETURN {
        techniques_summary,
        dex_entropy_chart,
        native_lib_artifacts,
        deobfuscated_texts
    }
```

---

## 3. Backend Core (`backend/core/`)

### `androguard_analyzer.py` — Androguard Analyzer (550 lines)
```
CLASS APKAnalyzer:
    FUNCTION analyze(apk_path):
        a = APK(apk_path)
        
        RETURN {
            package: a.get_package(),
            permissions: a.get_permissions(),
            activities: a.get_activities(),
            services: a.get_services(),
            receivers: a.get_receivers(),
            providers: a.get_providers(),
            main_activity: a.get_main_activity(),
            native_libs: list_native_libs(a),
            fcm_components: find_fcm_components(a),
            risk_indicators: assess_risk(a)
        }
```

### `apk_processor.py` — APK Processor (681 lines)
```
CLASS APKProcessor:
    FUNCTION process(apk_path, config):
        // 7-step lightweight pipeline
        step1 = androguard_analyze(apk_path)
        step2 = extract_strings(decompiled_dir)
        step3 = analyze_entropy(strings)
        step4 = detect_encoding(high_entropy_strings)
        step5 = decode_payloads(encoded)
        step6 = extract_c2s(decoded)
        step7 = build_threat_chains(c2s, decoded)
        
        RETURN aggregated_result
```

---

## 4. Scripts (`scripts/`)

### `batch_analyze_310.py` — Batch Analyzer
```
FUNCTION batch_analyze():
    metadata = load_sample_metadata("sample_metadata.csv")
    
    FOR each sample in metadata:
        timeout = estimate_timeout(sample.file_size)
        TRY:
            result = run_pipeline(sample.apk_path, timeout)
            save_result(sample.sha256, result)
        CATCH Exception as e:
            log_error(sample.sha256, e)
    
    PRINT summary: {total, succeeded, failed, avg_time}
```

### `validate_fp.py` — False Positive Validation
```
FUNCTION validate_false_positives():
    results = scan_pipeline_results()
    
    FOR each result with C2 indicators:
        display_c2_info(result)
        classification = ask_user("Is this a true positive?")  // Y/N/Skip
        persist_classification(result.sha, classification)
    
    generate_fp_summary_report()
```

### `check_live_c2.py` — Live C2 Checker
```
FUNCTION check_live_c2s(all_results):
    FOR each c2 in all_results:
        TRY:
            resp = http_get(c2.domain, timeout=5)
            c2.is_live = (resp.status_code < 500)
        CATCH:
            c2.is_live = False
    
    RETURN {live_count, dead_count, live_c2s: [...]}
```

---

## 5. Frontend (`frontend/`)

React-based dashboard UI. All components are functional React components with hooks.

### `src/App.jsx` — Main App
```
COMPONENT App:
    STATE: {samples, selectedSample, analysisState, ws}
    
    ON MOUNT:
        connectWebSocket("/ws")
        loadSampleList()
    
    FUNCTION onUpload(apkFile):
        POST /api/upload → {sha256}
        POST /api/analyze → {analysisId}
        ws.on("progress") → updateProgressBar()
        ws.on("completed") → refreshSampleList()
    
    FUNCTION onSampleClick(id):
        GET /api/sample/{id} → setSelectedSample(data)
    
    RENDER:
        UploadPanel
        SampleSearch
        IF selectedSample:
            SampleDetail(selectedSample)
```

### `src/pages/SampleDetail.jsx` — Sample Detail Page
```
COMPONENT SampleDetail(id):
    STATE: {analysis, dissection, family, loading}
    
    ON MOUNT:
        data = fetchSampleData(id)
        setAnalysis(data.result)
        setDissection(data.dissection)
        setFamily(data.family)
    
    RENDER:
        Tabs:
            Overview → ThreatSummary, ConfidenceBar, FamilySignalsCard
            Code → CodeTab, ClassSourceViewer
            Components → ComponentsTab, ComponentCard
            Manifest → ManifestTab, ManifestView
            Permissions → PermissionsTab, PermissionCard
            DEX → DEXTab
            Native Libs → NativeLibsTab
            Strings → StringsTab
        Sidebar:
            DissectionTabs, SmartDissection
        Bottom:
            ThreatSynthesisPanel, ThreatConsolidationSummary
```

### Key Frontend Components

| Component | Pseudocode |
|-----------|-----------|
| `UploadPanel` | Drag-and-drop zone → validate .apk → POST /api/upload → progress bar → completion toast |
| `AnalysisView` | Tabbed container for all analysis sections; fetches data by tab |
| `ThreatSummary` | Severity badge + risk score + key findings bullets |
| `ClassSourceViewer` | Syntax-highlighted Java code with line numbers, search, copy |
| `ManifestView` | XML tree view of AndroidManifest with permission highlighting |
| `ComponentCard` | Card showing Activity/Service/Receiver/Provider name, intent filters, exported flag |
| `PermissionCard` | Permission name, protection level, description, risk badge |
| `MITREDisplay` | MITRE ATT&CK techniques mapped to detected behaviors, with tactic grouping |
| `LLMVerificationBadge` | LLM assessment status (verified/contradicted/unverified), confidence score |
| `FamilySignalsCard` | Matched family signature dimensions (strings, C2s, permissions, classes, native libs) |
| `ThreatIntelView` | GeoIP map, ISP breakdown, C2 timeline, CSV/STIX/YARA export buttons |
| `ThreatSynthesisPanel` | Radar chart of 7 risk dimensions, zero-day risk score, contributing factors |
| `Toast` | Non-blocking notification for upload/analysis events |

---

## 6. Evaluation (`evaluation/`)

### `run_validation_359.py` — 359-Sample Validation Runner
```
FUNCTION run_validation():
    ground_truth = load_ground_truth("ground_truth_all.csv")  // 359 entries
    
    disable_ground_truth_lookup()  // prevent leakage
    
    start_isolated_ollama()
    
    predictions = {}
    WITH ProcessPoolExecutor(max_workers=4):
        FOR each (sha256, apk_path) in ground_truth:
            future = executor.submit(run_pipeline, apk_path)
            predictions[sha256] = future.result()
    
    save_predictions("predictions.json")
    
    accuracy = calculate_accuracy(predictions, ground_truth)
    confusion = build_confusion_matrix(predictions, ground_truth)
    
    PRINT accuracy_report
    SAVE confusion_matrix.csv
```

---

## 7. Tests (`tests/`, `frontend/__tests__/`)

**Python tests** (27 files): pytest-based, test all pipeline steps, backend API, C2 extraction, encoding detection, obfuscation analysis, family clustering, threat synthesis, hardcoded secrets, and more.

**Frontend tests** (35 files): vitest + React Testing Library, test all components (AnalysisView, UploadPanel, ThreatSummary, etc.), API client, and utility functions.

**Key test files:**

| Test File | What It Tests |
|-----------|---------------|
| `test_backend.py` | API health check, sample listing, pipeline integration |
| `test_c2_and_correlation.py` | classify_ip, parse_url, extract_c2, threat chains, fallback assessment |
| `test_encoding_detection.py` | Base64/hex encoding detection and decoding |
| `test_obfuscation_analysis.py` | Shannon entropy, obfuscation scoring, DEX entropy |
| `test_hardcoded_secrets.py` | AWS keys, Google API keys, JWT, private key detection |
| `test_code_analysis.py` | Method parsing, technique detection, risk assessment |
| `test_module_imports.py` | All modules import cleanly (smoke test) |
| `test_pipeline_integration.py` | Full end-to-end pipeline with mocked steps |
| `tests/analysis/test_step*.py` | Individual step tests (10-18) |
| `frontend/__tests__/AnalysisView.test.jsx` | AnalysisView rendering and interaction |
| `frontend/__tests__/ThreatSummary.test.jsx` | Threat summary display logic |

---

## Project Architecture Summary

```
DroidForensix/
├── analysis/               # 18-step pipeline (CORE)
│   ├── pipeline.py         # Orchestrator
│   ├── step1..step18.py    # Individual analysis steps
│   ├── decoding_engine.py  # Multi-layer string decoding
│   └── hardcoded_secrets.py # Secret/credential detection
├── backend/                # FastAPI server (API LAYER)
│   ├── main.py             # REST endpoints + WebSocket
│   ├── family_id.py        # Malware family identification
│   ├── dissection.py       # APK structural analysis
│   ├── code_analysis.py    # Java code analysis
│   ├── elf_analyzer.py     # Native ELF binary analysis
│   ├── pdf_report*.py      # PDF report generation
│   ├── threat_intel*.py    # Threat intel aggregation
│   ├── circl_client.py     # CIRCL passive DNS/SSL enrichment
│   └── core/               # Core processing (androguard, processor)
├── frontend/               # React dashboard (UI LAYER)
│   ├── src/components/     # 30+ React components
│   ├── src/pages/          # SampleDetail page
│   └── src/api/            # API client
├── scripts/                # Batch analysis, validation, utilities
├── evaluation/             # 359-sample family validation
├── tests/                  # Python test suite (27 files)
└── samples/                # APK sample storage
```
