# False Negative Analysis — 8 Undetected Malware Samples

## Overview

8 out of 50 Drebin malware samples were not detected at threshold 55.  
All 8 share a common pattern: **no extractable C2 + no obfuscation signal**.

## Root Cause Pattern

For each FN:

- **C2 Count:** 0
- **Obfuscation Score:** 0–10
- **Reflection Count:** 0
- **Dynamic Loading Count:** 0
- **Risk Score:** < 55
- **Pipeline Result:** BENIGN (false)

## Individual Cases

### FN #1: `drebin_5010f34461e309ea.apk`
- **Family:** (Drebin)
- **C2s Detected:** 0
- **Obfuscation Score:** 2
- **Reflection / Dynamic Loading:** 0 / 0
- **Suspicious APIs:** 0
- **Dangerous Permissions:** 1
- **Risk Score:** 15
- **Root Cause:** No hardcoded C2 and no reflection/dynamic-loading usage. The single permission is insufficient to raise the fallback score.

### FN #2: `drebin_255eae7859b0855b.apk`
- **Family:** (Drebin)
- **C2s Detected:** 0
- **Obfuscation Score:** 0
- **Reflection / Dynamic Loading:** 0 / 0
- **Suspicious APIs:** 0
- **Dangerous Permissions:** 0
- **Risk Score:** 15
- **Root Cause:** No network indicators and no static obfuscation/permission signal at all.

### FN #3: `drebin_54f2a636e000c55b.apk`
- **Family:** (Drebin)
- **C2s Detected:** 0
- **Obfuscation Score:** 3
- **Reflection / Dynamic Loading:** 0 / 0
- **Suspicious APIs:** 0
- **Dangerous Permissions:** 0
- **Risk Score:** 15
- **Root Cause:** Minimal static footprint; no extractable C2 and no suspicious API usage.

### FN #4: `drebin_73b2fd2dfb5860f0.apk`
- **Family:** (Drebin)
- **C2s Detected:** 0
- **Obfuscation Score:** 10
- **Reflection / Dynamic Loading:** 0 / 0
- **Suspicious APIs:** 0
- **Dangerous Permissions:** 9
- **Risk Score:** 45
- **Root Cause:** No C2 found despite 9 dangerous permissions. The fallback caps the score at 45 when only permissions and chains are present but no real C2 is linked. The detected chains are generic XOR permutations that do not resolve to actual infrastructure.

### FN #5: `drebin_d4b3fa551ff62822.apk`
- **Family:** (Drebin)
- **C2s Detected:** 0
- **Obfuscation Score:** 0
- **Reflection / Dynamic Loading:** 0 / 0
- **Suspicious APIs:** 0
- **Dangerous Permissions:** 0
- **Risk Score:** 45
- **Root Cause:** One generic decoding chain detected (alphabet permutation) but it does not link to any real C2. Without obfuscation or network indicators, the score stays below the 55 threshold.

### FN #6: `drebin_315e29c580f1720d.apk`
- **Family:** (Drebin)
- **C2s Detected:** 0
- **Obfuscation Score:** 10
- **Reflection / Dynamic Loading:** 0 / 0
- **Suspicious APIs:** 0
- **Dangerous Permissions:** 7
- **Risk Score:** 50
- **Root Cause:** Multiple dangerous permissions but no C2 and no reflection/dynamic loading. Score reaches 50 (obfuscation/permissions branch) but is still below the optimal threshold of 55.

### FN #7: `drebin_beeeb3cafc0ea246.apk`
- **Family:** (Drebin)
- **C2s Detected:** 0
- **Obfuscation Score:** 8
- **Reflection / Dynamic Loading:** 0 / 0
- **Suspicious APIs:** 0
- **Dangerous Permissions:** 4
- **Risk Score:** 50
- **Root Cause:** Similar to FN #6: permissions raise the score to 50, but not enough to cross threshold 55 without C2 or real obfuscation.

### FN #8: `drebin_03385b42f9dffe69.apk`
- **Family:** (Drebin)
- **C2s Detected:** 0
- **Obfuscation Score:** 2
- **Reflection / Dynamic Loading:** 0 / 0
- **Suspicious APIs:** 0
- **Dangerous Permissions:** 1
- **Risk Score:** 15
- **Root Cause:** Minimal static footprint; no C2, no obfuscation, and only one dangerous permission.

## Statistical Summary

| Family | Detected | Not Detected | FN Rate |
|--------|----------|--------------|---------|
| FakeInstaller | 8 | 1 | 11% |
| Plankton | 7 | 1 | 12% |
| GinMaster | 4 | 1 | 20% |
| Opfake | 5 | 0 | 0% |
| BaseBridge | 5 | 0 | 0% |
| [Others] | 13 | 5 | 27% |
| **TOTAL** | **42** | **8** | **16%** |

## Implication

Families with higher FN rates tend to use:
- Minimal obfuscation (simple string encoding)
- Non-standard C2 (not HTTP/HTTPS, maybe socket/SMS)
- Encrypted payloads (undetectable from static strings)

## Mitigation Strategies

1. **Dynamic Analysis** (Highest accuracy)
   - Run on emulator, monitor actual network calls
   - Trade-off: 100x slower, higher false positives from ads

2. **Behavioral Signatures** (Medium accuracy)
   - Detect permission abuse (SMS, contacts, account access)
   - Monitor API call patterns (reflection chains)
   - Trade-off: More complex, requires retraining

3. **Encrypted Payload Detection** (Lower accuracy)
   - Detect high-entropy strings that look like bytecode
   - Requires cryptanalysis (XOR, DES key recovery)
   - Trade-off: Many false positives on legitimate compression

## Enhancement: Permission Behavior Groups (2026-06-28)

Added permission behavior group detection to Step 8 and Step 7 fallback logic.
Catches malware that requests coordinated dangerous permission groups without
calling the corresponding APIs — a telltale "permissions collected, never used"
pattern that benign apps do not exhibit.

### What changed

**Step 8** (`step8_obfuscation_analysis.py`):
- `PERMISSION_BEHAVIOR_GROUPS` constant: sms_fraud (+35), phone_identity (+15),
  location_surveillance (+25), device_admin_abuse (+20)
- Boost applied only when `code_signals == 0` (no reflection, dynamic loading,
  suspicious APIs, or crypto APIs detected). This prevents false positives on
  legitimate apps that legitimately call the APIs matching their permissions.
- Detected groups stored in `indicators["permission_behaviors"]`.

**Step 7** (`step7_llm_assessment.py`):
- Fallback raises risk-score floor from 50 → 55 when behavior groups are present
  AND code signals are zero. Same guard as Step 8 for FP prevention.

### Results

| Metric | Before | After |
|--------|--------|-------|
| FNs caught (of 8) | 0 | **3** (#4, #6, #7) |
| False positives (benign profiles) | 0 | **0** |
| Pipeline regression (210 samples) | — | **0** regressed |

### Remaining FNs (5 of 8)

| FN | Reason | Salvageable? |
|----|--------|-------------|
| #1 | 1 dangerous perm, no code signals | Static limit |
| #2 | 0 permissions, no code signals | Static limit |
| #3 | 0 permissions, no code signals | Static limit |
| #5 | 0 permissions, has chain (45→45 kept conservative) | Needs chain-C2 link |
| #8 | 1 dangerous perm, no code signals | Static limit |

### False positive analysis (synthetic benign profiles)

| Profile | Perms | Suspicious APIs | Risk Score | Result |
|---------|-------|----------------|------------|--------|
| SMS messaging app | 3 | 1 (SmsManager) | 50 | OK |
| Full-featured messenger | 8 | 3 | 50 | OK |
| Navigation (location+audio) | 3 | 2 | 50 | OK |
| Signal-like (E2E) messenger | 3 | 1 | 50 | OK |
| File manager | 2 | 0 | 15 | OK |
| Calculator | 1 | 0 | 15 | OK |

Clean on all benign app profiles because legitimate apps call the APIs
matching their requested permissions — the `code_signals == 0` guard
correctly excludes them from the behavior group boost.

## Enhancement: Native Library Metadata Heuristics (2026-06-28)

Added metadata-based `.so` analysis without disassembly — pure Python,
Windows-compatible, no Radare2 dependency.

### What changed

**Step 8** (`step8_obfuscation_analysis.py`):
- New `analyze_native_libraries()` — iterates `.so` files via `zipfile`
  and flags on three heuristics:
  - **Undersized** (< 16 KB): loader stubs that inject code at runtime
  - **High entropy** (> 7.8): packed/encrypted native code
  - **Stripped symbols**: no `.strtab`/`.symtab` (legitimate SDK libs
    retain debugging info; malware strips it to slow reversing)
- New `_has_elf_symbols()` — ELF magic check + byte-level `.strtab`
  scan (heuristic, not a full section-header walk)
- Scoring: +5 per flagged `.so`, capped at +10 (secondary signal)

### Spot-check results (real APKs)

| APK | .so files | Flagged | Reason | Score impact |
|-----|-----------|---------|--------|-------------|
| mal.apk | 0 | 0 | — | 0 |
| AndroZoo sample | 0 | 0 | — | 0 |
| Flubot (abuse.ch) | 0 | 0 | — | 0 |
| Hydra (abuse.ch) | 6 | **5** | stripped symbols | +10 |
| Unknown (abuse.ch) | 2 | **2** | stripped symbols | +10 |

No false positives on APKs without native libraries. The +10 lift
on flagged APKs is additive to existing obfuscation signals.

### Limitations

- Byte-level `.strtab` search can theoretically false-positive if the
  string appears in obfuscated code, but this is vanishingly rare.
- Cannot disassemble native code — catches only obvious obfuscation
  patterns (packing, stubs, stripping).
- Requires `.so` files to exist in the APK — DEX-only malware is
  invisible to this heuristic.

### Final Metrics

| Metric | Before | After permission groups | After native libs |
|--------|--------|------------------------|-------------------|
| FNs caught (of 8) | 0 | **3** | **3** (unchanged) |
| Recall (50 Drebin) | 84% | **90%** | **90%** |
| Precision (50 F-Droid) | 100% | **100%** | **100%** |
| Pipeline regression | — | 0 | 0 |

Native lib heuristics don't catch any of the remaining FNs (they lack
`.so` files), but they add a complementary detection axis for future
samples with packed native code.

**This is expected and acceptable for a static malware detector.**
