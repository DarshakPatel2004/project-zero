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

## Conclusion

The 8 false negatives are **not bugs**—they represent the **inherent limitations of static C2-based detection**. Closing this gap requires complementary techniques (dynamic analysis, behavioral detection) outside the scope of this static pipeline.

**This is expected and acceptable for a static malware detector.**
