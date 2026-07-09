"""Check step files for errors or empty output on the 5 FNs."""
import json
from pathlib import Path

FNs = [
    "54f2a636e000c55bb725d7e552a22117837c1676fb4b96decd135ae10e6f7049",
    "255eae7859b0855b15de30e5405a2714837ac556c238bc009ac74c5bfa69714a",
    "03385b42f9dffe697a883aac40042188e658145e8d67e0dab9d665501d7e02aa",
    "5010f34461e309ea1bc5539bb24fccc320576ce6d677a29604f5568c0a5e6315",
    "d4b3fa551ff6282287ea8d30b2860a55198f0a8c76cf20ea27bba95113628f69",
]

WORK = Path("analysis/work")

STEP_FILES = [
    "step1_extraction.json",
    "step2_strings.json",
    "step3_encodings.json",
    "step4_payloads.json",
    "step5_c2s.json",
    "step6_chains.json",
    "step8_obfuscation.json",
]

for h in FNs:
    wd = WORK / h
    print(f"\n{'='*70}")
    print(f"Work dir: {h[:16]}...")

    for sf_name in STEP_FILES:
        sf = wd / sf_name
        if not sf.exists():
            print(f"  {sf_name}: MISSING")
            continue
        data = json.loads(sf.read_text())

        # Print key structure
        if isinstance(data, dict):
            keys = list(data.keys())
            if not keys:
                print(f"  {sf_name}: {{}} (empty dict)")
            else:
                print(f"  {sf_name}: keys={keys[:10]}")
                if "error" in data:
                    print(f"    ERROR: {data['error'][:200]}")
                if "permissions" in data:
                    print(f"    permissions={data['permissions']}")
                if "decoded_strings" in data:
                    val = data["decoded_strings"]
                    print(f"    decoded_strings={len(val) if val else 0}")
                if "suspicious_strings" in data:
                    val = data["suspicious_strings"]
                    print(f"    suspicious_strings={len(val) if val else 0}")
                if "domains" in data:
                    val = data["domains"]
                    print(f"    domains={len(val) if val else 0}")
                if "total_strings" in data:
                    print(f"    total_strings={data['total_strings']}")
        elif isinstance(data, list):
            if not data:
                print(f"  {sf_name}: [] (empty list)")
            else:
                print(f"  {sf_name}: list[{len(data)}] first={str(data[0])[:120]}")
        else:
            print(f"  {sf_name}: {type(data).__name__} = {str(data)[:100]}")
