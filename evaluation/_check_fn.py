"""Check whether these 5 APKs are actually parseable."""
import json
from pathlib import Path

FNs = [
    "54f2a636e000c55bb725d7e552a22117837c1676fb4b96decd135ae10e6f7049",  # BaseBridge
    "255eae7859b0855b15de30e5405a2714837ac556c238bc009ac74c5bfa69714a",  # Nisev
    "03385b42f9dffe697a883aac40042188e658145e8d67e0dab9d665501d7e02aa",  # Opfake
    "5010f34461e309ea1bc5539bb24fccc320576ce6d677a29604f5568c0a5e6315",  # Opfake
    "d4b3fa551ff6282287ea8d30b2860a55198f0a8c76cf20ea27bba95113628f69",  # Stiniter
]

WORK_DIR = Path("analysis/work")
SAMPLES_DIR = Path("samples")

for h in FNs:
    print("=" * 70)
    print(f"SHA256: {h}")
    wd = WORK_DIR / h
    if not wd.exists():
        print("  STATUS: No work directory at all — pipeline never processed this")
        print()
        continue

    # Check what files exist in work dir
    files = list(wd.iterdir())
    print(f"  Work dir files ({len(files)}): {[f.name for f in files]}")

    # Read pipeline_result to see what steps ran
    pr_file = wd / "pipeline_result.json"
    if pr_file.exists():
        pr = json.loads(pr_file.read_text())
        for step in ["metadata", "extraction", "manifest", "strings", "threat_chains"]:
            val = pr.get(step)
            if val:
                print(f"  {step}: PRESENT (type={type(val).__name__})")
            else:
                print(f"  {step}: MISSING or empty")

    # Check for raw analysis files
    for fname in ["manifest.json", "strings.json", "payloads.json", "encodings.json", "threat_chains.json", "c2.json", "obfuscation.json"]:
        f = wd / fname
        if f.exists():
            print(f"  {fname}: {f.stat().st_size} bytes")
    print()
