"""Deep analysis: what data DID the pipeline extract for these 5 FNs?"""
import json
from pathlib import Path

FNs = [
    ("54f2a636e000c55bb725d7e552a22117837c1676fb4b96decd135ae10e6f7049", "BaseBridge"),
    ("255eae7859b0855b15de30e5405a2714837ac556c238bc009ac74c5bfa69714a", "Nisev"),
    ("03385b42f9dffe697a883aac40042188e658145e8d67e0dab9d665501d7e02aa", "Opfake"),
    ("5010f34461e309ea1bc5539bb24fccc320576ce6d677a29604f5568c0a5e6315", "Opfake"),
    ("d4b3fa551ff6282287ea8d30b2860a55198f0a8c76cf20ea27bba95113628f69", "Stiniter"),
]

WORK_DIR = Path("analysis/work")

for h, fam in FNs:
    wd = WORK_DIR / h
    pr = json.loads((wd / "pipeline_result.json").read_text())

    print("=" * 70)
    print(f"{fam} ({h[:16]}...)")

    # 1. Manifest / permissions
    man = pr.get("manifest") or {}
    perms = man.get("permissions", [])
    print(f"\n  Permissions ({len(perms)}): {perms}")

    # 2. Strings
    strs = pr.get("strings") or {}
    print(f"\n  Strings:")
    print(f"    Total strings: {strs.get('total_strings', '?')}")
    decoded = strs.get("decoded_strings", []) or []
    if decoded:
        print(f"    Decoded ({len(decoded)}): {decoded[:10]}")
    else:
        print(f"    Decoded: none")
    suspicious = strs.get("suspicious_strings", []) or []
    if suspicious:
        print(f"    Suspicious ({len(suspicious)}): {suspicious[:10]}")

    # 3. Encodings
    encs = pr.get("encodings", []) or []
    print(f"\n  Encodings ({len(encs)}):")
    for e in encs:
        print(f"    Type={e.get('type')}  Data={str(e.get('data',''))[:120]}")

    # 4. Payloads
    pls = pr.get("payloads", []) or []
    print(f"\n  Payloads ({len(pls)}):")
    for p in pls:
        print(f"    Type={p.get('type')}  Technique={p.get('technique')}  Desc={str(p.get('description',''))[:120]}")

    # 5. C2
    c2 = pr.get("c2_infrastructure") or {}
    print(f"\n  C2 Domains ({len(c2.get('domains',[]) or [])}):")
    for d in (c2.get("domains", []) or [])[:5]:
        print(f"    {d}")

    # 6. Threat chains
    tc = pr.get("threat_chains", []) or []
    print(f"\n  Threat Chains ({len(tc)}):")
    for t in tc[:5]:
        print(f"    {t.get('category')}: {t.get('description','')[:150]}")

    # 7. Obfuscation
    obf = pr.get("obfuscation_analysis") or {}
    print(f"\n  Obfuscation Score: {obf.get('obfuscation_score')}")
    print()

    # Read actual step files for more detail
    for sf in ["step2_strings.json", "step3_encodings.json", "step4_payloads.json", "step5_c2s.json", "step6_chains.json", "step8_obfuscation.json"]:
        sf_path = wd / sf
        if sf_path.exists():
            data = json.loads(sf_path.read_text())
            if isinstance(data, dict) and data:
                if "error" in data:
                    print(f"  {sf}: ERROR = {data['error'][:100]}")
            elif isinstance(data, list):
                if not data:
                    pass  # empty list is fine
            elif data is None:
                print(f"  {sf}: NULL")
