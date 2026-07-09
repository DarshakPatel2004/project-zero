"""Dump the actual content of step files beyond the first-level keys."""
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
FAM = {h: fam for h, fam in zip(FNs, ["BaseBridge","Nisev","Opfake","Opfake","Stiniter"])}

for h in FNs:
    wd = WORK / h
    print(f"\n{'='*70}")
    print(f"{FAM[h]} ({h[:16]}...)")

    # step2_strings: look at categories
    sf = wd / "step2_strings.json"
    if sf.exists():
        data = json.loads(sf.read_text())
        cats = data.get("categories", {}) or {}
        if cats:
            print(f"\n  String categories ({len(cats)}):")
            for cat, items in list(cats.items())[:10]:
                print(f"    {cat}: {len(items) if isinstance(items, list) else items}")
                if isinstance(items, list) and items:
                    for x in items[:5]:
                        print(f"      {str(x)[:100]}")
        else:
            print("  String categories: empty")

    # step3_encodings: look at encodings list
    sf = wd / "step3_encodings.json"
    if sf.exists():
        data = json.loads(sf.read_text())
        encs = data.get("encodings", []) or []
        if encs:
            for e in encs[:5]:
                print(f"  Encoding: {json.dumps(e, default=str)[:200]}")
        else:
            print("  Encodings: empty")

    # step4_payloads
    sf = wd / "step4_payloads.json"
    if sf.exists():
        data = json.loads(sf.read_text())
        pls = data.get("payloads", []) or []
        if pls:
            for p in pls[:5]:
                print(f"  Payload: {json.dumps(p, default=str)[:200]}")
        else:
            print("  Payloads: empty")

    # step5_c2s
    sf = wd / "step5_c2s.json"
    if sf.exists():
        data = json.loads(sf.read_text())
        c2 = data.get("c2_infrastructure", {}) or {}
        domains = c2.get("domains", []) or []
        if domains:
            print(f"  C2 domains ({len(domains)}): {domains}")
        else:
            print("  C2 domains: empty")
        if c2:
            print(f"  C2 full keys: {list(c2.keys())}")

    # step6_chains
    sf = wd / "step6_chains.json"
    if sf.exists():
        data = json.loads(sf.read_text())
        tcs = data.get("threat_chains", []) or []
        if tcs:
            for t in tcs[:5]:
                print(f"  Threat chain: {json.dumps(t, default=str)[:300]}")
        else:
            print("  Threat chains: empty")

    # step8_obfuscation
    sf = wd / "step8_obfuscation.json"
    if sf.exists():
        data = json.loads(sf.read_text())
        indicators = data.get("indicators", []) or []
        notes = data.get("notes", "")
        print(f"  Obfuscation notes: {notes[:200]}")
        if indicators:
            print(f"  Obfuscation indicators ({len(indicators)}):")
            for ind in indicators[:5]:
                print(f"    {json.dumps(ind, default=str)[:150]}")
