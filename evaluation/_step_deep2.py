"""Dump step files with unicode-safe output."""
import json, sys
from pathlib import Path

FNs = [
    ("54f2a636e000c55bb725d7e552a22117837c1676fb4b96decd135ae10e6f7049", "BaseBridge"),
    ("255eae7859b0855b15de30e5405a2714837ac556c238bc009ac74c5bfa69714a", "Nisev"),
    ("03385b42f9dffe697a883aac40042188e658145e8d67e0dab9d665501d7e02aa", "Opfake"),
    ("5010f34461e309ea1bc5539bb24fccc320576ce6d677a29604f5568c0a5e6315", "Opfake"),
    ("d4b3fa551ff6282287ea8d30b2860a55198f0a8c76cf20ea27bba95113628f69", "Stiniter"),
]

WORK = Path("analysis/work")

for h, fam in FNs:
    wd = WORK / h
    print(f"\n{'='*70}", file=sys.stderr)
    print(f"{fam} ({h[:16]}...)", file=sys.stderr)

    # step2: categories summary
    sf = wd / "step2_strings.json"
    if sf.exists():
        data = json.loads(sf.read_text())
        cats = data.get("categories", {}) or {}
        ts = data.get("total_strings", 0)
        print(f"  Total strings: {ts}", file=sys.stderr)
        for cat, items in list(cats.items())[:8]:
            n = len(items) if isinstance(items, list) else items
            snippet = ""
            if isinstance(items, list) and items:
                raw = json.dumps(items[0], ensure_ascii=False)
                snippet = f"  e.g. {raw[:120]}"
            print(f"    {cat}: {n}{snippet}", file=sys.stderr)

    # step3: encodings
    sf = wd / "step3_encodings.json"
    if sf.exists():
        data = json.loads(sf.read_text())
        encs = data.get("encodings", []) or []
        if encs:
            print(f"  Encodings ({len(encs)}):", file=sys.stderr)
            for e in encs:
                print(f"    {json.dumps(e, ensure_ascii=False, default=str)[:200]}", file=sys.stderr)
        else:
            print(f"  Encodings: []", file=sys.stderr)

    # step4: payloads
    sf = wd / "step4_payloads.json"
    if sf.exists():
        data = json.loads(sf.read_text())
        pls = data.get("payloads", []) or []
        if pls:
            print(f"  Payloads ({len(pls)}):", file=sys.stderr)
            for p in pls:
                print(f"    {json.dumps(p, ensure_ascii=False, default=str)[:200]}", file=sys.stderr)
        else:
            print(f"  Payloads: []", file=sys.stderr)

    # step5: C2
    sf = wd / "step5_c2s.json"
    if sf.exists():
        data = json.loads(sf.read_text())
        c2 = data.get("c2_infrastructure", {}) or {}
        domains = c2.get("domains", []) or []
        if domains:
            print(f"  C2 ({len(domains)}): {json.dumps(domains, ensure_ascii=False)[:200]}", file=sys.stderr)
        else:
            print(f"  C2: empty", file=sys.stderr)

    # step6: threat chains
    sf = wd / "step6_chains.json"
    if sf.exists():
        data = json.loads(sf.read_text())
        tcs = data.get("threat_chains", []) or []
        if tcs:
            print(f"  Threat chains ({len(tcs)}):", file=sys.stderr)
            for t in tcs:
                print(f"    {json.dumps(t, ensure_ascii=False, default=str)[:300]}", file=sys.stderr)
        else:
            print(f"  Threat chains: []", file=sys.stderr)

    # step8: obfuscation notes
    sf = wd / "step8_obfuscation.json"
    if sf.exists():
        data = json.loads(sf.read_text())
        print(f"  Obfuscation score: {data.get('obfuscation_score')}", file=sys.stderr)
        print(f"  Obfuscation level: {data.get('obfuscation_level')}", file=sys.stderr)
        notes = data.get("notes", "")
        if notes:
            print(f"  Notes: {notes[:300]}", file=sys.stderr)
