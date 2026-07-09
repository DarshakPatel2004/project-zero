"""Deep dive: BaseBridge — confirm ad-fraud signals exist but were not correlated."""
import json, sys
from pathlib import Path

h = "54f2a636e000c55bb725d7e552a22117837c1676fb4b96decd135ae10e6f7049"
wd = Path(f"analysis/work/{h}")

pr = json.loads((wd / "pipeline_result.json").read_text())
strs = json.loads((wd / "step2_strings.json").read_text())

# 1. Look at ALL string_literals for C2-like / URL-like patterns
cats = strs.get("categories", {})
literals = cats.get("string_literals", [])
print(f"Total string_literals: {len(literals)}", file=sys.stderr)

# Check for URLs, C2 patterns, SMS-related, phone-related
urls = []
sms = []
phone = []
crypto = []
reflection = []
native_libs = []
other_suspicious = []

keywords = {
    "url": ["http", "https", "www.", ".com", ".net", ".org", "://"],
    "sms": ["sms", "SMS", "message", "send", "MMS"],
    "phone": ["phone", "PHONE", "call", "dial", "telephone", "number"],
    "crypto": ["AES", "DES", "RSA", "Blowfish", "Cipher", "SecretKey", "encrypt"],
    "reflection": ["Class.forName", "getMethod", "invoke", "getDeclared", "loadClass", "DexClassLoader"],
}

for lit in literals:
    val = lit.get("value", "")
    src = lit.get("source", "")
    if isinstance(val, str):
        for kw in keywords["url"]:
            if kw.lower() in val.lower():
                urls.append((val, src))
                break
    if isinstance(val, str):
        for kw in keywords["sms"]:
            if kw.lower() in val.lower():
                sms.append((val, src))
                break
    if isinstance(val, str):
        for kw in keywords["phone"]:
            if kw.lower() in val.lower():
                phone.append((val, src))
                break
    if isinstance(val, str):
        for kw in keywords["crypto"]:
            if kw.lower() in val.lower():
                crypto.append((val, src))
                break
    if isinstance(val, str):
        for kw in keywords["reflection"]:
            if kw.lower() in val.lower():
                reflection.append((val, src))
                break

print(f"\nURL-like strings: {len(urls)}", file=sys.stderr)
for v, s in urls[:20]:
    print(f"  {v[:100]}  ({s})", file=sys.stderr)

print(f"\nSMS-related strings: {len(sms)}", file=sys.stderr)
for v, s in sms[:10]:
    print(f"  {v[:100]}  ({s})", file=sys.stderr)

print(f"\nPhone/call-related strings: {len(phone)}", file=sys.stderr)
for v, s in phone[:10]:
    print(f"  {v[:100]}  ({s})", file=sys.stderr)

print(f"\nCrypto strings: {len(crypto)}", file=sys.stderr)
for v, s in crypto[:10]:
    print(f"  {v[:100]}  ({s})", file=sys.stderr)

print(f"\nReflection strings: {len(reflection)}", file=sys.stderr)
for v, s in reflection[:10]:
    print(f"  {v[:100]}  ({s})", file=sys.stderr)

# 2. Native library info
nat = cats.get("native_strings", [])
print(f"\nNative strings: {len(nat)}", file=sys.stderr)
for n in nat[:10]:
    print(f"  lib={n.get('source','?')}  func={n.get('value','')[:80]}", file=sys.stderr)

# 3. Check what obfuscation analysis found
obf = json.loads((wd / "step8_obfuscation.json").read_text())
print(f"\nObfuscation indicators:", file=sys.stderr)
for ind in obf.get("indicators", []):
    print(f"  {json.dumps(ind, ensure_ascii=False)[:150]}", file=sys.stderr)

# 4. Check metadata for native lib count
meta = pr.get("metadata", {})
print(f"\nMetadata:", file=sys.stderr)
print(f"  File size: {meta.get('file_size', '?')}", file=sys.stderr)
print(f"  Class count: {meta.get('class_count', '?')}", file=sys.stderr)
print(f"  Native lib count: {meta.get('native_lib_count', '?')}", file=sys.stderr)
print(f"  Package: {meta.get('package_name', '?')}", file=sys.stderr)
