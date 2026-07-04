import json
from pathlib import Path
from collections import Counter

wd = Path('D:/DroidForensix/analysis/work')
sevs = Counter()
methods = Counter()

for d in sorted(wd.iterdir()):
    if not d.is_dir():
        continue
    p = d / 'step7_assessment.json'
    if not p.exists():
        continue
    try:
        r = json.loads(p.read_text(encoding='utf-8'))
        s = r.get('severity', r.get('threat_level', 'unknown'))
        sevs[s] += 1

        raw = r.get('raw_llm_output', '')
        method = r.get('method', '')
        if method:
            methods[method] += 1
        elif raw and len(raw) > 50 and 'error' not in raw.lower()[:100]:
            methods['llm'] += 1
        else:
            methods['unknown'] += 1
    except Exception:
        methods['error'] += 1

total = sum(sevs.values())
print(f'Total samples: {total}')
print()
print('Method attribution:')
for m, c in methods.most_common():
    print(f'  {m}: {c} ({100*c/total:.1f}%)')
print()
print('Severity distribution:')
for s in ['critical', 'high', 'medium', 'low']:
    print(f'  {s}: {sevs[s]} ({100*sevs[s]/total:.1f}%)')
