"""Quick check: look at structure of pipeline_result.json files."""
import json, os

work = r'analysis/work'
dirs = sorted([d for d in os.listdir(work) if os.path.isdir(os.path.join(work, d))])
print(f'Total work dirs: {len(dirs)}')

pr_count = sum(1 for d in dirs if os.path.isfile(os.path.join(work, d, 'pipeline_result.json')))
fm_count = sum(1 for d in dirs if os.path.isfile(os.path.join(work, d, 'family.json')))
print(f'With pipeline_result.json: {pr_count}')
print(f'With family.json: {fm_count}')

# Check a few samples
checked = 0
for d in dirs:
    pr_file = os.path.join(work, d, 'pipeline_result.json')
    if not os.path.isfile(pr_file):
        continue
    pr = json.load(open(pr_file))
    keys = list(pr.keys())
    sev = pr.get('overall_severity', 'MISSING')
    llm = pr.get('llm_assessment') or {}
    rs = llm.get('risk_score', 'MISSING')
    print(f'{d[:16]}.. sev={sev} risk={rs} keys={keys}')
    checked += 1
    if checked >= 10:
        break
