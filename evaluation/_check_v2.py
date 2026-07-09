"""Check new pipeline_result.json structure."""
import json, os

work = r'analysis/work'
dirs = sorted([d for d in os.listdir(work) if os.path.isdir(os.path.join(work, d))])

# Check llm_assessment structure
for d in dirs:
    pr_file = os.path.join(work, d, 'pipeline_result.json')
    if not os.path.isfile(pr_file):
        continue
    pr = json.load(open(pr_file))
    llm = pr.get('llm_assessment') or {}
    print(f'{d[:16]}.. risk={llm.get("risk_score")} sev={llm.get("severity")} keys={list(llm.keys())}')
    break  # just one sample
