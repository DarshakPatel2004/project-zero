"""
C2 activity check: live DNS + CIRCL pDNS with live progress.
"""
import csv, json, os, socket, sys, time
from collections import defaultdict
from pathlib import Path
from concurrent.futures import ThreadPoolExecutor, as_completed
import math

for line in open('.env'):
    line = line.strip()
    if not line or line.startswith('#') or '=' not in line: continue
    k, v = line.split('=', 1)
    os.environ[k.strip()] = v.strip().strip('"').strip("'")

sys.path.insert(0, '.')
from backend.circl_client import CIRCLClient

WORK_DIR = Path('analysis/work')

samples = []
with open('sample_metadata.csv', encoding='utf-8') as f:
    for row in csv.DictReader(f): samples.append(row)

all_c2s = []
for s in samples:
    sid = s['sha256']
    fp = WORK_DIR / sid / 'step5_c2s.json'
    if not fp.exists(): continue
    with open(fp) as f: step5 = json.load(f)
    for c2 in step5.get('c2_infrastructure', []):
        all_c2s.append({**c2, 'sample_sha256': sid, 'package_name': s.get('package_name', s.get('sha256', sid[:16]))})

domains = sorted(set(c2.get('domain') for c2 in all_c2s if c2.get('domain')))
print(f"Total C2s: {len(all_c2s)}, unique domains: {len(domains)}")

# --- LIVE DNS ---
def resolve(domain):
    try:
        socket.setdefaulttimeout(3)
        addrs = socket.getaddrinfo(domain, 80, socket.AF_INET)
        ips = list(set(a[4][0] for a in addrs))
        return domain, {'resolves': True, 'ips': ips}
    except Exception as e:
        return domain, {'resolves': False, 'error': str(e)[:60]}

print("\n>>> LIVE DNS <<<")
start = time.time()
live_dns = {}
with ThreadPoolExecutor(max_workers=20) as pool:
    futmap = {pool.submit(resolve, d): d for d in domains}
    for f in as_completed(futmap):
        d, r = f.result()
        live_dns[d] = r

live_count = sum(1 for v in live_dns.values() if v['resolves'])
dead_count = len(domains) - live_count
print(f"  {live_count} resolve, {dead_count} dead  [{time.time()-start:.1f}s]")

# --- CIRCL pDNS ---
print(f"\n>>> CIRCL pDNS ({len(domains)} domains, ~{len(domains)*3//60} min with rate limit) <<<")
# Resume from cache if exists
CACHE_FILE = WORK_DIR / 'circl_pdns_cache.json'
pdns_cache = {}
if CACHE_FILE.exists():
    with open(CACHE_FILE) as f:
        pdns_cache = json.load(f)
    print(f"  Resuming from cache ({len(pdns_cache)} domains already done)")

client = CIRCLClient()
domains_remaining = [d for d in domains if d not in pdns_cache]
start = time.time()
i = len(pdns_cache)

while domains_remaining:
    d = domains_remaining.pop(0)
    i += 1
    t0 = time.time()
    try:
        pdns_cache[d] = client.pdns_query(d, rrtype='A', paginate_count=50, auto_paginate=False)
    except Exception as e:
        pdns_cache[d] = {'error': str(e)[:60]}
    
    elapsed = time.time() - start
    rate = i / elapsed
    remaining = len(domains_remaining) / rate if rate > 0 else 0
    
    pdns_hit = pdns_cache[d].get('count', 0) > 0 if 'count' in pdns_cache[d] else False
    
    # Persist cache every 10 domains for resume safety
    if i % 10 == 0:
        with open(CACHE_FILE, 'w') as f:
            json.dump(pdns_cache, f)
    
    status_icon = '+' if pdns_hit else '-'
    live_icon = '+' if live_dns.get(d, {}).get('resolves') else '-'
    
    print(f"  [{i:3d}/{len(domains)}] {d:45s} pdns={status_icon} dns={live_icon}  |  {elapsed:4.0f}s elapsed, ~{remaining:4.0f}s remain", flush=True)

# Final cache save
with open(CACHE_FILE, 'w') as f:
    json.dump(pdns_cache, f)
elapsed = time.time() - start
print(f"  Done in {elapsed:.0f}s")

# --- CLASSIFY ---
print(f"\n>>> Classifying {len(all_c2s)} C2s...")
for c2 in all_c2s:
    domain = c2.get('domain')
    c2['live_dns'] = live_dns.get(domain, {'resolves': False, 'ips': [], 'error': 'no domain'})
    circl = {}
    if domain and domain in pdns_cache:
        circl['pdns_domain'] = pdns_cache[domain]
    c2['circl'] = circl
    live = c2['live_dns'].get('resolves', False)
    pdns_hit = circl.get('pdns_domain', {}).get('count', 0) > 0
    if live and pdns_hit:       c2['status'] = 'active'
    elif live and not pdns_hit: c2['status'] = 'likely_active'
    elif not live and pdns_hit: c2['status'] = 'historical'
    else:                       c2['status'] = 'dead'

# --- SUMMARY ---
sc = defaultdict(int)
for c2 in all_c2s: sc[c2['status']] += 1

ss = defaultdict(lambda: defaultdict(int))
for c2 in all_c2s:
    p = c2.get('package_name', '?')
    ss[p][c2['status']] += 1
    ss[p]['total'] += 1

print("\n" + "=" * 70)
print("C2 ACTIVITY ASSESSMENT")
print("=" * 70)
print(f"{'Status':20s} {'Count':7s}  {'Meaning'}")
print("-" * 60)
print(f"{'active':20s} {sc['active']:7d}  Resolves now + in CIRCL pDNS history")
print(f"{'likely_active':20s} {sc['likely_active']:7d}  Resolves now, NOT in pDNS")
print(f"{'historical':20s} {sc['historical']:7d}  In pDNS history, currently down")
print(f"{'dead':20s} {sc['dead']:7d}  Neither resolves nor in pDNS")
print(f"{'TOTAL':20s} {len(all_c2s):7d}")
print()

print(f"{'Package':35s} {'Tot':5s} {'Act':5s} {'LkA':5s} {'Hist':5s} {'Dead':5s}")
print("-" * 65)
for pkg in sorted(ss.keys()):
    s = ss[pkg]
    print(f"{pkg[:35]:35s} {s['total']:5d} {s['active']:5d} {s['likely_active']:5d} {s['historical']:5d} {s['dead']:5d}")

# Show resolving C2s
active_list = [c2 for c2 in all_c2s if c2['status'] in ('active', 'likely_active')]
print(f"\n=== Live-resolving C2s ({len(active_list)}) ===")
for c2 in sorted(active_list, key=lambda x: x.get('domain', ''))[:40]:
    d = c2.get('domain', '')
    ip = c2.get('ip', '')
    ips = ', '.join(c2['live_dns'].get('ips', [])[:3])
    st = c2['status']
    pkg = c2.get('package_name', '')[:20]
    print(f"  [{st:14s}] {d:40s} -> {ips:30s} ({pkg})")

# Save
c2_by_sid = defaultdict(list)
for c2 in all_c2s: c2_by_sid[c2['sample_sha256']].append(c2)
for sid, enriched in c2_by_sid.items():
    for fn in ['step5_c2s.json', 'pipeline_result.json']:
        fp = WORK_DIR / sid / fn
        if fp.exists():
            with open(fp) as f: data = json.load(f)
            data['c2_infrastructure'] = enriched
            with open(fp, 'w') as f: json.dump(data, f, indent=2)

summary = {
    'total_c2s': len(all_c2s), 'status_counts': dict(sc),
    'active': sc.get('active',0), 'likely_active': sc.get('likely_active',0),
    'historical': sc.get('historical',0), 'dead': sc.get('dead',0),
    'per_sample': {pkg: dict(s) for pkg, s in ss.items()}
}
with open(WORK_DIR / 'circl_summary.json', 'w') as f: json.dump(summary, f, indent=2)
print(f"\nSaved to analysis/work/circl_summary.json")
