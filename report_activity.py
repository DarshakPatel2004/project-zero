"""
Check what we've got so far from Live DNS (complete) and partial CIRCL pDNS.
"""
import csv, json, os, socket, sys, time
from collections import defaultdict
from pathlib import Path
from concurrent.futures import ThreadPoolExecutor, as_completed

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
        all_c2s.append({**c2, 'sample_sha256': sid, 'package_name': s.get('package_name', '')})

domains = set(c2.get('domain') for c2 in all_c2s if c2.get('domain'))

# --- Live DNS ---
def resolve(domain):
    try:
        socket.setdefaulttimeout(3)
        addrs = socket.getaddrinfo(domain, 80, socket.AF_INET)
        ips = list(set(a[4][0] for a in addrs))
        return domain, {'resolves': True, 'ips': ips}
    except Exception as e:
        return domain, {'resolves': False, 'error': str(e)[:60]}

print("=== LIVE DNS (running fresh) ===")
live_dns = {}
with ThreadPoolExecutor(max_workers=20) as pool:
    futmap = {pool.submit(resolve, d): d for d in domains}
    for f in as_completed(futmap):
        d, r = f.result()
        live_dns[d] = r

resolved = [d for d,v in live_dns.items() if v['resolves']]
dead = [d for d,v in live_dns.items() if not v['resolves']]
print(f"Total unique domains: {len(domains)}")
print(f"Resolve (active):     {len(resolved)} ({len(resolved)*100//len(domains)}%)")
print(f"NXDOMAIN (dead):      {len(dead)} ({len(dead)*100//len(domains)}%)")
print()

# Map to C2s
c2_by_domain = defaultdict(list)
for c2 in all_c2s:
    d = c2.get('domain')
    if d: c2_by_domain[d].append(c2)

print(f"{'Status':10s} {'Count':6s}")
print("-" * 20)
live_ips = sum(1 for c2 in all_c2s if live_dns.get(c2.get('domain'),{}).get('resolves'))
dead_c2s = len(all_c2s) - live_ips
print(f"{'Alive':10s} {live_ips:6d}")
print(f"{'Dead':10s} {dead_c2s:6d}")
print()

# Top 10 most-used resolving domains
print("=== Top resolving C2 domains by usage ===")
dom_counts = defaultdict(int)
for c2 in all_c2s:
    d = c2.get('domain')
    if d and live_dns.get(d,{}).get('resolves'):
        dom_counts[d] += 1
for d, cnt in sorted(dom_counts.items(), key=lambda x:-x[1])[:15]:
    ips = ', '.join(live_dns[d].get('ips',[])[:3])
    print(f"  {cnt:3d}x {d:45s} -> {ips}")

# Per-sample breakdown
print(f"\n=== Per-sample breakdown ===")
ss = defaultdict(lambda: {'total':0, 'alive':0, 'dead':0, 'pct':0.0})
for c2 in all_c2s:
    pkg = c2.get('package_name', c2.get('sample_sha256','')[:16])
    d = c2.get('domain')
    ss[pkg]['total'] += 1
    if d and live_dns.get(d,{}).get('resolves'):
        ss[pkg]['alive'] += 1
    else:
        ss[pkg]['dead'] += 1
for pkg in ss:
    ss[pkg]['pct'] = ss[pkg]['alive']/max(ss[pkg]['total'],1)*100

print(f"{'Package':35s} {'Total':6s} {'Alive':6s} {'Dead':6s} {'Alive%':7s}")
print("-" * 65)
for pkg in sorted(ss.keys()):
    s = ss[pkg]
    print(f"{pkg[:35]:35s} {s['total']:6d} {s['alive']:6d} {s['dead']:6d} {s['pct']:6.1f}%")

# CIRCL pDNS — check what's cached or partially done
print(f"\n=== CIRCL pDNS status ===")
print("(not saved to disk — script was aborted mid-run)")
print(f"Domains queried before abort: ~115/287")
print("Need to re-run pDNS from scratch or continue where we left off")
