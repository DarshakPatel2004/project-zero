"""
Diagnostic: measure CIRCL pDNS response sizes for our actual IPs and sample domains.
Run with: python -u diag_circl_sizes.py
"""
import csv
import json
import os
import re
import sys
import time
from pathlib import Path

# Load .env
for line in open('.env'):
    line = line.strip()
    if not line or line.startswith('#') or '=' not in line:
        continue
    k, v = line.split('=', 1)
    os.environ[k.strip()] = v.strip().strip('"').strip("'")

sys.path.insert(0, '.')
from backend.circl_client import CIRCLClient

WORK = Path('analysis/work')
TEMPLATE_RE = re.compile(r'%[sdif]')

def is_real_domain(d):
    if not d: return False
    if TEMPLATE_RE.search(d): return False
    if ' ' in d or '/' in d or ':' in d: return False
    return True

def is_public_ip(ip):
    if not ip: return False
    p = ip.split('.')
    if len(p) != 4: return False
    try: o = [int(x) for x in p]
    except ValueError: return False
    o0, o1 = o[0], o[1]
    if o0 == 10: return False
    if o0 == 172 and 16 <= o1 <= 31: return False
    if o0 == 192 and o1 == 168: return False
    if o0 == 127: return False
    if o0 == 169 and o1 == 254: return False
    if o0 == 0: return False
    if o0 >= 224: return False
    return True

# Collect the 15 public IPs and a sample of 10 unenriched domains
samples = list(csv.DictReader(open('sample_metadata.csv', encoding='utf-8')))
ips = set()
domains = set()
for s in samples:
    f = WORK / s['sha256'] / 'step5_c2s.json'
    if not f.exists(): continue
    d = json.load(open(f))
    for c in d.get('c2_infrastructure', []):
        circl = c.get('circl') or {}
        ip = c.get('ip'); dom = c.get('domain')
        if ip and is_public_ip(ip) and not circl:
            ips.add(ip)
        if dom and is_real_domain(dom) and not circl:
            domains.add(dom)

ips = sorted(ips)
domains_sample = sorted(domains)[:10]  # just 10 for diagnosis

print(f"Found {len(ips)} public IPs, sampling {len(domains_sample)} of {len(domains)} unenriched domains\n", flush=True)

client = CIRCLClient()

# Test each IP with both rrtype=None and rrtype='A'
print("=" * 70, flush=True)
print("IP pDNS: rrtype=None vs rrtype='A'", flush=True)
print("=" * 70, flush=True)
print(f"{'IP':18s} {'rrtype=None':>20s} {'rrtype=A':>15s} {'records':>8s}", flush=True)
print("-" * 70, flush=True)
for ip in ips:
    # rrtype=None
    t0 = time.time()
    try:
        r = client.pdns_query(ip, rrtype=None, paginate_count=50, auto_paginate=False)
        elapsed_none = time.time() - t0
        cnt_none = r.get('count', 0)
        size_none = len(json.dumps(r))
    except Exception as e:
        elapsed_none = time.time() - t0
        cnt_none = -1
        size_none = 0
        r = {'error': str(e)}

    t0 = time.time()
    try:
        rA = client.pdns_query(ip, rrtype='A', paginate_count=50, auto_paginate=False)
        elapsed_A = time.time() - t0
        cnt_A = rA.get('count', 0)
        size_A = len(json.dumps(rA))
    except Exception as e:
        elapsed_A = time.time() - t0
        cnt_A = -1
        size_A = 0
        rA = {'error': str(e)}

    print(f"{ip:18s} {size_none:>15d}B/{elapsed_none:>4.1f}s {size_A:>10d}B/{elapsed_A:>3.1f}s {cnt_A:>8d}", flush=True)

# Test sample domains
print("\n" + "=" * 70, flush=True)
print(f"Domain pDNS (rrtype='A', paginate=50): first {len(domains_sample)}", flush=True)
print("=" * 70, flush=True)
print(f"{'Domain':50s} {'bytes':>10s} {'records':>8s} {'time':>6s}", flush=True)
print("-" * 70, flush=True)
for dom in domains_sample:
    t0 = time.time()
    try:
        r = client.pdns_query(dom, rrtype='A', paginate_count=50, auto_paginate=False)
        elapsed = time.time() - t0
        cnt = r.get('count', 0)
        size = len(json.dumps(r))
    except Exception as e:
        elapsed = time.time() - t0
        cnt = -1
        size = 0
        r = {'error': str(e)}
    print(f"{dom[:50]:50s} {size:>10d} {cnt:>8d} {elapsed:>5.1f}s", flush=True)
