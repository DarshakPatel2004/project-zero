"""
Enrich C2s with CIRCL - deduplicated by unique IPs and domains for efficiency.

Skips IPs/domains already enriched (have a 'circl' field) so re-runs only
query what is missing.
"""
import csv
import json
import os
import re
import sys
from collections import defaultdict
from pathlib import Path

# Load .env
for line in open('.env'):
    line = line.strip()
    if not line or line.startswith('#') or '=' not in line:
        continue
    k, v = line.split('=', 1)
    os.environ[k.strip()] = v.strip().strip('"').strip("'")

sys.path.insert(0, '.')
from backend.circl_client import CIRCLClient as CIRCLClientOrig

WORK_DIR = Path('analysis/work')

# Filter template-string domains (e.g. "%sadrevenue.%s", "%1$s") - these are not real C2s
TEMPLATE_RE = re.compile(r'%')

def is_real_domain(d):
    if not d:
        return False
    if TEMPLATE_RE.search(d):
        return False
    # Must look like a real hostname with at least 2 labels, each >= 2 chars
    if ' ' in d or '/' in d or ':' in d:
        return False
    labels = d.split('.')
    if len(labels) < 2:
        return False
    if any(len(label) < 2 for label in labels):
        return False
    return True

def is_public_ip(ip):
    """Skip RFC1918 private, loopback, link-local, and reserved IPs."""
    if not ip:
        return False
    parts = ip.split('.')
    if len(parts) != 4:
        return False
    try:
        octets = [int(p) for p in parts]
    except ValueError:
        return False
    o0, o1 = octets[0], octets[1]
    if o0 == 10:                                  # 10.0.0.0/8
        return False
    if o0 == 172 and 16 <= o1 <= 31:              # 172.16.0.0/12
        return False
    if o0 == 192 and o1 == 168:                   # 192.168.0.0/16
        return False
    if o0 == 127:                                 # loopback
        return False
    if o0 == 169 and o1 == 254:                   # link-local
        return False
    if o0 == 0:                                   # 0.0.0.0/8
        return False
    if o0 >= 224:                                 # multicast + reserved
        return False
    return True

# Step 1: Collect all unique IPs and domains from all samples
samples = []
with open('sample_metadata.csv', encoding='utf-8') as f:
    for row in csv.DictReader(f):
        samples.append(row)

all_c2_by_sample = {}
unique_ips = set()
unique_domains = set()
skipped_ips = set()
skipped_domains = set()
filtered_template_domains = set()
filtered_private_ips = set()

for s in samples:
    sid = s['sha256']
    step5_file = WORK_DIR / sid / 'step5_c2s.json'
    if not step5_file.exists():
        continue
    with open(step5_file) as f:
        step5 = json.load(f)
    c2s = step5.get('c2_infrastructure', [])
    if not c2s:
        continue
    all_c2_by_sample[sid] = c2s
    for c2 in c2s:
        ip = c2.get('ip')
        domain = c2.get('domain')
        url = c2.get('url', '')
        circl = c2.get('circl') or {}
        already_enriched = bool(circl)
        if ip:
            if already_enriched:
                skipped_ips.add(ip)
            elif not is_public_ip(ip):
                filtered_private_ips.add(ip)
            else:
                unique_ips.add(ip)
        if domain:
            if not is_real_domain(domain):
                filtered_template_domains.add(domain)
            elif already_enriched:
                skipped_domains.add(domain)
            else:
                unique_domains.add(domain)

print(f"Total C2s across all samples: {sum(len(v) for v in all_c2_by_sample.values())}")
print(f"Unique IPs needing query:     {len(unique_ips)}  (skipped {len(skipped_ips)} already-enriched, {len(filtered_private_ips)} private/reserved filtered)")
print(f"Unique domains needing query: {len(unique_domains)}  (skipped {len(skipped_domains)} already-enriched, {len(filtered_template_domains)} template-strings filtered)")

# Step 2: Query CIRCL for each unique IP and domain
client = CIRCLClientOrig()

ip_cache = {}
domain_cache = {}

def query_ip(ip):
    if ip in ip_cache:
        return ip_cache[ip]
    result = {}
    try:
        result['pssl'] = client.pssl_query_ip(ip)
    except Exception as e:
        result['pssl_error'] = str(e)
    try:
        pdns = client.pdns_query(ip, rrtype='A', paginate_count=50, auto_paginate=False)
        result['pdns'] = pdns
    except Exception as e:
        result['pdns_error'] = str(e)
    ip_cache[ip] = result
    return result

def query_domain(domain):
    if domain in domain_cache:
        return domain_cache[domain]
    result = {}
    try:
        pdns = client.pdns_query(domain, rrtype='A', paginate_count=50, auto_paginate=False)
        result['pdns'] = pdns
    except Exception as e:
        result['pdns_error'] = str(e)
    domain_cache[domain] = result
    return result

print(f"\nQuerying {len(unique_ips)} unique IPs (pSSL + pDNS)...", flush=True)
for i, ip in enumerate(sorted(unique_ips)):
    query_ip(ip)
    print(f"\r  IPs: {i+1}/{len(unique_ips)} ({ip})", end='', flush=True)
print(flush=True)

print(f"\nQuerying {len(unique_domains)} unique domains (pDNS)...", flush=True)
for i, domain in enumerate(sorted(unique_domains)):
    query_domain(domain)
    print(f"\r  Domains: {i+1}/{len(unique_domains)} ({domain[:40]})", end='', flush=True)
print(flush=True)

# Step 3: Apply cached results back to each sample's C2s
total_active = 0
total_c2s = 0
per_sample = []

for sid, c2s in all_c2_by_sample.items():
    active_count = 0
    error_count = 0
    enriched_c2s = []
    for c2 in c2s:
        c2 = dict(c2)
        ip = c2.get('ip')
        domain = c2.get('domain')
        # Preserve existing circl data; merge new fields on top
        circl = dict(c2.get('circl') or {})

        if ip:
            cached = ip_cache.get(ip, {})
            if 'pssl' in cached:
                circl['pssl_ip'] = cached['pssl']
            if 'pssl_error' in cached:
                circl['pssl_ip_error'] = cached['pssl_error']
            if 'pdns' in cached:
                circl['pdns_ip'] = cached['pdns']
            if 'pdns_error' in cached:
                circl['pdns_ip_error'] = cached['pdns_error']
            # Mark private/reserved IPs as skipped so downstream sees we considered them
            if not is_public_ip(ip):
                circl['skipped_reason'] = 'private_or_reserved_ip'

        if domain and is_real_domain(domain):
            cached = domain_cache.get(domain, {})
            if 'pdns' in cached:
                circl['pdns_domain'] = cached['pdns']
            if 'pdns_error' in cached:
                circl['pdns_domain_error'] = cached['pdns_error']

        c2['circl'] = circl
        enriched_c2s.append(c2)
        
        # Assess active/dead
        pdns_domain = circl.get('pdns_domain', {})
        pdns_ip = circl.get('pdns_ip', {})
        has_pdns = pdns_domain.get('count', 0) > 0 or pdns_ip.get('count', 0) > 0
        has_error = bool(circl.get('pdns_domain_error') or circl.get('pdns_ip_error'))
        
        if has_error:
            error_count += 1
        elif has_pdns:
            active_count += 1
    
    total_c2s += len(enriched_c2s)
    total_active += active_count
    
    # Update both files
    for fn in ['step5_c2s.json', 'pipeline_result.json']:
        fp = WORK_DIR / sid / fn
        if fp.exists():
            with open(fp) as f:
                data = json.load(f)
            data['c2_infrastructure'] = enriched_c2s
            with open(fp, 'w') as f:
                json.dump(data, f, indent=2)
    
    sample_name = next((s.get('sample_name') or s.get('package_name') or sid[:16] for s in samples if s['sha256'] == sid), sid[:16])
    per_sample.append({
        'sha256': sid,
        'package_name': sample_name,
        'total_c2s': len(enriched_c2s),
        'active': active_count,
        'inactive': len(enriched_c2s) - active_count - error_count,
        'errors': error_count,
    })
    
    pct = (active_count / max(len(enriched_c2s), 1)) * 100
    print(f"{sample_name[:35]:35s} {len(enriched_c2s):4d} C2s, active: {active_count:4d} ({pct:5.1f}%)")

print("\n" + "=" * 70)
print("CIRCL ENRICHMENT — FINAL SUMMARY")
print("=" * 70)
print(f"Total C2s: {total_c2s}")
print(f"Active (recent pDNS): {total_active}")
print(f"Dead/Unresolved: {total_c2s - total_active}")
print(f"Active rate: {(total_active/max(total_c2s,1))*100:.1f}%")
print()

# Table
print(f"{'Package':30s} {'C2s':5s} {'Active':7s} {'Dead':7s} {'Active%':8s}")
print("-" * 60)
for r in sorted(per_sample, key=lambda x: -x['active']):
    pct = (r['active'] / max(r['total_c2s'], 1)) * 100
    print(f"{r['package_name'][:30]:30s} {r['total_c2s']:5d} {r['active']:7d} {r['total_c2s']-r['active']:7d} {pct:7.1f}%")
print("-" * 60)

# Save summary
summary = {
    'total_c2s': total_c2s,
    'active_c2s': total_active,
    'inactive_c2s': total_c2s - total_active,
    'cache_stats': {
        'unique_ips': len(unique_ips),
        'unique_domains': len(unique_domains),
    },
    'per_sample': per_sample,
}
with open(WORK_DIR / 'circl_summary.json', 'w') as f:
    json.dump(summary, f, indent=2)
print(f"\nSummary saved to analysis/work/circl_summary.json")
