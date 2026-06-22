"""
Test CIRCL credentials and check which C2s are active.
"""
import json
import os

# Load .env
for line in open('.env'):
    line = line.strip()
    if not line or line.startswith('#') or '=' not in line:
        continue
    k, v = line.split('=', 1)
    os.environ[k.strip()] = v.strip().strip('"').strip("'")

from backend.circl_client import test_credentials, enrich_c2s

# Step 1: Test credentials
print("=== Testing CIRCL credentials ===")
result = test_credentials()
print(f"pSSL ok: {result['pssl'].get('ok')}")
print(f"pDNS ok: {result['pdns'].get('ok')}")
if not result['pssl'].get('ok'):
    print(f"pSSL error: {result['pssl'].get('error')}")
if not result['pdns'].get('ok'):
    print(f"pDNS error: {result['pdns'].get('error')}")

c2_list = [
    {"ip": "8.8.8.8", "domain": "google.com"},
    {"ip": "1.1.1.1", "domain": "cloudflare.com"},
]

print("\n=== Testing quick enrichment ===")
enriched = enrich_c2s(c2_list, include_pdns=True, include_pssl=True)
for c2 in enriched:
    circl = c2.get('circl', {})
    pdns = circl.get('pdns_domain', {})
    pssl = circl.get('pssl_ip', {})
    print(f"\n{c2['domain']} ({c2['ip']}):")
    print(f"  pDNS records: {pdns.get('count', 'error')}")
    print(f"  pSSL ok: {'subjects' in pssl or 'certificates' in pssl}")
