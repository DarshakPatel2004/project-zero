"""
C2 Classification + Geo-map + Blocklist + HTML Dashboard.
Reads enriched C2 data (live_dns + circl + status) and produces final outputs.
"""
import csv, json, os, socket, sys, time
from collections import defaultdict
from datetime import datetime
from pathlib import Path
from concurrent.futures import ThreadPoolExecutor, as_completed

WORK_DIR = Path('analysis/work')

# --- Whitelist of known benign SDK/ad domains ---
BENIGN_SDK_DOMAINS = {
    # Google / AdMob
    'admob.com', 'www.admob.com', 'a.admob.com', 'media.admob.com', 'e.admob.com',
    'googleads.g.doubleclick.net', 'doubleclick.net', 'googleadservices.com',
    'www.googleadservices.com', 'pagead2.googlesyndication.com',
    'googlesyndication.com', 'google-analytics.com', 'www.google-analytics.com',
    'ssl.google-analytics.com', 'analytics.google.com',
    # Google APIs
    'maps.googleapis.com', 'maps.google.com', 'ditu.google.cn',
    'www.googleapis.com', 'android.clients.google.com',
    # Facebook
    'facebook.com', 'www.facebook.com', 'api.facebook.com', 'apps.facebook.com',
    'graph.facebook.com', 'connect.facebook.net',
    # Amazon
    'amazon-adsystem.com', 's3.amazonaws.com', 'aws.amazon.com',
    # Ad networks
    'applovin.com', 'a.applovin.com', 'd.applovin.com',
    'flurry.com', 'data.flurry.com', 'cdn.flurry.com', 'adlog.flurry.com', 'ads.flurry.com',
    'vungle.com', 'api.vungle.com',
    'tapjoy.com', 'connect.tapjoy.com',
    'appodeal.com', 'ach.appodeal.com', 'adwatch.appodeal.com',
    'startappexchange.com', 'www.startappexchange.com',
    'pubnative.net', 'api.pubnative.net',
    'inmobi.com', 'www.inmobi.com',
    'revmob.com', 'android.revmob.com',
    'mopub.com', 'analytics.mopub.com',
    'adcolony.com', 'androidads23.adcolony.com',
    'unity3d.com', 'cdn.unityads.unity3d.com',
    'avocarrot.com', 'ads.avocarrot.com',
    'rubiconproject.com', 'ads.rubiconproject.com',
    'leadbolt.net', 'ad.leadbolt.net',
    'mydas.mobi', 'ads.mp.mydas.mobi', 'cvt.mydas.mobi', 'androidsdk.ads.mp.mydas.mobi',
    'scoreloop.com', 'api.scoreloop.com', 'community.scoreloop.com',
    'openfeint.com', 'api.openfeint.com', 'ads.openfeint.com',
    'apptornado.com', 'applift-a.apptornado.com',
    'whalecloud.com', 'feedback.whalecloud.com',
    # Apple
    'apple.com', 'www.apple.com',
    'itunes.apple.com', 'phobos.apple.com',
    # Adobe
    'adobe.com', 'www.adobe.com', 'www.macromedia.com',
    'crl3.adobe.com', 'airdownload.adobe.com', 'airinstall.adobe.com',
    'air-linux-qe.corp.adobe.com',
    # Microsoft
    'microsoft.com', 'www.microsoft.com',
    'live.com', 'msn.com',
    # CDNs / Cloud
    'cloudfront.net', 'd1byvlfiet2h9q.cloudfront.net',
    'dwxjayoxbnyrr.cloudfront.net',
    'akamai.net', 'akamaihd.net',
    # Misc legitimate services
    'github.com', 'raw.githubusercontent.com',
    'curl.haxx.se', 'daneden.me',
    'tumblr.com', 'api.tumblr.com',
    'yahoo.com', 'www.yahoo.com',
}

# Suspicious indicators
SUSPICIOUS_TLDS = {'.tk', '.ml', '.ga', '.cf', '.gq', '.xyz', '.top', '.club', '.work', '.bid', '.date', '.win', '.men', '.loan'}
SUSPICIOUS_PORTS = {8080, 8443, 444, 6666, 6667, 6668, 6669, 7000, 7070, 8888, 9999, 31337, 1337, 4444, 5555, 9000, 10000}

def load_all_c2s():
    samples = []
    with open('sample_metadata.csv', encoding='utf-8') as f:
        for row in csv.DictReader(f): samples.append(row)
    
    all_c2s = []
    for s in samples:
        sid = s['sha256']
        fp = WORK_DIR / sid / 'step5_c2s.json'
        if not fp.exists(): continue
        with open(fp) as f: data = json.load(f)
        for c2 in data.get('c2_infrastructure', []):
            all_c2s.append({**c2, 'sha256': sid, 'package_name': s.get('family', sid[:16])})
    return all_c2s

def classify_c2(c2):
    """Return 'benign', 'suspicious', or 'malicious' with reasoning."""
    reasons = []
    domain = (c2.get('domain') or '').lower()
    ip = c2.get('ip') or ''
    port = c2.get('port') or 0
    path = c2.get('path') or ''
    protocol = c2.get('protocol') or ''
    live = c2.get('live_dns', {})
    circl = c2.get('circl', {})
    
    # Check whitelist
    if any(domain == d or domain.endswith('.' + d) for d in BENIGN_SDK_DOMAINS):
        return 'benign', 'whitelisted SDK domain'
    
    # Check for template/obfuscated domains (like '%s...')
    if '%' in domain or domain.startswith('__'):
        return 'malicious', 'template/obfuscated domain'
    
    # Check TLD
    domain_lower = domain.lower()
    for tld in SUSPICIOUS_TLDS:
        if domain_lower.endswith(tld):
            reasons.append(f'suspicious TLD: {tld}')
            break
    
    # Check port
    if port and int(port) in SUSPICIOUS_PORTS:
        reasons.append(f'unusual port: {port}')
    
    # Check protocol
    if protocol and protocol not in ('http', 'https'):
        reasons.append(f'unusual protocol: {protocol}')
    
    # Check live DNS
    if not live.get('resolves', False):
        reasons.append('NXDOMAIN')
    
    # Check pDNS
    pdns = circl.get('pdns_domain', {})
    pdns_count = pdns.get('count', 0) if isinstance(pdns, dict) else 0
    if pdns_count == 0 and live.get('resolves', False):
        reasons.append('no pDNS history (newly registered?)')
    
    # Check for IP-based (no domain)
    if not domain and ip:
        reasons.append('IP-direct C2 (no domain)')
    
    # Check path for suspicious patterns
    path_lower = path.lower()
    if any(kw in path_lower for kw in ['/admin', '/panel', '/gate', '/command', '/shell', '/exec', '/c2', '/bot', '/callback']):
        reasons.append(f'suspicious path: {path}')
    
    # Classification
    if len(reasons) >= 2:
        return 'malicious', '; '.join(reasons)
    elif len(reasons) == 1:
        return 'suspicious', '; '.join(reasons)
    else:
        return 'benign', 'clean indicator'

def geo_lookup(ip):
    """Lookup IP location via ip-api.com free API."""
    if not ip: return None
    try:
        import urllib.request
        url = f'http://ip-api.com/json/{ip}?fields=status,country,regionName,city,isp,org,as,query,lat,lon'
        resp = urllib.request.urlopen(url, timeout=5)
        data = json.loads(resp.read())
        if data.get('status') == 'success':
            return data
    except: pass
    return None

# ====== MAIN ======
print("Loading enriched C2 data...")
all_c2s = load_all_c2s()
print(f"  {len(all_c2s)} total C2s")

print("\n>>> Classifying C2s (benign vs suspicious vs malicious)...")
for c2 in all_c2s:
    label, reason = classify_c2(c2)
    c2['classification'] = label
    c2['classification_reason'] = reason

class_counts = defaultdict(int)
for c2 in all_c2s: class_counts[c2['classification']] += 1
print(f"  benign: {class_counts.get('benign', 0)}")
print(f"  suspicious: {class_counts.get('suspicious', 0)}")
print(f"  malicious: {class_counts.get('malicious', 0)}")

# Active C2s (resolve and classified as suspicious/malicious)
active_c2s = [c2 for c2 in all_c2s 
              if c2.get('live_dns', {}).get('resolves', False) 
              and c2.get('classification') in ('suspicious', 'malicious')]
print(f"\n  Active suspicious/malicious C2s: {len(active_c2s)}")

# Get unique IPs for geo
unique_ips = set(c2.get('ip') for c2 in active_c2s if c2.get('ip'))
live_ips = set()
for c2 in active_c2s:
    ips = c2.get('live_dns', {}).get('ips', [])
    for ip in ips: live_ips.add(ip)

all_geo_ips = unique_ips | live_ips
print(f"\n>>> Geo-locating {len(all_geo_ips)} unique IPs...")
geo_cache = {}
with ThreadPoolExecutor(max_workers=5) as pool:
    futmap = {pool.submit(geo_lookup, ip): ip for ip in all_geo_ips if ip}
    for f in as_completed(futmap):
        ip = futmap[f]
        result = f.result()
        geo_cache[ip] = result
        if result:
            print(f"  {ip:15s} -> {result.get('country','?')}, {result.get('regionName','?')} ({result.get('isp','?')})", flush=True)
        else:
            print(f"  {ip:15s} -> lookup failed", flush=True)

print(f"\n>>> Exporting blocklists...")
# CSV blocklist
with open(WORK_DIR / 'c2_blocklist.csv', 'w', newline='') as f:
    w = csv.writer(f)
    w.writerow(['classification', 'status', 'domain', 'ip', 'port', 'protocol', 'path', 'package_name', 'reason', 'resolved_ips'])
    for c2 in sorted(active_c2s, key=lambda x: x.get('domain','')):
        ips = ', '.join(c2.get('live_dns', {}).get('ips', []))
        w.writerow([
            c2.get('classification',''),
            c2.get('status',''),
            c2.get('domain',''),
            c2.get('ip',''),
            c2.get('port',''),
            c2.get('protocol',''),
            c2.get('path',''),
            c2.get('package_name',''),
            c2.get('classification_reason',''),
            ips
        ])
print(f"  CSV blocklist: analysis/work/c2_blocklist.csv ({len(active_c2s)} entries)")

# STIX-like JSON blocklist
stix = {
    "type": "bundle",
    "id": f"bundle--{datetime.utcnow().strftime('%Y%m%d%H%M%S')}",
    "objects": []
}
for c2 in active_c2s:
    domain = c2.get('domain','')
    ip = c2.get('ip','')
    indicator = {
        "type": "indicator",
        "id": f"indicator--{c2.get('sha256','')[:16]}-{c2.get('c2_id','unknown')}",
        "created": datetime.utcnow().strftime('%Y-%m-%dT%H:%M:%SZ'),
        "name": domain or ip,
        "pattern": f"[domain-name:value = '{domain}']" if domain else f"[ipv4-addr:value = '{ip}']",
        "valid_from": datetime.utcnow().strftime('%Y-%m-%dT%H:%M:%SZ'),
        "labels": [c2.get('classification',''), c2.get('status',''), 'c2'],
    }
    stix["objects"].append(indicator)
with open(WORK_DIR / 'c2_blocklist_stix.json', 'w') as f:
    json.dump(stix, f, indent=2)
print(f"  STIX blocklist: analysis/work/c2_blocklist_stix.json ({len(stix['objects'])} objects)")

# ====== Save enriched data ======
print(f"\n>>> Updating result files...")
c2_by_sid = defaultdict(list)
for c2 in all_c2s: c2_by_sid[c2.get('sha256')].append(c2)
for sid, enriched in c2_by_sid.items():
    for fn in ['step5_c2s.json', 'pipeline_result.json']:
        fp = WORK_DIR / sid / fn
        if fp.exists():
            with open(fp) as f: data = json.load(f)
            data['c2_infrastructure'] = enriched
            data['c2_classification_summary'] = dict(class_counts)
            with open(fp, 'w') as f: json.dump(data, f, indent=2)

# Save geo data
with open(WORK_DIR / 'c2_geo.json', 'w') as f:
    json.dump(geo_cache, f, indent=2)
print(f"  Geo data: analysis/work/c2_geo.json ({sum(1 for v in geo_cache.values() if v)} located)")

# ====== HTML Dashboard ======
print(f"\n>>> Building HTML dashboard...")

# Per-sample stats
per_sample = defaultdict(lambda: {'total':0, 'benign':0, 'suspicious':0, 'malicious':0, 'active':0, 'dead':0})
for c2 in all_c2s:
    pkg = c2.get('package_name', 'unknown')
    per_sample[pkg]['total'] += 1
    per_sample[pkg][c2.get('classification','benign')] += 1
    if c2.get('live_dns',{}).get('resolves',False):
        per_sample[pkg]['active'] += 1
    else:
        per_sample[pkg]['dead'] += 1

# Geo data for map
geo_data = []
for ip, info in geo_cache.items():
    if info:
        geo_data.append({'ip': ip, 'lat': info.get('lat', 0), 'lon': info.get('lon', 0),
                         'country': info.get('country', ''), 'isp': info.get('isp', '')})

# Top malicious C2s
malicious = [c2 for c2 in all_c2s if c2.get('classification') == 'malicious']
top_malicious = sorted(malicious, key=lambda x: x.get('domain') or x.get('ip') or '')[:50]

html = '''<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>DroidForensix C2 Analysis Report</title>
<style>
* { margin:0; padding:0; box-sizing:border-box; }
body { font-family: 'Segoe UI', system-ui, sans-serif; background:#0f172a; color:#e2e8f0; padding:24px; }
h1 { font-size:2rem; margin-bottom:8px; }
h2 { font-size:1.3rem; margin:24px 0 12px; color:#38bdf8; }
.subtitle { color:#94a3b8; margin-bottom:24px; }
.cards { display:grid; grid-template-columns:repeat(auto-fit, minmax(180px,1fr)); gap:16px; margin:20px 0; }
.card { background:#1e293b; border-radius:12px; padding:20px; text-align:center; }
.card .value { font-size:2.5rem; font-weight:700; }
.card .label { color:#94a3b8; font-size:0.85rem; margin-top:4px; }
.green { color:#22c55e; }
.yellow { color:#eab308; }
.red { color:#ef4444; }
.blue { color:#38bdf8; }
.gray { color:#64748b; }
table { width:100%; border-collapse:collapse; margin:12px 0; font-size:0.85rem; }
th { text-align:left; padding:8px 10px; background:#1e293b; color:#94a3b8; font-weight:600; border-bottom:2px solid #334155; }
td { padding:8px 10px; border-bottom:1px solid #1e293b; }
tr:hover td { background:#1e293b; }
.badge { display:inline-block; padding:2px 8px; border-radius:4px; font-size:0.75rem; font-weight:600; }
.badge-benign { background:#166534; color:#86efac; }
.badge-suspicious { background:#713f12; color:#fde047; }
.badge-malicious { background:#7f1d1d; color:#fca5a5; }
.badge-active { background:#166534; color:#86efac; }
.badge-dead { background:#374151; color:#9ca3af; }
.status-bar { display:flex; height:24px; border-radius:6px; overflow:hidden; margin:8px 0; }
.status-bar div { transition:width 0.3s; }
.row { display:flex; gap:24px; flex-wrap:wrap; }
.col { flex:1; min-width:300px; }
.footer { margin-top:32px; padding-top:16px; border-top:1px solid #334155; color:#64748b; font-size:0.8rem; }
</style>
</head>
<body>
<h1>DroidForensix &mdash; C2 Infrastructure Analysis</h1>
<p class="subtitle">''' + datetime.now().strftime('%Y-%m-%d %H:%M') + ''' &middot; 25 Android malware samples from AndroZoo</p>

<div class="cards">
  <div class="card"><div class="value green">''' + str(class_counts.get('benign',0)) + '''</div><div class="label">Benign (SDK)</div></div>
  <div class="card"><div class="value yellow">''' + str(class_counts.get('suspicious',0)) + '''</div><div class="label">Suspicious</div></div>
  <div class="card"><div class="value red">''' + str(class_counts.get('malicious',0)) + '''</div><div class="label">Malicious C2</div></div>
  <div class="card"><div class="value blue">''' + str(len(active_c2s)) + '''</div><div class="label">Active (Live DNS)</div></div>
</div>

<div class="cards">
  <div class="card"><div class="value">''' + str(len(all_c2s)) + '''</div><div class="label">Total C2 Indicators</div></div>
  <div class="card"><div class="value green">''' + str(class_counts.get('benign',0) + class_counts.get('suspicious',0)) + '''</div><div class="label">Monitored (Benign+Suspicious)</div></div>
  <div class="card"><div class="value red">''' + str(class_counts.get('malicious',0)) + '''</div><div class="label">Action Required (Malicious)</div></div>
  <div class="card"><div class="value">''' + str(len(all_geo_ips)) + '''</div><div class="label">Unique IPs (Geo)</div></div>
</div>

<h2>C2 Classification Breakdown</h2>
<div class="status-bar" style="width:100%">
  <div class="green" style="width:''' + str(class_counts.get('benign',0)/max(len(all_c2s),1)*100) + '''%">''' + str(class_counts.get('benign',0)) + '''</div>
  <div class="yellow" style="width:''' + str(class_counts.get('suspicious',0)/max(len(all_c2s),1)*100) + '''%">''' + str(class_counts.get('suspicious',0)) + '''</div>
  <div class="red" style="width:''' + str(class_counts.get('malicious',0)/max(len(all_c2s),1)*100) + '''%">''' + str(class_counts.get('malicious',0)) + '''</div>
</div>

<div class="row">
<div class="col">
<h2>Per-Sample Breakdown</h2>
<table>
<tr><th>Package</th><th>Total</th><th>Benign</th><th>Susp.</th><th>Mal.</th><th>Alive</th></tr>
'''
for pkg in sorted(per_sample.keys()):
    s = per_sample[pkg]
    html += f'<tr><td>{pkg[:30]}</td><td>{s["total"]}</td><td>{s["benign"]}</td><td>{s["suspicious"]}</td><td>{s["malicious"]}</td><td><span class="badge badge-{"active" if s["active"]>0 else "dead"}">{s["active"]}</span></td></tr>\n'

html += '''
</table>
</div>
<div class="col">
<h2>Top Malicious C2 Domains</h2>
<table>
<tr><th>Domain</th><th>Status</th><th>Class</th><th>Reason</th></tr>
'''
for c2 in top_malicious[:30]:
    dom = c2.get('domain','') or c2.get('ip','')
    st = c2.get('status','')
    cl = c2.get('classification','')
    rs = c2.get('classification_reason','')[:40]
    html += f'<tr><td>{dom[:35]}</td><td><span class="badge badge-{st}">{st}</span></td><td><span class="badge badge-{cl}">{cl}</span></td><td>{rs}</td></tr>\n'

html += '''
</table>
</div>
</div>

<h2>Active C2 Geo-Locations</h2>
<table>
<tr><th>IP</th><th>Country</th><th>Region</th><th>ISP</th></tr>
'''
for g in sorted(geo_data, key=lambda x: x.get('country','')):
    html += f'<tr><td>{g["ip"]}</td><td>{g.get("country","?")}</td><td>{g.get("regionName","?")}</td><td>{g.get("isp","?")}</td></tr>\n'

html += '''
</table>

<h2>Threat Intel Exports</h2>
<table>
<tr><th>File</th><th>Format</th><th>Entries</th></tr>
<tr><td>analysis/work/c2_blocklist.csv</td><td>CSV</td><td>''' + str(len(active_c2s)) + '''</td></tr>
<tr><td>analysis/work/c2_blocklist_stix.json</td><td>STIX 2.0</td><td>''' + str(len(active_c2s)) + '''</td></tr>
<tr><td>analysis/work/c2_geo.json</td><td>JSON</td><td>''' + str(sum(1 for v in geo_cache.values() if v)) + ''' locations</td></tr>
</table>

<div class="footer">
Generated by DroidForensix pipeline &middot;
''' + str(len(all_c2s)) + ''' C2 indicators across 25 samples &middot;
C2 classification based on domain whitelist + live DNS + CIRCL pDNS
</div>
</body>
</html>'''

with open(WORK_DIR / 'c2_report.html', 'w', encoding='utf-8') as f:
    f.write(html)
print(f"  HTML report: analysis/work/c2_report.html")

# Final summary JSON
final = {
    'total_c2s': len(all_c2s),
    'classification': dict(class_counts),
    'status': {s: sum(1 for c2 in all_c2s if c2.get('status') == s) for s in ['active','likely_active','historical','dead']},
    'geo_located': sum(1 for v in geo_cache.values() if v),
    'active_suspicious_malicious': len(active_c2s),
    'blocklist_csv': 'analysis/work/c2_blocklist.csv',
    'blocklist_stix': 'analysis/work/c2_blocklist_stix.json',
    'geo_file': 'analysis/work/c2_geo.json',
    'report_html': 'analysis/work/c2_report.html',
}
with open(WORK_DIR / 'final_summary.json', 'w') as f:
    json.dump(final, f, indent=2)

print(f"\n{'='*60}")
print(f"COMPLETE")
print(f"{'='*60}")
print(f"Benign (SDK/clean):   {class_counts.get('benign',0)}")
print(f"Suspicious:           {class_counts.get('suspicious',0)}")
print(f"Malicious C2:         {class_counts.get('malicious',0)}")
print(f"Geo-located IPs:      {sum(1 for v in geo_cache.values() if v)}")
print(f"Blocklist entries:    {len(active_c2s)}")
print(f"Report:               analysis/work/c2_report.html")
