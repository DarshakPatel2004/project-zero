"""
Threat-intel aggregation and exports.

Builds the Phase-2 threat-intelligence view consumed by the frontend
``ThreatIntelView`` from a pipeline result, and produces CSV / STIX / YARA
exports. C2 indicators are read from ``c2_infrastructure`` in the result;
DNS-liveness ``status`` and ``classification`` fields are used when present
(added by the offline ``enrich_c2_activity.py`` / ``build_final_outputs.py``
batch scripts) and computed on the fly otherwise so the endpoint works for
any analyzed sample.

Geo-location is read from the shared cache ``analysis/work/c2_geo.json`` when
available; no network calls are made from the request path.
"""

import csv
import io
import ipaddress
import json
import socket
import time
from collections import defaultdict
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Tuple
from urllib.request import urlopen, Request

from backend.config import settings

try:
    import geoip2.database
    _GEO_READER = geoip2.database.Reader(str(settings.GEOIP_PATH)) if settings.GEOIP_PATH.exists() else None
except Exception:
    _GEO_READER = None

_ISP_CACHE_PATH = settings.WORK_DIR / 'isp_cache.json'
_LAST_ISP_QUERY = 0.0

def _load_isp_cache() -> Dict[str, Any]:
    if _ISP_CACHE_PATH.exists():
        try:
            with open(_ISP_CACHE_PATH, 'r', encoding='utf-8') as f:
                return json.load(f)
        except Exception:
            pass
    return {}

def _save_isp_cache(cache: Dict[str, Any]) -> None:
    try:
        with open(_ISP_CACHE_PATH, 'w', encoding='utf-8') as f:
            json.dump(cache, f, indent=2)
    except Exception:
        pass

def _enrich_isp(ip: str) -> Dict[str, str]:
    """Query ip-api.com for ISP/org/AS, with rate limiting and caching."""
    global _LAST_ISP_QUERY
    cache = _load_isp_cache()
    if ip in cache:
        return cache[ip]

    if _classify_ip(ip) != 'public':
        result = {'isp': '', 'org': '', 'as': ''}
        cache[ip] = result
        _save_isp_cache(cache)
        return result

    elapsed = time.time() - _LAST_ISP_QUERY
    if elapsed < 1.4:
        time.sleep(1.4 - elapsed)
    _LAST_ISP_QUERY = time.time()

    try:
        req = Request(f'http://ip-api.com/json/{ip}?fields=status,isp,org,as,country,regionName,city',
                      headers={'User-Agent': 'DroidForensix/1.0'})
        with urlopen(req, timeout=5) as resp:
            data = json.loads(resp.read().decode())
        if data.get('status') == 'success':
            result = {
                'isp': data.get('isp', ''),
                'org': data.get('org', ''),
                'as': data.get('as', ''),
            }
        else:
            result = {'isp': '', 'org': '', 'as': ''}
    except Exception:
        result = {'isp': '', 'org': '', 'as': ''}

    cache[ip] = result
    _save_isp_cache(cache)
    return result


def _geo_lookup(ip: str) -> Optional[Dict[str, Any]]:
    """On-the-fly GeoIP lookup via MaxMind when the cache misses."""
    if not ip or _GEO_READER is None:
        return None
    try:
        response = _GEO_READER.city(ip)
        return {
            'country': response.country.name or 'Unknown',
            'region': response.subdivisions.most_specific.name if response.subdivisions else '',
            'city': response.city.name or '',
            'lat': response.location.latitude,
            'lon': response.location.longitude,
            'isp': response.traits.isp or '',
        }
    except Exception:
        return None


# --- Whitelist of known benign SDK / ad domains (mirrors build_final_outputs.py) ---
BENIGN_SDK_DOMAINS = {
    'admob.com', 'www.admob.com', 'a.admob.com', 'media.admob.com', 'e.admob.com',
    'googleads.g.doubleclick.net', 'doubleclick.net', 'googleadservices.com',
    'www.googleadservices.com', 'pagead2.googlesyndication.com',
    'googlesyndication.com', 'google-analytics.com', 'www.google-analytics.com',
    'ssl.google-analytics.com', 'analytics.google.com',
    'maps.googleapis.com', 'maps.google.com', 'ditu.google.cn',
    'www.googleapis.com', 'android.clients.google.com',
    'facebook.com', 'www.facebook.com', 'api.facebook.com', 'apps.facebook.com',
    'graph.facebook.com', 'connect.facebook.net',
    'amazon-adsystem.com', 's3.amazonaws.com', 'aws.amazon.com',
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
    'apple.com', 'www.apple.com', 'itunes.apple.com', 'phobos.apple.com',
    'adobe.com', 'www.adobe.com', 'www.macromedia.com',
    'crl3.adobe.com', 'airdownload.adobe.com', 'airinstall.adobe.com',
    'microsoft.com', 'www.microsoft.com', 'live.com', 'msn.com',
    'cloudfront.net', 'akamai.net', 'akamaihd.net',
    'github.com', 'raw.githubusercontent.com',
    'curl.haxx.se', 'daneden.me', 'tumblr.com', 'api.tumblr.com',
    'yahoo.com', 'www.yahoo.com',
    # Indian payment gateways
    'paytm.in', 'securegw.paytm.in', 'easypay.paytm.in',
    'payu.in', 'payumoney.com', 'ccavenue.com',
    'mobikwik.com', 'zaakpay.com',
    'npci.org.in',
    # Indian bank 3D Secure / ACS
    'onlinesbi.com', 'hdfcbank.com', 'icicibank.com',
    'citibank.co.in', 'enstage.com', 'idbibank.com',
    'amxvpos.com', 'deutschebank.co.in',
    # Xiaomi / Mi ecosystem
    'xiaomi.com', 'xiaomi.net', 'mi.com',
    'xmpush.global.xiaomi.com', 'appmifile.com',
    # Payment 3DS authentication providers
    'arcot.com',
    # Xiaomi POCO sub-brand
    'po.co',
    # Other legitimate services
    'cashify.in', 'uber.com', 'schema.org',
    'twitter.com', 'worldpay.com', 'apaylater.com',
    'indusguard.com', 'monstat.com',
    'paysecure.ru',
    'paypal.com', 'www.paypal.com', 'api.paypal.com',
}

SUSPICIOUS_TLDS = {'.tk', '.ml', '.ga', '.cf', '.gq', '.xyz', '.top', '.club',
                   '.work', '.bid', '.date', '.win', '.men', '.loan'}
SUSPICIOUS_PORTS = {8080, 8443, 444, 6666, 6667, 6668, 6669, 7000, 7070, 8888,
                    9999, 31337, 1337, 4444, 5555, 9000, 10000}

SUSPICIOUS_PATH_KEYWORDS = ['/admin', '/panel', '/gate', '/command', '/shell',
                            '/exec', '/c2', '/bot', '/callback']


def _result_package(result: Dict[str, Any]) -> str:
    """Package name from result metadata (handles both key spellings)."""
    meta = result.get('metadata', {}) or {}
    return meta.get('package') or meta.get('package_name') or ''


def classify_c2(c2: Dict[str, Any]) -> Tuple[str, str]:
    """Return (classification, reason) for a C2 indicator.

    Mirrors build_final_outputs.classify_c2 so on-the-fly results match the
    offline batch output.
    """
    reasons: List[str] = []
    domain = (c2.get('domain') or '').lower()
    ip = c2.get('ip') or ''
    port = c2.get('port') or 0
    path = c2.get('path') or ''
    protocol = c2.get('protocol') or ''
    live = c2.get('live_dns') or {}
    circl = c2.get('circl') or {}

    if any(domain == d or domain.endswith('.' + d) for d in BENIGN_SDK_DOMAINS):
        return 'benign', 'whitelisted SDK domain'

    if '%' in domain or domain.startswith('__'):
        return 'malicious', 'template/obfuscated domain'

    for tld in SUSPICIOUS_TLDS:
        if domain.endswith(tld):
            reasons.append(f'suspicious TLD: {tld}')
            break

    try:
        if port and int(port) in SUSPICIOUS_PORTS:
            reasons.append(f'unusual port: {port}')
    except (TypeError, ValueError):
        pass

    if protocol and protocol not in ('http', 'https'):
        reasons.append(f'unusual protocol: {protocol}')

    # Only treat a non-resolving domain as a signal when liveness was checked.
    if live and not live.get('resolves', False):
        reasons.append('NXDOMAIN')

    pdns = circl.get('pdns_domain', {}) if isinstance(circl, dict) else {}
    pdns_count = pdns.get('count', 0) if isinstance(pdns, dict) else 0
    if live.get('resolves', False) and pdns_count == 0:
        reasons.append('no pDNS history (newly registered?)')

    if not domain and ip:
        reasons.append('IP-direct C2 (no domain)')

    path_lower = path.lower()
    if any(kw in path_lower for kw in SUSPICIOUS_PATH_KEYWORDS):
        reasons.append(f'suspicious path: {path}')

    if len(reasons) >= 2:
        return 'malicious', '; '.join(reasons)
    if len(reasons) == 1:
        return 'suspicious', '; '.join(reasons)
    return 'benign', 'clean indicator'


def _status_bucket(c2: Dict[str, Any]) -> str:
    """Normalize a C2's liveness status into active/likely_active/dead."""
    status = c2.get('status')
    if status in ('active', 'likely_active', 'dead', 'historical'):
        # historical = in pDNS history but currently down -> treat as dead for display
        return 'dead' if status == 'historical' else status
    # No enrichment: infer from live_dns if present, else unknown -> dead bucket.
    live = c2.get('live_dns') or {}
    if live:
        return 'active' if live.get('resolves', False) else 'dead'
    return 'dead'


def _ensure_classification(c2: Dict[str, Any]) -> str:
    """Return the C2's classification, computing it if the batch enrichment
    did not run for this sample."""
    label = c2.get('classification')
    if label in ('benign', 'suspicious', 'malicious'):
        return label
    label, _reason = classify_c2(c2)
    return label


def _load_geo_cache() -> Dict[str, Any]:
    """Load the shared IP geo cache produced by build_final_outputs.py."""
    geo_path = settings.WORK_DIR / 'c2_geo.json'
    if not geo_path.exists():
        return {}
    try:
        with open(geo_path, 'r', encoding='utf-8') as f:
            return json.load(f)
    except Exception:
        return {}


def _collect_ips(c2: Dict[str, Any]) -> List[str]:
    """All IPs associated with a C2: the direct IP plus any resolved IPs."""
    ips: List[str] = []
    if c2.get('ip'):
        ips.append(c2['ip'])
    live = c2.get('live_dns') or {}
    for ip in (live.get('ips') or []):
        ips.append(ip)
    return ips


def _is_valid_ip(ip: str) -> bool:
    try:
        socket.inet_aton(ip)
        return True
    except socket.error:
        return False


def _classify_ip(ip: str) -> str:
    if not _is_valid_ip(ip):
        return "invalid"
    try:
        addr = ipaddress.ip_address(ip)
        if addr.is_loopback:
            return "loopback"
        if addr.is_private:
            return "private"
        return "public"
    except ValueError:
        return "invalid"


def build_threat_intel(result: Dict[str, Any], sample_id: str) -> Dict[str, Any]:
    """Aggregate the threat-intel view for a single sample's pipeline result."""
    c2s: List[Dict[str, Any]] = result.get('c2_infrastructure', []) or []

    # Enrich liveness on-the-fly if needed
    unresolved_c2s = [c for c in c2s if not c.get('status') and not c.get('live_dns')]
    if unresolved_c2s:
        from concurrent.futures import ThreadPoolExecutor

        def resolve_one(c):
            domain = c.get('domain')
            ip = c.get('ip')
            if domain:
                try:
                    old_timeout = socket.getdefaulttimeout()
                    socket.setdefaulttimeout(2.0)
                    addrs = socket.getaddrinfo(domain, 80, socket.AF_INET)
                    ips = list(sorted(set(a[4][0] for a in addrs)))
                    socket.setdefaulttimeout(old_timeout)
                    return c, {'live_dns': {'resolves': True, 'ips': ips}, 'status': 'active'}
                except Exception as e:
                    try:
                        socket.setdefaulttimeout(old_timeout)
                    except Exception:
                        pass
                    return c, {'live_dns': {'resolves': False, 'ips': [], 'error': str(e)[:60]}, 'status': 'dead'}
            elif ip:
                ip_class = _classify_ip(ip)
                if ip_class in ('public', 'private', 'vpn'):
                    return c, {'live_dns': {'resolves': True, 'ips': [ip]}, 'status': 'active'}
                else:
                    return c, {'live_dns': {'resolves': False, 'ips': [], 'error': 'invalid/loopback ip'}, 'status': 'dead'}
            return c, None

        with ThreadPoolExecutor(max_workers=min(len(unresolved_c2s), 10)) as pool:
            futures = [pool.submit(resolve_one, c) for c in unresolved_c2s]
            has_changes = False
            for fut in futures:
                try:
                    c, update = fut.result()
                    if update:
                        c.update(update)
                        has_changes = True
                except Exception:
                    pass

        if has_changes:
            try:
                # 1. Update pipeline_result.json
                result_path = settings.WORK_DIR / sample_id / "pipeline_result.json"
                if result_path.exists():
                    with open(result_path, "w", encoding="utf-8") as f:
                        json.dump(result, f, indent=2, default=str)

                # 2. Update step5_c2s.json
                step5_path = settings.WORK_DIR / sample_id / "step5_c2s.json"
                if step5_path.exists():
                    with open(step5_path, "r", encoding="utf-8") as f:
                        step5_data = json.load(f)
                    
                    step5_c2s = step5_data.get('c2_infrastructure', []) or []
                    c2_map = {c.get('c2_id'): c for c in step5_c2s if c.get('c2_id')}
                    for c in c2s:
                        c2_id = c.get('c2_id')
                        if c2_id and c2_id in c2_map:
                            c2_map[c2_id].update({
                                'live_dns': c.get('live_dns'),
                                'status': c.get('status')
                            })
                    with open(step5_path, "w", encoding="utf-8") as f:
                        json.dump(step5_data, f, indent=2, default=str)
            except Exception as e:
                print(f"[WARN] Failed to save enriched threat intel for {sample_id}: {e}")

    dns = {'active': 0, 'likely_active': 0, 'dead': 0}
    classification = {'benign': 0, 'suspicious': 0, 'malicious': 0}

    enriched_c2s: List[Dict[str, Any]] = []
    geo_cache = _load_geo_cache()
    seen_ips = set()
    ips_geolocated: List[Dict[str, Any]] = []

    for c2 in c2s:
        bucket = _status_bucket(c2)
        dns[bucket] = dns.get(bucket, 0) + 1

        label = _ensure_classification(c2)
        classification[label] = classification.get(label, 0) + 1

        # Carry computed fields back so the frontend list and exports agree.
        item = dict(c2)
        item.setdefault('classification', label)
        item.setdefault('status', c2.get('status') or bucket)
        enriched_c2s.append(item)

        for ip in _collect_ips(c2):
            if ip in seen_ips:
                continue
            seen_ips.add(ip)
            ip_type = _classify_ip(ip)
            geo = geo_cache.get(ip) or _geo_lookup(ip)
            isp_data = _enrich_isp(ip) if not (geo and geo.get('isp')) else {'isp': geo.get('isp', ''), 'org': '', 'as': ''}
            if geo:
                ips_geolocated.append({
                    'ip': ip,
                    'ip_type': ip_type,
                    'country': geo.get('country', 'Unknown'),
                    'region': geo.get('regionName') or geo.get('region') or '',
                    'city': geo.get('city', ''),
                    'isp': isp_data.get('isp', geo.get('isp', '')),
                    'org': isp_data.get('org', ''),
                    'as': isp_data.get('as', ''),
                    'latitude': geo.get('lat'),
                    'longitude': geo.get('lon'),
                })
            else:
                country = 'Private Network' if ip_type in ('private', 'loopback') else 'Unknown'
                ips_geolocated.append({
                    'ip': ip,
                    'ip_type': ip_type,
                    'country': country,
                    'region': '',
                    'city': '',
                    'isp': '',
                    'org': '',
                    'as': '',
                    'latitude': None,
                    'longitude': None,
                })

    return {
        'sample_id': sample_id,
        'c2s': enriched_c2s,
        'dns': dns,
        'classification': classification,
        'ips_geolocated': ips_geolocated,
        'totals': {
            'c2s': len(enriched_c2s),
            'geolocated_ips': len(ips_geolocated),
        },
    }


# ---------------------------------------------------------------------------
# Exports
# ---------------------------------------------------------------------------

def _export_c2s(result: Dict[str, Any]) -> List[Dict[str, Any]]:
    """C2s with classification/status guaranteed, for export builders."""
    out = []
    for c2 in result.get('c2_infrastructure', []) or []:
        item = dict(c2)
        item['classification'] = _ensure_classification(c2)
        item['status'] = c2.get('status') or _status_bucket(c2)
        out.append(item)
    return out


def to_csv(result: Dict[str, Any]) -> str:
    """CSV blocklist of C2 indicators."""
    buf = io.StringIO()
    writer = csv.writer(buf)
    writer.writerow(['classification', 'status', 'domain', 'ip', 'port',
                     'protocol', 'path', 'package_name', 'reason', 'resolved_ips'])
    for c2 in _export_c2s(result):
        live = c2.get('live_dns') or {}
        resolved = ', '.join(live.get('ips', []) or [])
        writer.writerow([
            c2.get('classification', ''),
            c2.get('status', ''),
            c2.get('domain', ''),
            c2.get('ip', ''),
            c2.get('port', ''),
            c2.get('protocol', ''),
            c2.get('path', ''),
            c2.get('package_name') or _result_package(result),
            c2.get('classification_reason', ''),
            resolved,
        ])
    return buf.getvalue()


def to_stix(result: Dict[str, Any], sample_id: str) -> Dict[str, Any]:
    """STIX 2.0-style bundle of C2 indicators."""
    now = datetime.now(timezone.utc).strftime('%Y-%m-%dT%H:%M:%SZ')
    bundle = {
        'type': 'bundle',
        'id': f'bundle--{sample_id[:32]}',
        'objects': [],
    }
    for c2 in _export_c2s(result):
        domain = c2.get('domain') or ''
        ip = c2.get('ip') or ''
        if not domain and not ip:
            continue
        pattern = (f"[domain-name:value = '{domain}']" if domain
                   else f"[ipv4-addr:value = '{ip}']")
        bundle['objects'].append({
            'type': 'indicator',
            'id': f"indicator--{sample_id[:16]}-{c2.get('c2_id', 'unknown')}",
            'created': now,
            'valid_from': now,
            'name': domain or ip,
            'pattern': pattern,
            'pattern_type': 'stix',
            'labels': [c2.get('classification', ''), c2.get('status', ''), 'c2'],
        })
    return bundle


def to_yara(result: Dict[str, Any], sample_id: str) -> str:
    """Generate a per-sample YARA rule from this sample's C2 indicators."""
    metadata = result.get('metadata', {}) or {}
    package = _result_package(result) or 'unknown'
    rule_name = f"droidforensix_{sample_id[:16]}"

    strings: List[str] = []
    seen = set()
    idx = 0
    for c2 in _export_c2s(result):
        if c2.get('classification') == 'benign':
            continue
        for value in (c2.get('domain'), c2.get('raw_url')):
            if not value or value in seen:
                continue
            seen.add(value)
            escaped = value.replace('\\', '\\\\').replace('"', '\\"')
            strings.append(f'        $s{idx} = "{escaped}" ascii wide nocase')
            idx += 1

    lines = [f'rule {rule_name}', '{', '    meta:']
    lines.append(f'        description = "Auto-generated C2 indicators for {package}"')
    lines.append(f'        sample_sha256 = "{metadata.get("sha256", sample_id)}"')
    lines.append('        generator = "DroidForensix"')
    if strings:
        lines.append('    strings:')
        lines.extend(strings)
        lines.append('    condition:')
        lines.append('        any of them')
    else:
        lines.append('    condition:')
        lines.append('        false  // no malicious/suspicious C2 indicators extracted')
    lines.append('}')
    return '\n'.join(lines) + '\n'
