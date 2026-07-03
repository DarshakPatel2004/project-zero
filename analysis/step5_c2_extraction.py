"""
Step 5: C2 Infrastructure Extraction

Parses URLs/IPs from decoded payloads and direct source strings into structured
C2 records: protocol, domain, port, path, query params, IP classification,
communication type, and confidence scores.
"""

import ipaddress
import json
import logging
import re
import socket
from pathlib import Path
from typing import Dict, List, Any, Optional
from urllib.parse import urlparse, parse_qs

from analysis.ip_validation import calculate_ip_legitimacy_score
from backend.config import settings

try:
    from backend.circl_client import CIRCLAuthError, CIRCLClient, CIRCLClientError
    CIRCL_AVAILABLE = True
except ImportError:
    CIRCL_AVAILABLE = False


class C2ExtractionError(Exception):
    """Raised when C2 extraction fails."""
    pass


logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Patterns and constants
# ---------------------------------------------------------------------------

URL_RE = re.compile(r'https?://[^\s"\'<>]+', re.IGNORECASE)
IP_RE = re.compile(r'\b(?:(?:25[0-5]|2[0-4]\d|[01]?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d?\d)\b')
DOMAIN_RE = re.compile(r'\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}\b')

# Known benign SDK, documentation, and namespace domains that are not C2.
# These appear frequently in legitimate apps and dilute the C2 signal.
BENIGN_DOMAINS = {
    # Android / Google
    "schemas.android.com",
    "play.google.com",
    "developer.android.com",
    "issuetracker.google.com",
    "maps.google.com",
    "www.googleapis.com",
    "www.google.com",
    "google.com",
    "youtube.com",
    "android.com",
    "www.android.com",
    "gstatic.com",
    # Java / Sun / Oracle
    "java.sun.com",
    "sun.com",
    "oracle.com",
    "openjdk.java.net",
    "javaee.github.io",
    # W3C / XML
    "www.w3.org",
    "xml.org",
    "xmlpull.org",
    "www.w3.org",
    "xmlns.org",
    # Development platforms / libraries
    "github.com",
    "githubusercontent.com",
    "gitlab.com",
    "bitbucket.org",
    "www.slf4j.org",
    "apache.org",
    "www.apache.org",
    "kotlinlang.org",
    # Adobe / media
    "ns.adobe.com",
    "aomedia.org",
    # JetBrains
    "youtrack.jetbrains.com",
    "developer.apple.com",
    "docs.flutter.dev",
    # Mozilla
    "mozilla.org",
    "www.mozilla.org",
    # Common legitimate app endpoints observed in dataset
    "videolan.org",
    "www.videolan.org",
    "etesync.com",
    "etebase.com",
    "dashboard.etebase.com",
    "api.etebase.com",
    "api.etesync.com",
    "fastmail.com",
    "www.fastmail.com",
    "api.fastmail.com",
    "api.login.aol.com",
    "thunderbird.net",
    "autoconfig.thunderbird.net",
    "jrpn.jovial.com",
    "legacy.jrpn.jovial.com",
    "dmfs.org",
    "schema.dmfs.org",
    "t.me",
    # Search / portals (legitimate, often embedded in browsers or regional apps)
    "yandex.ru",
    "yandex.com",
    "yahoo.com",
    "bing.com",
    "duckduckgo.com",
    "baidu.com",
    # PDF/file converter services (legitimate, often embedded in readers)
    "cloudconvert.com",
    "www.zamzar.com",
    "zamzar.com",
    "www.pdfrotate.com",
    "pdfrotate.com",
    "rotatepdf.net",
    "www.rotatepdf.net",
    "smallpdf.com",
    "topdf.com",
    "smaltilpdf.com",
    # Browser / mail / sync app endpoints observed as false positives
    "crbug.com",
    "bugs.chromium.org",
    "oauth2.googleapis.com",
    "googleapis.com",
    "outlook.office.com",
    "office.com",
    "login.microsoftonline.com",
    "graph.microsoft.com",
    "dashif.org",
    "syncadapter.bitfire.at",
    "www.bitfire.at",
    "bitfire.at",
    "dnsjava.org",
    "ical4j.github.io",
    "square.github.io",
    "accounts.stage.mozaws.net",
    "stable.dev.lcip.org",
    "identity.mozilla.com",
    "accounts.firefox.com",
    "relay.firefox.com",
    "firefox.com",
    "mozilla.github.io",
    "docs.videolan.me",
    "android.googlesource.com",
    "g.co",
    "goo.gle",
    "api.flutter.dev",
    "pub.dev",
    "zulip.readthedocs.io",
    "blog.zulip.com",
    "secure.gravatar.com",
    "drift.simonbinder.eu",
    "purl.org",
    "projectlombok.org",
    "insert-koin.io",
    "k9mail.app",
    "forum.k9mail.app",
    "tb.pro",
    "auth.tb.pro",
    "auth-stage.tb.pro",
    "jsoup.org",
    "jutf7.sourceforge.net",
    "jcraft.com",
    "jcip.net",
    # PDF / ebook / converter services
    "samlib.ru",
    "toepub.com",
    "online-convert.com",
    "document.online-convert.com",
    "ebook.online-convert.com",
    "pdf2docx.com",
    "m.gutenberg.org",
    "gutenberg.org",
    "bookserver.archive.org",
    "archive.org",
    "f-droid.org",
    # Media / streaming standards
    "schemas.xmlsoap.org",
    "xmlsoap.org",
    "www.shoutcast.com",
    "xspf.org",
    "lame.sf.net",
    "www.twolame.org",
    "schemas.upnp.org",
    "upnp.org",
    "www.tvdr.de",
    "www.crunchyroll.com",
    "musicbrainz.org",
    "www.icecast.org",
    "ns.adobe.com",
    "www.brynosaurus.com",
    # Document / ebook format schemas and services
    "schemas.microsoft.com",
    "schemas.openxmlformats.org",
    "openoffice.org",
    "docs.oasis-open.org",
    "schemas.openxps.org",
    "www.idpf.org",
    "www.daisy.org",
    "librera.mobi",
    "beta.librera.mobi",
    "worldswithoutend.com",
    "www.worldswithoutend.com",
    "manybooks.net",
    "idownload.manybooks.net",
    "goodreads.com",
    "www.goodreads.com",
    "amazon.com",
    "www.amazon.com",
    "issuu.com",
    "wiki.mobileread.com",
    "cdn.jsdelivr.net",
    "jsdelivr.net",
    "emma.cloud.tabdigital.eu",
    # Unicode / XML constants
    "www.unicode.org",
    "unicode.org",
    "javax.xml.xmlconstants",
    # Certificate / PKI / OCSP / CRL endpoints
    "d-trust.net",
    "www.d-trust.net",
    "crl.d-trust.net",
    "webrtc.org",
    "www.webrtc.org",
    "accv.es",
    "www.accv.es",
    "fineid.fi",
    "www.fineid.fi",
    "proxy.fineid.fi",
    "eadtrust.eu",
    "crl.eadtrust.eu",
    "ca.eadtrust.eu",
    "cert.fnmt.es",
    "www.cert.fnmt.es",
    "globaltrust.eu",
    "service.globaltrust.eu",
    "harica.gr",
    "repo.harica.gr",
    "crl.harica.gr",
    "fina.hr",
    "rdc.fina.hr",
    "anf.es",
    "www.anf.es",
    "crl.anf.es",
    "ocsp.anf.es",
    "firmaprofesional.com",
    "crl.firmaprofesional.com",
    "multicert.com",
    "pkiroot.multicert.com",
    "a-trust.at",
    "www.a-trust.at",
    "crl.a-trust.at",
    "certsign.ro",
    "www.certsign.ro",
    "halcom.si",
    "domina.halcom.si",
    "quovadisglobal.com",
    "www.quovadisglobal.com",
    "ca.gov.si",
    "www.ca.gov.si",
    "posta.si",
    "postarca.posta.si",
    "certeurope.fr",
    "www.certeurope.fr",
    "nbusr.sk",
    "ep.nbusr.sk",
    # Mozilla / Google endpoints
    "llvm.googlesource.com",
    "wikipedia.org",
    "ja.wikipedia.org",
    "tenki.jp",
    # Search engines / portals observed in browsers
    "qwant.com",
    "www.qwant.com",
    "api.qwant.com",
    "lite.qwant.com",
    "ecosia.org",
    "www.ecosia.org",
    "ac.ecosia.org",
    "brave.com",
    "search.brave.com",
    "kagi.com",
    "startpage.com",
    "www.startpage.com",
    "metager.org",
    "mojeek.com",
    "www.mojeek.com",
    "yahoo.co.jp",
    "yelp.com",
    "www.yelp.com",
    # Certificate / trust service providers observed in Fennec
    "stampit.org",
    "www.stampit.org",
    "netlock.hu",
    "crl3.netlock.hu",
    "entrust.net",
    "www.entrust.net",
    "infocert.it",
    "www.firma.infocert.it",
    "izenpe.com",
    "www.izenpe.com",
    "evrotrust.com",
    "www.evrotrust.com",
    "postsignum.cz",
    "www.postsignum.cz",
    "www2.postsignum.cz",
    "postsignum.ttc.cz",
    # Documentation / standards / libraries
    "khronos.org",
    "www.khronos.org",
    "registry.khronos.org",
    "docs.rs",
    "sqlite.org",
    "geonames.org",
    "download.geonames.org",
    "ietf.org",
    "www.ietf.org",
    "aomediacodec.github.io",
    "cairographics.org",
    "allizom.org",
    "ads.allizom.org",
    "addons.allizom.org",
    "fastly-edge.com",
    "mozilla-ohttp.fastly-edge.com",
    "cloudflare-dns.com",
    "mozilla.cloudflare-dns.com",
    "mzl.la",
    "firefox.com.cn",
    "accounts.firefox.com.cn",
    # Additional CA / PKI / trust providers observed in Fennec
    "digicert.com",
    "cacerts.digicert.com",
    "crl3.digicert.com",
    "globalsign.com",
    "secure.globalsign.com",
    "www.globalsign.com",
    "telesec.de",
    "tstlsrr23.crl.telesec.de",
    "tstlsrr23.ocsp.telesec.de",
    "tstlsrr23.crt.telesec.de",
    "grcl3.crl.telesec.de",
    "grcl3.ocsp.telesec.de",
    "grcl3.crt.telesec.de",
    "bank-verlag.de",
    "www.bank-verlag.de",
    "e-szigno.hu",
    "erootca2024-crl.e-szigno.hu",
    "erootca2024-ca.e-szigno.hu",
    "cp.e-szigno.hu",
    "rootca2009-crl1.e-szigno.hu",
    "rootca2009-crl2.e-szigno.hu",
    "rootca2009-crl3.e-szigno.hu",
    "rootca2009-ca1.e-szigno.hu",
    "rootca2009-ca2.e-szigno.hu",
    "rootca2009-ca3.e-szigno.hu",
    "rootca2017-crl1.e-szigno.hu",
    "rootca2017-crl2.e-szigno.hu",
    "rootca2017-crl3.e-szigno.hu",
    "rootca2017-ca1.e-szigno.hu",
    "rootca2017-ca2.e-szigno.hu",
    "rootca2017-ca3.e-szigno.hu",
    "tlsrootca2023-crl.e-szigno.hu",
    "tlsrootca2023-ca.e-szigno.hu",
    "etlsrootca2024-crl.e-szigno.hu",
    "etlsrootca2024-ca.e-szigno.hu",
    "disig.sk",
    "eidas.disig.sk",
    "nccert.pl",
    "www.nccert.pl",
    "b-trust.org",
    "www.b-trust.org",
    "certigna.fr",
    "www.certigna.fr",
    "wwww.certigna.fr",
    "autorite.certigna.fr",
    "dhimyotis.com",
    "autorite.dhimyotis.com",
    "snca.gov.sk",
    "zone.nfqes.sk",
    "globaltrustedsign.com",
    "pki02.globaltrustedsign.com",
    "pki.globaltrustedsign.com",
    "chambersign.fr",
    "pc.chambersign.fr",
    "actalis.it",
    "www.actalis.it",
    "pec.it",
    "www.pec.it",
    "infonotary.com",
    "repository.infonotary.com",
    "swisssign.com",
    "repository.swisssign.com",
    "ssl.com",
    "cert.ssl.com",
    "www.ssl.com",
    "crls.ssl.com",
    # Additional services
    "ameblo.jp",
    "mozgcp.net",
    "prod.ohttp-gateway.prod.webservices.mozgcp.net",
    "shadertoy.com",
    "www.shadertoy.com",
    "fxtf.org",
    "drafts.fxtf.org",
    "stackexchange.com",
    "math.stackexchange.com",
    "jdashg.github.io",
    "dartbug.com",
    # Indian payment gateways
    "paytm.in", "securegw.paytm.in", "easypay.paytm.in",
    "payu.in", "payumoney.com", "ccavenue.com",
    "mobikwik.com", "zaakpay.com",
    "npci.org.in",
    # Indian bank 3D Secure / ACS
    "onlinesbi.com", "hdfcbank.com", "icicibank.com",
    "citibank.co.in", "enstage.com", "idbibank.com",
    "amxvpos.com", "deutschebank.co.in",
    # Xiaomi / Mi ecosystem
    "xiaomi.com", "xiaomi.net", "mi.com",
    "xmpush.global.xiaomi.com", "appmifile.com",
    # Payment 3DS authentication providers
    "arcot.com",
    # Xiaomi POCO sub-brand
    "po.co",
    # Other legitimate services
    "cashify.in", "uber.com", "schema.org",
    "twitter.com", "worldpay.com", "apaylater.com",
    "indusguard.com", "monstat.com",
    "paysecure.ru",
    "paypal.com", "www.paypal.com",
}

# TLD-like tokens produced by over-matching URL regex on code fragments.
# These are not real TLDs and should be rejected during domain validation.
INVALID_TLDS = {
    "world", "years", "recent", "icon", "css", "language", "style",
    "shortcut", "interpretation", "encodeuricomponent", "adobe",
}

BENIGN_DOMAIN_PATTERNS = {
    # Certificate / PKI infrastructure endpoints (OCSP, CRL, CRT, CA, PKI)
    r"^crl\.",
    r"^ocsp\.",
    r"^pki\.",
    r"^ca\.",
    r"^crt\.",
    r"^proxy\.",
    r"^repo\.",
    r"^rdc\.",
    r"^service\.",
    r"^postarca\.",
    r"^qcrldp\d+\.",
    r"^erootca\d+-",
    r"^rootca\d+-",
    r"^tlsrootca\d+-",
    r"^etlsrootca\d+-",
    r"^autorite\.",
    r"^r\.",
    # Service / docs subdomains that are always legitimate in this dataset
    r"\.readthedocs\.io$",
    r"\.services\.mozilla\.com$",
    r"\.mozaws\.net$",
    r"\.dev\.lcip\.org$",
    r"\.googlesource\.com$",
    r"\.stage\.mozaws\.net$",
    r"\.mozgcp\.net$",
    r"\.stackexchange\.com$",
}

BENIGN_URL_PATHS = {
    "/apk/res/android",
    "/apk/res-auto",
}

# Mobile advertising and analytics networks. These are legitimate monetization
# endpoints, but they frequently appear in adware / grayware. They should not
# be treated as high-confidence malware C2s.
AD_NETWORK_DOMAINS = {
    # Ad networks
    "airpush.com",
    "leadbolt.net",
    "leadboltapps.net",
    "searchmobileonline.com",
    "mobpartner.com",
    "tapjoy.com",
    "chartboost.com",
    "applovin.com",
    "fyber.com",
    "inneractive.com",
    "inmobi.com",
    "admob.com",
    "googleadservices.com",
    "doubleclick.net",
    "mopub.com",
    "millennialmedia.com",
    "supersonicads.com",
    "ironsource.com",
    "unity3d.com",
    "vungle.com",
    "adcolony.com",
    "startapp.com",
    "appnext.com",
    "digitalturbine.com",
    "superrewards.com",
    "flurry.com",
    "crashlytics.com",
    "appsflyer.com",
    "adjust.com",
    "kochava.com",
    # Shorteners / redirectors commonly used by ad SDKs
    "bit.ly",
    "tinyurl.com",
    "goo.gl",
    "ow.ly",
}

# Known DTD / XML Schema / namespace URIs that are library/documentation
# references, never actual network C2 traffic.
BENIGN_URIS = {
    "http://java.sun.com/dtd/properties.dtd",
    "http://java.sun.com/xml/ns/javaee",
    "http://java.sun.com/jsp/jstl/core",
    "http://www.w3.org/2000/xmlns",
    "http://www.w3.org/2001/XMLSchema",
    "http://www.w3.org/2001/XMLSchema-instance",
    "http://www.w3.org/1999/xlink",
    "http://www.w3.org/1999/xhtml",
    "http://www.w3.org/2005/Atom",
    "http://www.w3.org/2000/svg",
    "http://www.w3.org/1999/02/22-rdf-syntax-ns#",
    "http://purl.org/rss/1.0/",
    "http://www.opml.org/spec2",
    "http://www.springframework.org/schema/beans",
    "http://maven.apache.org/xsd/maven-4.0.0.xsd",
    "http://schemas.android.com/apk/res/android",
    "http://schemas.android.com/apk/res-auto",
}

# Known VPN/proxy ranges (common examples, not exhaustive)
VPN_RANGES = [
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.168.0.0/16"),
]


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def is_valid_ip(ip: str) -> bool:
    """Validate IPv4 address."""
    try:
        socket.inet_aton(ip)
        return True
    except socket.error:
        return False


def is_benign_uri_reference(url: str) -> bool:
    """Return True if the URL is a known DTD, XML schema, or namespace URI."""
    try:
        url_lower = url.strip().lower()
        if url_lower in BENIGN_URIS:
            return True
        if any(url_lower.startswith(uri.lower()) for uri in BENIGN_URIS):
            return True
        parsed = urlparse(url)
        path = parsed.path.lower()
        if path.endswith((".dtd", ".xsd", ".xsl", ".xml")):
            return True
    except Exception:
        logger.debug("Failed to check URI reference: %s", url)
    return False


def is_benign_url(url: str) -> bool:
    """Return True if URL belongs to a known benign SDK/documentation endpoint."""
    try:
        # Strip trailing punctuation that can be captured by URL regex
        url_clean = url.strip().rstrip(".,;:!?')")
        if is_benign_uri_reference(url_clean):
            return True
        parsed = urlparse(url_clean)
        if parsed.hostname:
            hostname = parsed.hostname.lower().lstrip("www.")
            if hostname in BENIGN_DOMAINS:
                return True
            # Also match any subdomain of a benign domain
            parts = parsed.hostname.lower().split(".")
            for i in range(len(parts)):
                if ".".join(parts[i:]) in BENIGN_DOMAINS:
                    return True
            # Pattern-based matching (e.g. crl.*, ocsp.*, *.readthedocs.io)
            host_lower = parsed.hostname.lower()
            for pattern in BENIGN_DOMAIN_PATTERNS:
                if re.search(pattern, host_lower):
                    return True
        for benign_path in BENIGN_URL_PATHS:
            if benign_path in parsed.path:
                return True
    except Exception:
        logger.debug("Failed to check benign URL: %s", url)
    return False


def is_ad_network(domain: str) -> bool:
    """Return True if domain belongs to a known ad/analytics network."""
    if not domain:
        return False
    domain_lower = domain.lower().lstrip("www.")
    if domain_lower in AD_NETWORK_DOMAINS:
        return True
    # Match subdomains (e.g. api.airpush.com -> airpush.com)
    parts = domain_lower.split(".")
    for i in range(len(parts)):
        if ".".join(parts[i:]) in AD_NETWORK_DOMAINS:
            return True
    return False


def classify_ip(ip: str) -> str:
    """Classify IP as private, loopback, vpn, or public."""
    if not is_valid_ip(ip):
        return "invalid"
    try:
        addr = ipaddress.ip_address(ip)
        if addr.is_loopback:
            return "loopback"
        if addr.is_private:
            return "private"
        # Check known VPN ranges (redundant with is_private but explicit)
        for net in VPN_RANGES:
            if addr in net:
                return "vpn"
        return "public"
    except ValueError:
        return "invalid"


def infer_communication_type(url: str, source_location: str) -> str:
    """Infer communication type from URL scheme and source context."""
    parsed = urlparse(url)
    source_lower = source_location.lower()

    if parsed.scheme in ("http", "https"):
        return "http_request"
    if "inetaddress" in source_lower or "dns" in source_lower:
        return "dns_query"
    if "socket" in source_lower:
        return "socket"
    if parsed.scheme in ("tcp", "udp"):
        return parsed.scheme
    return "other"


def parse_url(url: str) -> Optional[Dict[str, Any]]:
    """Parse URL into components."""
    try:
        parsed = urlparse(url)
        if parsed.scheme not in ("http", "https"):
            return None

        domain = parsed.hostname
        ip = None
        if domain:
            # Check if hostname is actually an IP
            if is_valid_ip(domain):
                ip = domain
                domain = None

        port = parsed.port
        if port is None and parsed.scheme == "http":
            port = 80
        elif port is None and parsed.scheme == "https":
            port = 443

        query_params = {k: v[0] if len(v) == 1 else v for k, v in parse_qs(parsed.query).items()}

        return {
            "protocol": parsed.scheme,
            "domain": domain,
            "ip": ip,
            "port": port,
            "path": parsed.path if parsed.path else "/",
            "query_params": query_params,
        }
    except Exception:
        logger.debug("Failed to parse URL: %s", url)
        return None


def calculate_c2_confidence(parsed: dict, source_context: str, ip_legitimacy: Optional[Dict] = None) -> float:
    """Calculate confidence score for a C2 record."""
    score = 0.5

    # Boost for valid URL structure
    if parsed["protocol"] in ("http", "https"):
        score += 0.2

    # Boost for public IP, private IP (VPN/proxy C2s), or real domain.
    # FIX: do not penalize private IPs — real C2 infrastructure frequently uses
    # them (e.g. Metasploit stagers behind VPNs).
    if parsed["ip"]:
        ip_class = classify_ip(parsed["ip"])
        if ip_class in ("public", "private", "vpn"):
            score += 0.25
        elif ip_class == "loopback":
            score -= 0.2

        # Incorporate IP legitimacy scoring
        if ip_legitimacy and ip_legitimacy.get("verdict") == "likely_malicious":
            score += 0.15
        elif ip_legitimacy and ip_legitimacy.get("verdict") == "uncertain":
            score += 0.05
    elif parsed["domain"]:
        # Real domain with TLD
        if "." in parsed["domain"] and len(parsed["domain"].split(".")[-1]) >= 2:
            score += 0.2

    # Boost for non-default path (suggests C2 endpoint)
    if parsed["path"] and parsed["path"] != "/":
        score += 0.15

    # Reduce confidence for known ad/analytics networks. These endpoints are
    # legitimate monetization infrastructure, but they commonly appear in
    # adware / grayware samples and should not be scored like malware C2s.
    if parsed["domain"] and is_ad_network(parsed["domain"]):
        score *= 0.5

    return round(min(1.0, max(0.0, score)), 4)


def enrich_with_circl(c2_records: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """
    Optionally enrich C2 records with CIRCL pSSL/pDNS data.

    Returns the records unmodified if CIRCL is not configured or the
    enrichment fails.
    """
    if not CIRCL_AVAILABLE:
        return c2_records

    try:
        client = CIRCLClient()
    except CIRCLAuthError:
        # Credentials not configured; skip enrichment silently
        return c2_records

    # CIRCL client expects items with ip/domain/url/cert_sha1 keys
    enrichment_input = []
    for record in c2_records:
        enrichment_input.append({
            "ip": record.get("ip"),
            "domain": record.get("domain"),
            "url": record.get("raw_url"),
            "cert_sha1": record.get("cert_sha1"),
        })

    try:
        enriched = client.enrich_c2_infrastructure(enrichment_input)
    except CIRCLClientError:
        return c2_records

    # Merge CIRCL data back into original records
    for original, circl_data in zip(c2_records, enriched):
        original["circl"] = circl_data.get("circl", {})

    return c2_records


# ---------------------------------------------------------------------------
# Main extraction
# ---------------------------------------------------------------------------


def extract_c2_infrastructure(payloads_result: dict, strings_result: dict) -> dict:
    """
    Full Step 5: Extract C2 infrastructure from payloads and source strings.

    Args:
        payloads_result: Output dict from Step 4.
        strings_result: Output dict from Step 2.

    Returns:
        dict with C2 records.
    """
    sample_id = payloads_result["sample_id"]
    work_dir = settings.WORK_DIR / sample_id
    work_dir.mkdir(parents=True, exist_ok=True)

    c2_records = []
    c2_id = 0
    seen_urls = set()

    # Extract URLs from decoded payloads
    for payload in payloads_result.get("payloads", []):
        payload_id = payload.get("payload_id", "")
        source_location = payload.get("source_location", "unknown")

        for artifact in payload.get("artifacts", []):
            if artifact["type"] == "url":
                url = artifact["value"]
                if url in seen_urls:
                    continue
                seen_urls.add(url)

                parsed = parse_url(url)
                if parsed is None or is_benign_url(url):
                    continue

                ip_legitimacy = None
                if parsed["ip"]:
                    ip_legitimacy = calculate_ip_legitimacy_score(
                        parsed["ip"], url, source_location
                    )

                confidence = calculate_c2_confidence(parsed, source_location, ip_legitimacy)
                record = {
                    "c2_id": f"c2_{c2_id:03d}",
                    "payload_id": payload_id,
                    "raw_url": url,
                    "protocol": parsed["protocol"],
                    "domain": parsed["domain"],
                    "ip": parsed["ip"],
                    "port": parsed["port"],
                    "path": parsed["path"],
                    "query_params": parsed["query_params"],
                    "ip_classification": classify_ip(parsed["ip"]) if parsed["ip"] else "n/a",
                    "communication_type": infer_communication_type(url, source_location),
                    "is_fallback": False,
                    "source_location": source_location,
                    "confidence": confidence,
                    "threat_category": "adware" if parsed["domain"] and is_ad_network(parsed["domain"]) else "malware",
                }
                if ip_legitimacy:
                    record["ip_legitimacy"] = ip_legitimacy
                c2_records.append(record)
                c2_id += 1

    # Also scan source strings directly for URLs not caught by payloads
    for category_name, items in strings_result.get("categories", {}).items():
        for item in items:
            value = item.get("value", "")
            if not isinstance(value, str):
                continue
            source_location = item.get("source", "unknown")

            for url in URL_RE.findall(value):
                if url in seen_urls:
                    continue
                seen_urls.add(url)

                parsed = parse_url(url)
                if parsed is None or is_benign_url(url):
                    continue

                ip_legitimacy = None
                if parsed["ip"]:
                    ip_legitimacy = calculate_ip_legitimacy_score(
                        parsed["ip"], url, source_location
                    )

                confidence = round(calculate_c2_confidence(parsed, source_location, ip_legitimacy), 4)
                record = {
                    "c2_id": f"c2_{c2_id:03d}",
                    "payload_id": None,
                    "raw_url": url,
                    "protocol": parsed["protocol"],
                    "domain": parsed["domain"],
                    "ip": parsed["ip"],
                    "port": parsed["port"],
                    "path": parsed["path"],
                    "query_params": parsed["query_params"],
                    "ip_classification": classify_ip(parsed["ip"]) if parsed["ip"] else "n/a",
                    "communication_type": infer_communication_type(url, source_location),
                    "is_fallback": False,
                    "source_location": source_location,
                    "confidence": confidence,
                    "threat_category": "adware" if parsed["domain"] and is_ad_network(parsed["domain"]) else "malware",
                }
                if ip_legitimacy:
                    record["ip_legitimacy"] = ip_legitimacy
                c2_records.append(record)
                c2_id += 1

    # Optional CIRCL enrichment (pSSL/pDNS) — never fail the pipeline
    c2_records = enrich_with_circl(c2_records)

    result = {
        "sample_id": sample_id,
        "total_c2s": len(c2_records),
        "c2_infrastructure": c2_records,
    }

    # Save intermediate result
    result_path = work_dir / "step5_c2s.json"
    with open(result_path, "w", encoding="utf-8") as f:
        json.dump(result, f, indent=2)

    return result


if __name__ == "__main__":
    import sys
    if len(sys.argv) < 3:
        print("Usage: python step5_c2_extraction.py <step4_payloads.json> <step2_strings.json>")
        sys.exit(1)
    with open(sys.argv[1], "r", encoding="utf-8") as f:
        payloads = json.load(f)
    with open(sys.argv[2], "r", encoding="utf-8") as f:
        strings = json.load(f)
    print(json.dumps(extract_c2_infrastructure(payloads, strings), indent=2))
