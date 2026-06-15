import pytest
from analysis.step5_c2_extraction import (
    extract_c2_infrastructure,
    classify_ip,
    parse_url,
    calculate_c2_confidence,
    is_benign_url,
    is_ad_network,
)
from analysis.step6_correlation import build_threat_chains
from analysis.step7_llm_assessment import fallback_assessment


def test_classify_ip():
    assert classify_ip("192.168.1.1") == "private"
    assert classify_ip("10.0.0.1") == "private"
    assert classify_ip("127.0.0.1") == "loopback"
    assert classify_ip("8.8.8.8") == "public"
    assert classify_ip("999.999.999.999") == "invalid"


def test_parse_url():
    parsed = parse_url("https://evil-domain.com:8443/api/data?key=value")
    assert parsed is not None
    assert parsed["protocol"] == "https"
    assert parsed["domain"] == "evil-domain.com"
    assert parsed["port"] == 8443
    assert parsed["path"] == "/api/data"
    assert parsed["query_params"] == {"key": "value"}


def test_extract_c2_from_payload():
    payloads_result = {
        "sample_id": "test_sample",
        "payloads": [
            {
                "payload_id": "pld_000",
                "encoding_id": "enc_000",
                "decoded_content": "https://evil-domain.com/c2",
                "artifacts": [
                    {"type": "url", "value": "https://evil-domain.com/c2", "confidence": 0.95}
                ],
                "source_location": "Decoder.java:15",
                "confidence": 0.9,
            }
        ],
    }
    strings_result = {
        "sample_id": "test_sample",
        "categories": {
            "string_literals": [],
            "byte_arrays": [],
            "numeric_constants": [],
            "resource_strings": [],
            "native_strings": [],
        },
    }
    result = extract_c2_infrastructure(payloads_result, strings_result)
    assert result["total_c2s"] == 1
    c2 = result["c2_infrastructure"][0]
    assert c2["protocol"] == "https"
    assert c2["domain"] == "evil-domain.com"
    assert c2["path"] == "/c2"


def test_build_threat_chain():
    encodings_result = {
        "sample_id": "test_sample",
        "encodings": [
            {
                "encoding_id": "enc_000",
                "type": "base64",
                "original_string": "aHR0cHM6Ly9ldmlsLWRvbWFpbi5jb20vYzI=",
                "confidence": 0.9,
                "entropy": 4.5,
                "source_location": "MainActivity.java:42",
                "decoded_preview": "https://evil-domain.com/c2",
                "validation_status": "valid",
            }
        ],
    }
    payloads_result = {
        "sample_id": "test_sample",
        "payloads": [
            {
                "payload_id": "pld_000",
                "encoding_id": "enc_000",
                "decoded_content": "https://evil-domain.com/c2",
                "artifacts": [
                    {"type": "url", "value": "https://evil-domain.com/c2", "confidence": 0.95}
                ],
                "source_location": "Decoder.java:15",
                "confidence": 0.9,
            }
        ],
    }
    c2_result = {
        "sample_id": "test_sample",
        "total_c2s": 1,
        "c2_infrastructure": [
            {
                "c2_id": "c2_000",
                "payload_id": "pld_000",
                "raw_url": "https://evil-domain.com/c2",
                "protocol": "https",
                "domain": "evil-domain.com",
                "ip": None,
                "port": 443,
                "path": "/c2",
                "query_params": {},
                "ip_classification": "n/a",
                "communication_type": "http_request",
                "is_fallback": False,
                "source_location": "NetworkTask.java:88",
                "confidence": 0.85,
            }
        ],
    }
    result = build_threat_chains(encodings_result, payloads_result, c2_result)
    assert result["total_chains"] == 1
    chain = result["threat_chains"][0]
    assert chain["severity"] in ("critical", "high", "medium", "low")
    assert len(chain["steps"]) == 5
    assert chain["steps"][0]["type"] == "encoded_string"
    assert chain["steps"][-1]["type"] == "c2_infrastructure"


def test_fallback_assessment_with_c2():
    chains_result = {"total_chains": 1}
    c2_result = {"total_c2s": 2}
    assessment = fallback_assessment(chains_result, c2_result)
    assert assessment["severity"] == "high"
    assert assessment["primary_threat"] == "c2_exfiltration"


# ---------------------------------------------------------------------------
# Repair regression tests
# ---------------------------------------------------------------------------

BENIGN_URLS = [
    "http://java.sun.com/dtd/properties.dtd",
    "http://www.w3.org/2001/XMLSchema",
    "http://android.com/",
    "https://schemas.android.com/apk/res/android",
]

MALICIOUS_URLS = [
    "https://47.116.192.150:444/cBYFilXD/HNbfYsYd8Shi2GHLBHyb-gDN9Hwbd6Itpm3jtM4fQpWreFMkgGdQyEmayxRNMBKyMfb6kZsi71hMzOxV8VpPRQrcsurLqQCsGxh7PvRmdUTTbgDb/",
    "https://evil-c2.example.com/beacon",
]


def test_benign_urls_are_filtered():
    for url in BENIGN_URLS:
        assert is_benign_url(url) is True, f"Expected {url} to be filtered"


def test_malicious_urls_are_not_filtered():
    for url in MALICIOUS_URLS:
        assert is_benign_url(url) is False, f"Expected {url} to be allowed"


def test_private_ip_c2_gets_high_confidence():
    url = "https://47.116.192.150:444/cBYFilXD/endpoint"
    parsed = parse_url(url)
    assert parsed is not None
    confidence = calculate_c2_confidence(parsed, "unknown")
    assert confidence >= 0.75, f"Expected high confidence for private IP C2, got {confidence}"


def test_malicious_domain_c2_gets_high_confidence():
    url = "http://malicious.tk/beacon"
    parsed = parse_url(url)
    assert parsed is not None
    confidence = calculate_c2_confidence(parsed, "unknown")
    assert confidence >= 0.60, f"Expected confidence >= 0.60 for malicious domain, got {confidence}"


def test_direct_string_url_confidence_not_penalized():
    """Direct URLs found in strings should not receive a 0.9 confidence penalty."""
    payloads_result = {
        "sample_id": "test_direct_string",
        "payloads": [],
    }
    strings_result = {
        "sample_id": "test_direct_string",
        "categories": {
            "string_literals": [
                {
                    "value": "https://47.116.192.150:444/cBYFilXD/endpoint",
                    "source": "MainActivity.java:10",
                }
            ],
            "byte_arrays": [],
            "numeric_constants": [],
            "resource_strings": [],
            "native_strings": [],
        },
    }
    result = extract_c2_infrastructure(payloads_result, strings_result)
    assert result["total_c2s"] == 1
    assert result["c2_infrastructure"][0]["confidence"] >= 0.75


def test_low_confidence_c2_excluded_from_chains():
    encodings_result = {
        "sample_id": "test_threshold",
        "encodings": [
            {
                "encoding_id": "enc_000",
                "type": "base64",
                "original_string": "aHR0cHM6Ly9ldmlsLWRvbWFpbi5jb20vYzI=",
                "confidence": 0.9,
                "entropy": 4.5,
                "source_location": "MainActivity.java:42",
                "decoded_preview": "https://evil-domain.com/c2",
                "validation_status": "valid",
            }
        ],
    }
    payloads_result = {
        "sample_id": "test_threshold",
        "payloads": [
            {
                "payload_id": "pld_000",
                "encoding_id": "enc_000",
                "decoded_content": "https://evil-domain.com/c2",
                "artifacts": [
                    {"type": "url", "value": "https://evil-domain.com/c2", "confidence": 0.95}
                ],
                "source_location": "Decoder.java:15",
                "confidence": 0.9,
            }
        ],
    }
    c2_result = {
        "sample_id": "test_threshold",
        "total_c2s": 1,
        "c2_infrastructure": [
            {
                "c2_id": "c2_000",
                "payload_id": "pld_000",
                "raw_url": "https://evil-domain.com/c2",
                "protocol": "https",
                "domain": "evil-domain.com",
                "ip": None,
                "port": 443,
                "path": "/c2",
                "query_params": {},
                "ip_classification": "n/a",
                "communication_type": "http_request",
                "is_fallback": False,
                "source_location": "NetworkTask.java:88",
                "confidence": 0.85,
            }
        ],
    }
    result = build_threat_chains(encodings_result, payloads_result, c2_result)
    assert result["total_chains"] == 1

    # Now drop the C2 confidence below the threshold and verify it is excluded.
    c2_result["c2_infrastructure"][0]["confidence"] = 0.4
    result = build_threat_chains(encodings_result, payloads_result, c2_result)
    assert result["total_chains"] == 1  # still one chain, but without the C2 step
    assert all(
        step["type"] != "c2_infrastructure"
        for chain in result["threat_chains"]
        for step in chain["steps"]
    )


def test_ad_network_domain_recognized():
    assert is_ad_network("api.airpush.com") is True
    assert is_ad_network("airpush.com") is True
    assert is_ad_network("www.leadbolt.net") is True
    assert is_ad_network("evil-domain.com") is False


def test_ad_network_c2_has_reduced_confidence():
    parsed = parse_url("http://api.airpush.com/v2/api.php")
    assert parsed is not None
    confidence = calculate_c2_confidence(parsed, "unknown")
    # Without ad-network penalty this would be 1.0; with penalty it is 0.5.
    assert confidence < 0.6, f"Expected ad network confidence < 0.6, got {confidence}"


def test_malicious_domain_c2_has_high_confidence():
    parsed = parse_url("http://gp-imports.com/android.php")
    assert parsed is not None
    confidence = calculate_c2_confidence(parsed, "unknown")
    assert confidence >= 0.9, f"Expected malicious domain confidence >= 0.9, got {confidence}"


def test_yandex_benign_domain_filtered():
    assert is_benign_url("http://yandex.ru") is True
