import pytest
from analysis.step5_c2_extraction import extract_c2_infrastructure, classify_ip, parse_url
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
