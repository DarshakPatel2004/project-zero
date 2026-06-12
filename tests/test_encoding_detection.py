import pytest
from analysis.step3_encoding_detection import (
    detect_encoding,
    try_base64_decode,
    try_hex_decode,
    has_meaningful_content,
)
from analysis.step4_decoding import decode_payloads, extract_artifacts


def test_base64_detection():
    # Base64 of "https://evil-domain.com/c2"
    original = "aHR0cHM6Ly9ldmlsLWRvbWFpbi5jb20vYzI="
    strings_result = {
        "sample_id": "test_sample",
        "categories": {
            "string_literals": [
                {
                    "value": original,
                    "entropy": 4.5,
                    "source": "Test.java:10",
                }
            ],
            "byte_arrays": [],
            "numeric_constants": [],
            "resource_strings": [],
            "native_strings": [],
        },
    }
    result = detect_encoding(strings_result)
    assert result["total_encodings"] >= 1
    enc = result["encodings"][0]
    assert enc["type"] == "base64"
    assert "evil-domain.com" in enc["decoded_preview"]


def test_hex_detection():
    # Hex of "hello world"
    original = "68656c6c6f20776f726c64"
    strings_result = {
        "sample_id": "test_sample",
        "categories": {
            "string_literals": [
                {
                    "value": original,
                    "entropy": 3.2,
                    "source": "Test.java:20",
                }
            ],
            "byte_arrays": [],
            "numeric_constants": [],
            "resource_strings": [],
            "native_strings": [],
        },
    }
    result = detect_encoding(strings_result)
    assert result["total_encodings"] >= 1
    enc = result["encodings"][0]
    assert enc["type"] == "hex"
    assert "hello world" in enc["decoded_preview"]


def test_xor_detection():
    # XOR of a URL with key 0xA7 (produces mostly non-printable bytes,
    # so only the correct key should exceed the printable threshold)
    original = "https://secret-server.com/api/data"
    key = 0xA7
    encoded = "".join(chr(ord(c) ^ key) for c in original)
    strings_result = {
        "sample_id": "test_sample",
        "categories": {
            "string_literals": [
                {
                    "value": encoded,
                    "entropy": 6.5,
                    "source": "Test.java:30",
                }
            ],
            "byte_arrays": [],
            "numeric_constants": [],
            "resource_strings": [],
            "native_strings": [],
        },
    }
    result = detect_encoding(strings_result)
    assert result["total_encodings"] >= 1
    enc = result["encodings"][0]
    assert enc["type"] == "xor"
    assert "secret-server.com" in enc["decoded_preview"]


def test_decoding_extracts_url():
    encodings_result = {
        "sample_id": "test_sample",
        "encodings": [
            {
                "encoding_id": "enc_000",
                "type": "base64",
                "original_string": "aHR0cHM6Ly9ldmlsLWRvbWFpbi5jb20vYzI=",
                "confidence": 0.9,
                "entropy": 4.5,
                "source_location": "Test.java:10",
                "decoded_preview": "https://evil-domain.com/c2",
                "validation_status": "valid",
            }
        ],
    }
    result = decode_payloads(encodings_result)
    assert result["total_payloads"] == 1
    payload = result["payloads"][0]
    assert any(a["type"] == "url" and "evil-domain.com" in a["value"] for a in payload["artifacts"])


def test_has_meaningful_content():
    assert has_meaningful_content("Visit https://evil.com/path") is True
    assert has_meaningful_content("Contact admin@example.com") is True
    assert has_meaningful_content("just some random text") is False
