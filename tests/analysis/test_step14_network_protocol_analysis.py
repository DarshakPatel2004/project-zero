"""Unit tests for Step 14 network protocol analysis."""

import pytest
from analysis.step14_network_protocol_analysis import (
    analyze_network_protocols,
    BENIGN_DOMAINS,
)


def test_analyze_network_protocols_empty():
    result = analyze_network_protocols([])
    assert result["total_endpoints"] == 0
    assert result["total_c2"] == 0
    assert result["total_suspicious"] == 0
    assert result["endpoints"] == []
    assert result["c2_endpoints"] == []


def test_analyze_network_protocols_benign():
    strings = [
        "https://www.google.com/search",
        "https://github.com/opencode",
        "https://developer.android.com/reference",
    ]
    result = analyze_network_protocols(strings)
    assert result["total_endpoints"] > 0
    assert result["total_c2"] == 0


def test_analyze_network_protocols_suspicious():
    strings = [
        "https://192.168.1.1:4444/gate",
        "http://10.0.0.5:1337/command",
    ]
    result = analyze_network_protocols(strings)
    assert result["total_c2"] > 0
    assert result["total_suspicious"] > 0

    c2_domains = {e["domain"] for e in result["c2_endpoints"]}
    c2_ips = {e["ip"] for e in result["c2_endpoints"]}
    assert "192.168.1.1" in c2_ips or "192.168.1.1" in c2_domains


def test_analyze_network_protocols_mixed():
    strings = [
        "https://www.google.com/search",
        "https://malicious.example.com:8443/panel",
        "https://github.com",
    ]
    result = analyze_network_protocols(strings)
    assert result["total_endpoints"] >= 2
    assert result["total_c2"] >= 1
    assert result["total_suspicious"] >= 1


def test_benign_domains_contains_common():
    assert "google.com" in BENIGN_DOMAINS
    assert "github.com" in BENIGN_DOMAINS


def test_analyze_network_protocols_ip_only():
    strings = ["http://10.0.0.1:8080/admin"]
    result = analyze_network_protocols(strings)
    assert result["total_endpoints"] == 1
    assert result["total_c2"] == 1
    assert result["endpoints"][0]["ip"] == "10.0.0.1"
