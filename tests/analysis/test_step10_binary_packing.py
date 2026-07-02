import json
from pathlib import Path
from analysis.step10_binary_packing import (
    detect_binary_packing,
    detect_dex_in_dex,
    analyze_dex_sections,
    PACKING_INDICATORS,
)

def test_detect_binary_packing_empty():
    result = detect_binary_packing({})
    assert result["packing_detected"] is False
    assert result["obfuscation_score"] == 0.0
    assert "indicators" in result


def test_detect_binary_packing_with_dex_sections():
    sections = {
        ".text": {"size": 500000, "entropy": 7.9},
        ".data": {"size": 1000, "entropy": 4.5},
    }
    result = analyze_dex_sections(sections)
    assert len(result["scored_indicators"]) > 0
    assert result["obfuscation_score"] > 0


def test_detect_dex_in_dex():
    result = detect_dex_in_dex(["classes.dex", "classes2.dex", "r%le3.dex"])
    assert result["suspicious"] is True
    assert any("unexpected_dex_name" in i for i in result.get("indicators", []))


def test_packing_indicators_defined():
    assert len(PACKING_INDICATORS) > 0
    for pi in PACKING_INDICATORS:
        assert "name" in pi
        assert "weight" in pi
        assert 0 < pi["weight"] <= 100
