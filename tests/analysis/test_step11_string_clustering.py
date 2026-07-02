# tests/analysis/test_step11_string_clustering.py
from analysis.step11_string_clustering import (
    cluster_high_entropy_strings,
    string_similarity,
    classify_obfuscation_type,
)

def test_cluster_high_entropy_strings_empty():
    result = cluster_high_entropy_strings([])
    assert result["clusters"] == []
    assert result["total_clusters"] == 0


def test_cluster_high_entropy_strings_with_data():
    samples = [
        "aWQ9MSZ1cmw9aHR0cDovL2V2aWwuY29tL3BheWxvYWQ=",
        "cGFzc3dvcmQ9YWRtaW4xMjM=",
        "dXNlcj1hZG1pbiZwYXNzPXNlY3JldA==",
        "open", "close", "save", "load",
    ]
    result = cluster_high_entropy_strings(samples)
    assert result["total_clusters"] >= 0
    assert "high_entropy_strings" in result
    for s in result["high_entropy_strings"]:
        assert s["entropy"] >= 0.0
        assert s["entropy"] <= 8.0


def test_string_similarity():
    sim = string_similarity("base64datahere", "base64dataalso")
    assert 0.0 <= sim <= 1.0


def test_classify_obfuscation_type():
    result = classify_obfuscation_type("QUJDMTIzKy9kZWY0NTY9PXdoYXRldmVy")
    assert result == "base64"
    result = classify_obfuscation_type("deadbeefcafebabe")
    assert result == "hex"
    result = classify_obfuscation_type("hello world")
    assert result == "plaintext"
