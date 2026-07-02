# tests/analysis/test_step17_family_clustering.py
import hashlib
from analysis.step17_family_clustering import (
    hash_method_signature,
    build_sample_signature,
    match_against_index,
)
from analysis.cross_sample_index import load_or_build_index


def test_hash_method_signature():
    sig = hash_method_signature("Lcom/example/Main;->onCreate(Landroid/os/Bundle;)V")
    assert len(sig) == 64
    assert isinstance(sig, str)


def test_build_sample_signature():
    result = build_sample_signature([])
    assert result["total_methods"] == 0

    result = build_sample_signature([
        {"class": "com.example.Main", "method": "onCreate", "descriptor": "(Landroid/os/Bundle;)V"},
        {"class": "com.example.Main", "method": "onResume", "descriptor": "()V"},
    ])
    assert result["total_methods"] == 2
    assert len(result["method_signatures"]) == 2
    assert len(result["expanded_signature_hashes"]) == 10


def test_match_against_index_empty():
    result = match_against_index({"method_signatures": []}, {})
    assert result["matches"] == []
    assert result["best_match"] is None


def test_match_against_index_with_data():
    query_sigs = {
        "method_signatures": [
            hashlib.sha256("test".encode()).hexdigest()
        ],
        "expanded_signature_hashes": ["abc", "def"],
    }
    index = {
        "samples": {
            "sample_A": {
                "family": "Joker",
                "method_signatures": [hashlib.sha256("test".encode()).hexdigest()],
                "expanded_signature_hashes": ["abc"],
                "signature_count": 1,
            }
        }
    }
    result = match_against_index(query_sigs, index)
    assert len(result["matches"]) > 0


def test_load_or_build_index():
    # Note: depends on backend.config.settings — needs proper import setup
    # In a real test environment with mocking, this would mock settings.WORK_DIR
    pass  # Placeholder for integration test


def test_index_constants():
    """Verify module-level constants resolve without config."""
    from analysis.cross_sample_index import INDEX_PATH
    assert str(INDEX_PATH).endswith("cross_sample_index.json")
