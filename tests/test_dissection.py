"""
Tests for APK dissection backend.
"""

import json
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from backend.config import settings
from backend.main import app
from backend.dissection import APKDissector, load_dissection
from backend.transformers import load_all_results


@pytest.fixture
def client():
    return TestClient(app)


@pytest.fixture(scope="module")
def test_apk_path() -> Path:
    """Return a small, real APK for direct dissection tests."""
    path = Path(
        "CICAndMal2017/_extracted_Scareware-APKs/Scareware/virusShield/"
        "002485c5c96f0681a4eccee5b69c5f50.apk"
    )
    if not path.exists():
        pytest.skip("Test APK not found")
    return path


@pytest.fixture(scope="module")
def existing_sample_id() -> str:
    """Return an existing analyzed sample id whose APK is still on disk."""
    results = load_all_results()
    for result in results:
        sample_id = result["sample_id"]
        sample_name = result.get("metadata", {}).get("sample_name")
        if not sample_name:
            continue
        # Check whether the APK is locatable
        candidates = [
            settings.SAMPLES_DIR / "malware" / "androzoo_drebin" / sample_name,
            settings.SAMPLES_DIR / "malware" / sample_name,
        ]
        for candidate in candidates:
            if candidate.exists():
                return sample_id
    pytest.skip("No existing analyzed sample with APK on disk")


class TestAPKDissector:
    def test_dissect_returns_expected_keys(self, test_apk_path):
        dissector = APKDissector(str(test_apk_path))
        data = dissector.dissect()
        assert "metadata" in data
        assert "manifest" in data
        assert "permissions" in data
        assert "components" in data
        assert "native_libs" in data
        assert "resources" in data
        assert "dex_stats" in data
        assert "file_structure" in data

    def test_metadata(self, test_apk_path):
        dissector = APKDissector(str(test_apk_path))
        meta = dissector.extract_metadata()
        assert meta["package_name"] == "com.agilebinary.phonebeagle"
        assert meta["file_size_bytes"] > 0
        assert meta["version_code"] is not None

    def test_permissions(self, test_apk_path):
        dissector = APKDissector(str(test_apk_path))
        perms = dissector.extract_permissions()
        assert len(perms) > 0
        names = {p["name"] for p in perms}
        assert "android.permission.INTERNET" in names
        for perm in perms:
            assert "protection_level" in perm
            assert perm["protection_level"] in {"dangerous", "signature", "normal", "unknown"}

    def test_components(self, test_apk_path):
        dissector = APKDissector(str(test_apk_path))
        comps = dissector.extract_components()
        assert len(comps["activities"]) > 0
        for activity in comps["activities"]:
            assert "name" in activity
            assert "exported" in activity

    def test_dex_stats(self, test_apk_path):
        dissector = APKDissector(str(test_apk_path))
        stats = dissector.extract_dex_stats()
        assert stats["dex_count"] >= 1
        assert stats["total_classes"] > 0
        assert stats["total_methods"] > 0
        assert 0 <= stats["entropy"] <= 8

    def test_json_serializable(self, test_apk_path):
        dissector = APKDissector(str(test_apk_path))
        data = dissector.dissect()
        # Must not raise
        json.dumps(data)

    def test_load_dissection_missing(self):
        assert load_dissection(str(settings.WORK_DIR), "nonexistent_sample_id") is None


class TestDissectionEndpoints:
    def test_dissection_full(self, client, existing_sample_id):
        response = client.get(f"/api/sample/{existing_sample_id}/dissection")
        assert response.status_code == 200
        data = response.json()
        assert "metadata" in data
        assert "permissions" in data
        assert "dex_stats" in data

    def test_dissection_manifest(self, client, existing_sample_id):
        response = client.get(f"/api/sample/{existing_sample_id}/dissection/manifest")
        assert response.status_code == 200
        data = response.json()
        assert "manifest" in data
        assert "package" in data["manifest"]

    def test_dissection_permissions(self, client, existing_sample_id):
        response = client.get(f"/api/sample/{existing_sample_id}/dissection/permissions")
        assert response.status_code == 200
        data = response.json()
        assert "permissions" in data
        assert isinstance(data["permissions"], list)

    def test_dissection_components(self, client, existing_sample_id):
        response = client.get(f"/api/sample/{existing_sample_id}/dissection/components")
        assert response.status_code == 200
        data = response.json()
        assert "components" in data
        assert "activities" in data["components"]

    def test_dissection_dex(self, client, existing_sample_id):
        response = client.get(f"/api/sample/{existing_sample_id}/dissection/dex")
        assert response.status_code == 200
        data = response.json()
        assert "dex_stats" in data
        assert data["dex_stats"]["dex_count"] >= 1

    def test_dissection_classes(self, client, existing_sample_id):
        response = client.get(f"/api/sample/{existing_sample_id}/dissection/classes")
        assert response.status_code == 200
        data = response.json()
        assert "classes" in data
        assert isinstance(data["classes"], list)

    def test_dissection_code_existing_class(self, client, existing_sample_id):
        # Fetch class list first
        classes_resp = client.get(f"/api/sample/{existing_sample_id}/dissection/classes")
        classes = classes_resp.json().get("classes", [])
        if not classes:
            pytest.skip("No decompiled classes available")
        class_name = classes[0]
        response = client.get(
            f"/api/sample/{existing_sample_id}/dissection/code/{class_name}"
        )
        assert response.status_code == 200
        data = response.json()
        assert data["class_name"] == class_name
        assert "code" in data
        assert len(data["code"]) > 0

    def test_dissection_code_missing_class(self, client, existing_sample_id):
        response = client.get(
            f"/api/sample/{existing_sample_id}/dissection/code/DefinitelyNotARealClass"
        )
        assert response.status_code == 404

    def test_dissection_strings(self, client, existing_sample_id):
        response = client.get(f"/api/sample/{existing_sample_id}/dissection/strings")
        assert response.status_code == 200
        data = response.json()
        assert "sample_id" in data
        assert "categories" in data

    def test_dissection_not_found(self, client):
        response = client.get("/api/sample/nonexistent_sample_id/dissection")
        assert response.status_code == 404
