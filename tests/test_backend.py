import shutil
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from analysis.pipeline import run_pipeline
from backend.config import settings
from backend.main import app


@pytest.fixture
def client():
    return TestClient(app)


@pytest.fixture(scope="module")
def test_apk_path() -> Path:
    """Return a small, real APK for pipeline tests."""
    path = Path(
        "CICAndMal2017/_extracted_Adware-APKs/Adware/dowgin/"
        "1c4e357a8ec5f13de4ffd57cc2711afe.apk"
    )
    if not path.exists():
        pytest.skip("Test APK not found")
    return path


def _tools_available() -> bool:
    jadx = Path(settings.JADX_PATH)
    apktool = Path(settings.APKTOOL_PATH)
    return (jadx.exists() or shutil.which(settings.JADX_PATH)) and \
           (apktool.exists() or shutil.which(settings.APKTOOL_PATH))


def test_health_check(client):
    response = client.get("/")
    assert response.status_code == 200
    data = response.json()
    assert data["status"] == "ok"
    assert data["version"] == "1.0.0"


def test_api_samples(client):
    response = client.get("/api/samples")
    assert response.status_code == 200
    data = response.json()
    assert "samples" in data
    assert "total" in data
    assert data["total"] == len(data["samples"])
    if data["total"] > 0:
        assert data["samples"][0]["id"]
        assert "risk_score" in data["samples"][0]


def test_api_sample_detail(client):
    samples = client.get("/api/samples").json()["samples"]
    if not samples:
        pytest.skip("No analyzed samples available")
    sample_id = samples[0]["id"]
    response = client.get(f"/api/sample/{sample_id}")
    assert response.status_code == 200
    data = response.json()
    assert data["sample_id"] == sample_id
    assert "llm_assessment" in data
    assert "threat_chains" in data


def test_api_graph(client):
    samples = client.get("/api/samples").json()["samples"]
    if not samples:
        pytest.skip("No analyzed samples available")
    sample_id = samples[0]["id"]
    response = client.get(f"/api/graph/{sample_id}")
    assert response.status_code == 200
    data = response.json()
    assert "nodes" in data
    assert "edges" in data
    assert data["total_nodes"] >= 1


def test_api_clusters(client):
    response = client.get("/api/clusters")
    assert response.status_code == 200
    data = response.json()
    assert "samples" in data
    assert data["total_samples"] == len(data["samples"])
    if data["samples"]:
        sample = data["samples"][0]
        assert "x" in sample
        assert "y" in sample
        assert "z" in sample


def test_api_timeline(client):
    samples = client.get("/api/samples").json()["samples"]
    if not samples:
        pytest.skip("No analyzed samples available")
    sample_id = samples[0]["id"]
    response = client.get(f"/api/timeline/{sample_id}")
    assert response.status_code == 200
    data = response.json()
    assert "chains" in data


def test_api_sample_not_found(client):
    response = client.get("/api/sample/nonexistent")
    assert response.status_code == 404


def test_analyze_missing_apk(client):
    response = client.post("/analyze", json={"apk_path": "D:/does/not/exist.apk"})
    assert response.status_code == 400


def test_websocket_connection(client):
    with client.websocket_connect("/ws") as websocket:
        websocket.send_text('{"action": "ping"}')
        data = websocket.receive_text()
        assert "pong" in data


@pytest.mark.skipif(not _tools_available(), reason="JADX/APKTool not configured")
def test_full_pipeline_writes_to_work_dir(client, test_apk_path):
    """End-to-end: run the full pipeline on an APK and verify outputs in WORK_DIR."""
    result = run_pipeline(str(test_apk_path))
    sample_id = result["sample_id"]

    result_path = settings.WORK_DIR / sample_id / "pipeline_result.json"
    assert result_path.exists(), f"Expected result at {result_path}"

    response = client.get(f"/api/sample/{sample_id}")
    assert response.status_code == 200
    data = response.json()
    assert data["sample_id"] == sample_id
    assert "metadata" in data
