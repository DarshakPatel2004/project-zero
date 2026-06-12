import pytest
from fastapi.testclient import TestClient

from backend.main import app


@pytest.fixture
def client():
    return TestClient(app)


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
    assert data["total"] >= 50  # We have 56 analyzed samples
    assert data["samples"][0]["id"]
    assert "risk_score" in data["samples"][0]


def test_api_sample_detail(client):
    # Get first sample ID
    samples = client.get("/api/samples").json()["samples"]
    sample_id = samples[0]["id"]
    response = client.get(f"/api/sample/{sample_id}")
    assert response.status_code == 200
    data = response.json()
    assert data["sample_id"] == sample_id
    assert "llm_assessment" in data
    assert "threat_chains" in data


def test_api_graph(client):
    samples = client.get("/api/samples").json()["samples"]
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
    assert data["total_samples"] >= 50
    sample = data["samples"][0]
    assert "x" in sample
    assert "y" in sample
    assert "z" in sample


def test_api_timeline(client):
    samples = client.get("/api/samples").json()["samples"]
    sample_id = samples[0]["id"]
    response = client.get(f"/api/timeline/{sample_id}")
    assert response.status_code == 200
    data = response.json()
    assert "chains" in data


def test_api_sample_not_found(client):
    response = client.get("/api/sample/nonexistent")
    assert response.status_code == 404


def test_analyze_missing_apk(client):
    response = client.post("/analyze", json={"apk_path": "/does/not/exist.apk"})
    assert response.status_code == 400


def test_websocket_connection(client):
    with client.websocket_connect("/ws") as websocket:
        websocket.send_text('{"action": "ping"}')
        data = websocket.receive_text()
        assert "pong" in data
