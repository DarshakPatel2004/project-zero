import pytest
from fastapi.testclient import TestClient

from backend.main import app, manager, sample_results


@pytest.fixture
def client():
    return TestClient(app)


def test_health_check(client):
    response = client.get("/")
    assert response.status_code == 200
    data = response.json()
    assert data["status"] == "ok"
    assert data["version"] == "1.0.0"


def test_list_samples_empty(client):
    response = client.get("/samples")
    assert response.status_code == 200
    assert response.json()["samples"] == []


def test_get_sample_not_found(client):
    response = client.get("/samples/nonexistent")
    assert response.status_code == 404


def test_analyze_missing_apk(client):
    response = client.post("/analyze", json={"apk_path": "/does/not/exist.apk"})
    assert response.status_code == 400


def test_websocket_connection(client):
    with client.websocket_connect("/ws") as websocket:
        websocket.send_text('{"action": "ping"}')
        data = websocket.receive_text()
        assert "pong" in data
