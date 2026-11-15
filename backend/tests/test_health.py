from fastapi.testclient import TestClient

from app.main import app

client = TestClient(app)  # no context manager: the lifespan (and the database) is not started


def test_health():
    response = client.get("/health")
    assert response.status_code == 200
    assert response.json()["status"] == "ok"


def test_openapi_lists_the_v1_routes():
    paths = client.get("/openapi.json").json()["paths"]
    for path in (
        "/api/v1/events",
        "/api/v1/incidents",
        "/api/v1/analyze",
        "/api/v1/analyze/auto",
        "/api/v1/metrics",
    ):
        assert path in paths


def test_analyze_rejects_a_request_without_events():
    assert client.post("/api/v1/analyze", json={}).status_code == 422
