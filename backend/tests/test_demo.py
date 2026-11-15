import pytest
from fastapi.testclient import TestClient

from app.core import demo
from app.core.config import settings
from app.main import app

client = TestClient(app)  # no lifespan: these paths must answer before touching the database

EVENT = {
    "source": "auth.log",
    "event_type": "authentication_failure",
    "timestamp": "2026-11-02T09:00:00Z",
    "raw_data": {"src_ip": "203.0.113.57"},
}


@pytest.fixture
def demo_on(monkeypatch):
    monkeypatch.setattr(settings, "demo_mode", True)


class Clock:
    def __init__(self, now: float = 1_000_000.0) -> None:
        self.now = now

    def __call__(self) -> float:
        return self.now


def test_health_reports_demo_mode(demo_on):
    assert client.get("/health").json()["demo_mode"] is True


@pytest.mark.parametrize(
    ("method", "path"),
    [
        ("POST", "/api/v1/events"),
        ("POST", "/api/v1/events/batch"),
        ("POST", "/api/v1/events/cef"),
        ("POST", "/api/v1/incidents"),
        ("PATCH", "/api/v1/incidents/1"),
        ("POST", "/api/v1/analyze/auto"),
    ],
)
def test_demo_blocks_writes(demo_on, method, path):
    response = client.request(method, path, json={})
    assert response.status_code == 403
    assert "read-only demo" in response.json()["detail"]


def test_demo_rejects_oversized_batches(demo_on, monkeypatch):
    monkeypatch.setattr(settings, "demo_max_events", 2)
    response = client.post("/api/v1/analyze", json={"events": [EVENT] * 3})
    assert response.status_code == 413


def test_demo_rate_limits_analyze(demo_on, monkeypatch):
    monkeypatch.setattr(demo, "quota", demo.AnalyzeQuota(per_ip_per_hour=0, per_day=10))
    response = client.post("/api/v1/analyze", json={"events": [EVENT]})
    assert response.status_code == 429


def test_writes_are_open_outside_demo_mode():
    assert not settings.demo_mode
    # 422: the empty body reaches validation instead of being refused by the demo guard
    assert client.post("/api/v1/analyze/auto", json={"window_minutes": 0}).status_code == 422


def test_quota_per_ip_window_slides():
    clock = Clock()
    quota = demo.AnalyzeQuota(per_ip_per_hour=2, per_day=100, clock=clock)
    assert quota.take("a") is None
    assert quota.take("a") is None
    assert "2 analyses per hour" in quota.take("a")
    assert quota.take("b") is None  # other visitors are counted separately
    clock.now += 3600
    assert quota.take("a") is None


def test_quota_daily_cap_is_global_and_resets():
    clock = Clock(now=86_400 * 20_000)
    quota = demo.AnalyzeQuota(per_ip_per_hour=100, per_day=2, clock=clock)
    assert quota.take("a") is None
    assert quota.take("b") is None
    assert "budget for today" in quota.take("c")
    clock.now += 86_400
    assert quota.take("c") is None


def test_client_ip_prefers_the_proxy_header():
    scope = {
        "type": "http",
        "headers": [(b"x-forwarded-for", b"198.51.100.7, 172.18.0.5")],
        "client": ("172.18.0.5", 1234),
    }
    from starlette.requests import Request

    assert demo.client_ip(Request(scope)) == "198.51.100.7"
    assert demo.client_ip(Request({**scope, "headers": []})) == "172.18.0.5"
