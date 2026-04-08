import os

import pytest
from fastapi.testclient import TestClient

from app.main import app

API_KEY = os.environ.get("IDS_API_KEY", "test-api-key-for-ci")
AUTH_HEADERS = {"X-API-Key": API_KEY}


@pytest.fixture(scope="module")
def client():
    with TestClient(app) as c:
        yield c


def test_health(client):
    r = client.get("/health")
    assert r.status_code == 200
    data = r.json()
    assert data["status"] == "ok"
    assert "model_trained" in data
    assert "min_training_samples" in data
    assert "security_log_available" in data


def test_events(client):
    r = client.get("/events?limit=5", headers=AUTH_HEADERS)
    assert r.status_code == 200
    assert isinstance(r.json(), list)


def test_features(client):
    r = client.get("/features?limit=5", headers=AUTH_HEADERS)
    assert r.status_code == 200
    assert isinstance(r.json(), list)


def test_alerts(client):
    r = client.get("/alerts?limit=5", headers=AUTH_HEADERS)
    assert r.status_code == 200
    assert isinstance(r.json(), list)


def test_incidents_list(client):
    r = client.get("/incidents?limit=5", headers=AUTH_HEADERS)
    assert r.status_code == 200
    assert isinstance(r.json(), list)


def test_incident_not_found(client):
    r = client.get("/incidents/999999", headers=AUTH_HEADERS)
    assert r.status_code == 404


def test_metrics_summary(client):
    r = client.get("/metrics/summary", headers=AUTH_HEADERS)
    assert r.status_code == 200
    data = r.json()
    assert "total_events" in data
    assert "model_trained" in data
    assert "min_training_samples" in data
    assert "security_log_available" in data


def test_prometheus_metrics(client):
    r = client.get("/metrics")
    assert r.status_code == 200
    assert "ids_model_trained" in r.text


def test_auth_token(client):
    password = os.environ.get("IDS_ADMIN_PASSWORD", "admin")
    r = client.post(
        "/auth/token",
        json={"username": "admin", "password": password},
    )
    assert r.status_code == 200
    data = r.json()
    assert "access_token" in data
    assert data["token_type"] == "bearer"


def test_auth_token_invalid(client):
    r = client.post("/auth/token", json={"username": "wrong", "password": "wrong"})
    assert r.status_code == 401


def test_unauthenticated_request_rejected(client):
    r = client.get("/events?limit=5")
    assert r.status_code in (401, 403)


def test_simulate_brute_force(client):
    r = client.post("/admin/simulate?scenario=brute_force_portscan", headers=AUTH_HEADERS)
    assert r.status_code == 200
    data = r.json()
    assert data["events_injected"] > 0


def test_simulate_unknown_scenario(client):
    r = client.post("/admin/simulate?scenario=unknown", headers=AUTH_HEADERS)
    assert r.status_code == 400


def test_force_train_too_few(client):
    r = client.post("/admin/train", headers=AUTH_HEADERS)
    assert r.status_code in (200, 400)


def test_summary_endpoint(client):
    r = client.get("/summary", headers=AUTH_HEADERS)
    assert r.status_code == 200
    data = r.json()
    assert "briefing" in data
    assert "data" in data
    assert "generated_at" in data
    assert "open_incidents" in data["data"]
    assert "severity_counts" in data["data"]
    assert "trend" in data["data"]


def test_incident_status_validation(client):
    r = client.patch("/incidents/1/status?status=invalid_status", headers=AUTH_HEADERS)
    assert r.status_code in (404, 422)


def test_incident_valid_status_values(client):
    for status in ["open", "acknowledged", "investigating", "resolved", "closed"]:
        r = client.patch(f"/incidents/1/status?status={status}", headers=AUTH_HEADERS)
        assert r.status_code in (200, 404)
