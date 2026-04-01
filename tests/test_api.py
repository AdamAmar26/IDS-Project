import sys
import os

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "backend"))

import pytest
from fastapi.testclient import TestClient
from app.main import app


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
    r = client.get("/events?limit=5")
    assert r.status_code == 200
    assert isinstance(r.json(), list)


def test_features(client):
    r = client.get("/features?limit=5")
    assert r.status_code == 200
    assert isinstance(r.json(), list)


def test_alerts(client):
    r = client.get("/alerts?limit=5")
    assert r.status_code == 200
    assert isinstance(r.json(), list)


def test_incidents_list(client):
    r = client.get("/incidents?limit=5")
    assert r.status_code == 200
    assert isinstance(r.json(), list)


def test_incident_not_found(client):
    r = client.get("/incidents/999999")
    assert r.status_code == 404


def test_metrics_summary(client):
    r = client.get("/metrics/summary")
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
    r = client.post("/auth/token", json={"username": "admin", "password": "admin"})
    assert r.status_code == 200
    data = r.json()
    assert "access_token" in data
    assert data["token_type"] == "bearer"


def test_auth_token_invalid(client):
    r = client.post("/auth/token", json={"username": "wrong", "password": "wrong"})
    assert r.status_code == 401


def test_simulate_brute_force(client):
    r = client.post("/admin/simulate?scenario=brute_force_portscan")
    assert r.status_code == 200
    data = r.json()
    assert data["events_injected"] > 0


def test_simulate_unknown_scenario(client):
    r = client.post("/admin/simulate?scenario=unknown")
    assert r.status_code == 400


def test_force_train_too_few(client):
    r = client.post("/admin/train")
    assert r.status_code in (200, 400)
