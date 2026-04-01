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


def test_metrics(client):
    r = client.get("/metrics")
    assert r.status_code == 200
    data = r.json()
    assert "total_events" in data
    assert "model_trained" in data
    assert "min_training_samples" in data
    assert "security_log_available" in data


def test_force_train_too_few(client):
    r = client.post("/admin/train")
    assert r.status_code in (200, 400)
