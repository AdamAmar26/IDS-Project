"""Tests for SOAR validation and hunt execution endpoints."""

import os

import pytest
from fastapi.testclient import TestClient
from jose import jwt

from app.config import JWT_ALGORITHM
from app.main import app

JWT_SECRET = os.environ.get("IDS_JWT_SECRET", "test-secret-not-for-production")


@pytest.fixture(scope="module")
def client():
    with TestClient(app) as c:
        yield c


def _jwt_headers() -> dict:
    from datetime import UTC, datetime, timedelta

    payload = {"sub": "admin", "exp": datetime.now(UTC) + timedelta(hours=1)}
    token = jwt.encode(payload, JWT_SECRET, algorithm=JWT_ALGORITHM)
    return {"Authorization": f"Bearer {token}"}


def test_soar_rejects_invalid_ip(client):
    headers = _jwt_headers()
    r = client.post(
        "/soar/action",
        json={"action": "block_ip", "target": "not-an-ip", "dry_run": True},
        headers=headers,
    )
    assert r.status_code == 422


def test_soar_rejects_live_without_confirm(client):
    os.environ["IDS_SOAR_ENABLED"] = "true"
    headers = _jwt_headers()
    r = client.post(
        "/soar/action",
        json={"action": "block_ip", "target": "1.2.3.4", "dry_run": False, "confirm": False},
        headers=headers,
    )
    assert r.status_code == 400
    os.environ["IDS_SOAR_ENABLED"] = "false"


def test_soar_disabled_returns_403(client):
    os.environ["IDS_SOAR_ENABLED"] = "false"
    headers = _jwt_headers()
    r = client.post(
        "/soar/action",
        json={"action": "block_ip", "target": "1.2.3.4", "dry_run": True},
        headers=headers,
    )
    assert r.status_code == 403


def test_hunt_create_and_list(client):
    headers = _jwt_headers()
    r = client.post(
        "/hunts",
        json={"name": "Test Hunt", "filters": {"event_type": "connection"}},
        headers=headers,
    )
    assert r.status_code == 200
    data = r.json()
    assert data["name"] == "Test Hunt"
    hunt_id = data["id"]

    r = client.get("/hunts", headers=headers)
    assert r.status_code == 200
    names = [h["name"] for h in r.json()]
    assert "Test Hunt" in names

    return hunt_id


def test_hunt_run(client):
    headers = _jwt_headers()

    r = client.post(
        "/hunts",
        json={"name": "Run Test", "filters": {"event_type": "login_failure"}},
        headers=headers,
    )
    hunt_id = r.json()["id"]

    r = client.post(f"/hunts/{hunt_id}/run", headers=headers)
    assert r.status_code == 200
    data = r.json()
    assert "total" in data
    assert "events" in data
    assert "alerts" in data


def test_hunt_run_not_found(client):
    headers = _jwt_headers()
    r = client.post("/hunts/99999/run", headers=headers)
    assert r.status_code == 404


def test_audit_with_filters(client):
    headers = _jwt_headers()
    r = client.get("/audit?limit=10", headers=headers)
    assert r.status_code == 200
    data = r.json()
    assert "total" in data
    assert "items" in data


def test_audit_actor_filter(client):
    headers = _jwt_headers()
    r = client.get("/audit?actor=admin&limit=5", headers=headers)
    assert r.status_code == 200


def test_fleet_summary(client):
    headers = _jwt_headers()
    r = client.get("/fleet/summary", headers=headers)
    assert r.status_code == 200
    assert isinstance(r.json(), list)
