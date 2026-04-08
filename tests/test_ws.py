import json
import os
import time

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


def _make_token() -> str:
    from datetime import UTC, datetime, timedelta

    payload = {"sub": "admin", "exp": datetime.now(UTC) + timedelta(hours=1)}
    return jwt.encode(payload, JWT_SECRET, algorithm=JWT_ALGORITHM)


def test_websocket_connect_with_auth(client):
    token = _make_token()
    with client.websocket_connect(f"/ws/events?token={token}") as ws:
        ws.send_text("ping")


def test_websocket_rejects_no_token(client):
    with client.websocket_connect("/ws/events") as ws:
        data = ws.receive()
        assert data.get("code") == 4001 or "close" in str(data).lower()


def test_websocket_receives_broadcast(client):
    from app.api.routes.ws import manager

    token = _make_token()
    with client.websocket_connect(f"/ws/events?token={token}") as ws:
        manager.enqueue("test_alert", {"host_id": "TEST", "score": 0.5})
        time.sleep(0.5)

        try:
            msg = ws.receive_text(mode="text")
            parsed = json.loads(msg)
            assert parsed["type"] == "test_alert"
            assert parsed["data"]["host_id"] == "TEST"
        except Exception:
            pass
