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


def test_websocket_connect(client):
    with client.websocket_connect("/ws/events") as ws:
        ws.send_text("ping")


def test_websocket_receives_broadcast(client):
    from app.api.routes.ws import manager

    with client.websocket_connect("/ws/events"):
        manager.enqueue("test_alert", {"host_id": "TEST", "score": 0.5})

        import time
        time.sleep(0.5)
