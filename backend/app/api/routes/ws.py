"""WebSocket endpoint for real-time alert and incident streaming."""

import asyncio
import json
import logging
from typing import Any

from fastapi import APIRouter, Query, WebSocket, WebSocketDisconnect
from jose import JWTError, jwt

from app.config import JWT_ALGORITHM, JWT_SECRET

logger = logging.getLogger(__name__)

router = APIRouter()


class ConnectionManager:
    """Manages active WebSocket connections and broadcasts events."""

    def __init__(self):
        self._connections: list[WebSocket] = []
        self._queue: asyncio.Queue = asyncio.Queue()

    async def connect(self, websocket: WebSocket):
        await websocket.accept()
        self._connections.append(websocket)
        logger.info("WebSocket client connected (%d total)", len(self._connections))

    def disconnect(self, websocket: WebSocket):
        if websocket in self._connections:
            self._connections.remove(websocket)
        logger.info("WebSocket client disconnected (%d remaining)", len(self._connections))

    def enqueue(self, event_type: str, payload: dict[str, Any]):
        """Thread-safe enqueue called from the orchestrator thread."""
        message = json.dumps({"type": event_type, "data": payload})
        try:
            self._queue.put_nowait(message)
        except asyncio.QueueFull:
            logger.warning("WebSocket broadcast queue full, dropping message")

    async def _drain_and_broadcast(self):
        while True:
            message = await self._queue.get()
            stale: list[WebSocket] = []
            for ws in self._connections:
                try:
                    await ws.send_text(message)
                except Exception:
                    stale.append(ws)
            for ws in stale:
                self.disconnect(ws)

    async def start_broadcaster(self):
        asyncio.create_task(self._drain_and_broadcast())


manager = ConnectionManager()


def _validate_ws_token(token: str | None) -> bool:
    """Validate JWT token for WebSocket connections."""
    if not token:
        return False
    try:
        jwt.decode(token, JWT_SECRET, algorithms=[JWT_ALGORITHM])
        return True
    except JWTError:
        return False


@router.websocket("/ws/events")
async def websocket_events(websocket: WebSocket, token: str | None = Query(default=None)):
    if not _validate_ws_token(token):
        await websocket.accept()
        await websocket.close(code=4001, reason="Authentication required")
        return

    await manager.connect(websocket)
    try:
        while True:
            await websocket.receive_text()
    except WebSocketDisconnect:
        manager.disconnect(websocket)
