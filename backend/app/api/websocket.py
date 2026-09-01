"""
WebSocket endpoint for live detection events.

Clients connect to /ws/traffic and receive JSON messages matching
the WebSocketMessage type union from the frontend:
  - { type: "flow", data: NetworkFlow }
  - { type: "alert", data: Alert }
  - { type: "incident", data: Incident }
  - { type: "metrics", data: SystemMetrics }
  - { type: "replay_status", data: { status: string } }
"""

from __future__ import annotations

import asyncio
import json
import logging
from typing import Any

from fastapi import APIRouter, WebSocket, WebSocketDisconnect

logger = logging.getLogger(__name__)

router = APIRouter()

# Active WebSocket connections
_connections: list[WebSocket] = []


async def broadcast(message: dict[str, Any]) -> None:
    """Send a JSON message to all connected WebSocket clients."""
    dead: list[WebSocket] = []
    payload = json.dumps(message)
    for ws in _connections:
        try:
            await ws.send_text(payload)
        except Exception:
            dead.append(ws)
    for ws in dead:
        if ws in _connections:
            _connections.remove(ws)


@router.websocket("/ws/traffic")
async def traffic_websocket(websocket: WebSocket) -> None:
    """
    WebSocket endpoint for live flow/alert/metrics streaming.

    Clients connect here to receive real-time updates.
    The server can push messages at any time via the broadcast() function.
    """
    await websocket.accept()
    _connections.append(websocket)
    logger.info("WebSocket client connected (%d total)", len(_connections))

    try:
        # Keep connection alive and listen for client messages
        while True:
            # We don't expect client messages, but reading prevents
            # the connection from appearing idle and being closed.
            data = await websocket.receive_text()
            # Client messages are currently ignored
            logger.debug("WS received: %s", data)
    except WebSocketDisconnect:
        logger.info("WebSocket client disconnected")
    except Exception as exc:
        logger.error("WebSocket error: %s", exc)
    finally:
        if websocket in _connections:
            _connections.remove(websocket)
