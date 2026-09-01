"""Replay control endpoints."""

from fastapi import APIRouter

from ..models.schemas import ReplayStartRequest, ReplayStatusResponse
from ..replay.engine import reset_flow_counter
from ..services import store

router = APIRouter()

# Replay session state
_replay_state: dict = {
    "status": "idle",
    "scenario": "normal",
    "speed": 100,
    "dataset": "synthetic",
}


@router.post("/api/replay/start", response_model=ReplayStatusResponse)
async def start_replay(request: ReplayStartRequest) -> ReplayStatusResponse:
    """Start replaying synthetic flow data."""
    _replay_state.update({
        "status": "running",
        "scenario": request.scenario,
        "speed": request.speed,
        "dataset": request.dataset,
    })
    reset_flow_counter()
    return ReplayStatusResponse(status="running")


@router.post("/api/replay/pause", response_model=ReplayStatusResponse)
async def pause_replay() -> ReplayStatusResponse:
    """Pause the current replay."""
    _replay_state["status"] = "paused"
    return ReplayStatusResponse(status="paused")


@router.post("/api/replay/stop", response_model=ReplayStatusResponse)
async def stop_replay() -> ReplayStatusResponse:
    """Stop the current replay."""
    _replay_state["status"] = "stopped"
    return ReplayStatusResponse(status="stopped")


@router.post("/api/replay/reset", response_model=ReplayStatusResponse)
async def reset_replay() -> ReplayStatusResponse:
    """Reset replay and clear all stored data."""
    _replay_state.update({
        "status": "idle",
        "scenario": "normal",
        "speed": 100,
        "dataset": "synthetic",
    })
    store.clear_all()
    store.reset_counters()
    reset_flow_counter()
    return ReplayStatusResponse(status="idle")
