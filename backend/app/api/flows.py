"""Flow ingestion and retrieval endpoints."""

from fastapi import APIRouter, Query

from ..models.schemas import FlowsResponse, NetworkFlow
from ..services import store

router = APIRouter()


@router.post("/api/flows", response_model=NetworkFlow)
async def ingest_flow(flow: NetworkFlow) -> NetworkFlow:
    """Ingest a single network flow record."""
    return store.insert_flow(flow)


@router.get("/api/flows", response_model=FlowsResponse)
async def list_flows(limit: int = Query(default=200, ge=1, le=5000)) -> FlowsResponse:
    """Return recent flows and aggregate statistics."""
    flows = store.get_flows(limit)
    stats = store.get_flow_stats()
    return FlowsResponse(flows=flows, stats=stats)
