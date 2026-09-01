"""Flow ingestion and retrieval endpoints."""

from fastapi import APIRouter, Query

from ..detection.pipeline import pipeline
from ..features.common import extract_features
from ..models.schemas import (
    FlowsResponse,
    NetworkFlow,
)
from ..services import store

router = APIRouter()


@router.post("/api/flows", response_model=NetworkFlow)
async def ingest_flow(flow: NetworkFlow) -> NetworkFlow:
    """
    Ingest a single network flow record and run the full detection pipeline.

    All 6 detectors are evaluated against the incoming flow.
    If any detector triggers, the flow is classified and alerts are stored.

    This endpoint runs the same pipeline as POST /api/predict.
    The caller should use one or the other, not both, for the same flow.
    """
    # Run the full detection pipeline
    alerts = pipeline.analyze(flow)

    # Update flow classification if any threat detected
    if alerts:
        # Use the highest-confidence alert for classification
        best = pipeline.get_best_alert(alerts)
        if best:
            flow.classification = best.threatClass
            flow.confidence = best.confidence
            flow.severity = best.severity
            flow.isSuspicious = True

        # Store all alerts
        for alert in alerts:
            store.insert_alert(alert)

    # Store the flow (after classification update)
    store.insert_flow(flow)

    return flow


@router.get("/api/flows", response_model=FlowsResponse)
async def list_flows(limit: int = Query(default=200, ge=1, le=5000)) -> FlowsResponse:
    """Return recent flows and aggregate statistics."""
    flows = store.get_flows(limit)
    stats = store.get_flow_stats()
    return FlowsResponse(flows=flows, stats=stats)
