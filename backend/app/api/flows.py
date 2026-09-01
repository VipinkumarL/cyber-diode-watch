"""Flow ingestion and retrieval endpoints."""

from fastapi import APIRouter, Query

from ..detection.pipeline import pipeline
from ..features.common import extract_features
from ..models.schemas import (
    FlowsResponse,
    NetworkFlow,
    ThreatClass,
)
from ..services import store

router = APIRouter()


@router.post("/api/flows", response_model=NetworkFlow)
async def ingest_flow(flow: NetworkFlow) -> NetworkFlow:
    """
    Ingest a single network flow record and run the full detection pipeline.

    Runs ML model (if loaded) + all 6 baseline detectors.
    If any detector or ML model triggers, the flow is classified and alerts stored.
    """
    # Run ML prediction
    ml_prediction = pipeline.predict_ml(flow)

    # Run the full baseline detection pipeline
    alerts = pipeline.analyze(flow)

    # If ML model is loaded, add its prediction as an alert
    if ml_prediction is not None:
        ml_alert = pipeline.ml_to_alert(ml_prediction, flow)
        alerts.append(ml_alert)

    # Update flow classification if any threat detected
    if alerts:
        best = pipeline.get_best_alert(alerts)
        if best:
            flow.classification = best.threatClass
            flow.confidence = best.confidence
            flow.severity = best.severity
            flow.isSuspicious = best.threatClass != ThreatClass.Normal

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
