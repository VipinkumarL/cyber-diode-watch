"""Flow ingestion and retrieval endpoints."""

import time

from fastapi import APIRouter, Query

from ..detection.ddos import DDoSDetector
from ..features.common import extract_features
from ..models.schemas import (
    FlowsResponse,
    NetworkFlow,
    Severity,
    ThreatClass,
)
from ..services import store

router = APIRouter()

_ddos = DDoSDetector()


@router.post("/api/flows", response_model=NetworkFlow)
async def ingest_flow(flow: NetworkFlow) -> NetworkFlow:
    """
    Ingest a single network flow record and run DDoS detection.

    This endpoint automatically analyzes each incoming flow using
    the DDoS baseline detector. If DDoS behavior is detected, the
    flow is classified accordingly and an alert is stored.

    This ensures flows submitted via POST /api/flows receive the
    same analysis as flows submitted via POST /api/predict.
    The detector runs once per flow — no duplicate analysis occurs
    when /api/predict is used for the same flow (the caller chooses
    one endpoint or the other).
    """
    # Run DDoS detection
    alert = _ddos.analyze(flow)

    # Update flow classification if threat detected
    if alert:
        flow.classification = ThreatClass.DDoS
        flow.confidence = alert.confidence
        flow.severity = alert.severity
        flow.isSuspicious = True

        # Store the alert
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
