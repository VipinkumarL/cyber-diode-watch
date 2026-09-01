"""Prediction API endpoint."""

import time

from fastapi import APIRouter

from ..detection.ddos import DDoSDetector
from ..features.common import extract_features
from ..models.schemas import (
    NetworkFlow,
    PredictRequest,
    PredictResponse,
    Severity,
    ThreatClass,
)
from ..services import store

router = APIRouter()

_ddos = DDoSDetector()


@router.post("/api/predict", response_model=PredictResponse)
async def predict(request: PredictRequest) -> PredictResponse:
    """
    Accept a network flow, run DDoS detection, and return the result.

    Pipeline:
      1. Record start time
      2. Extract features
      3. Run DDoS baseline detector
      4. Calculate actual detection latency
      5. Update flow classification if threat detected
      6. Store the flow
      7. Store the alert if generated
      8. Return PredictResponse
    """
    flow = request.flow
    start_time = time.time()

    # Feature extraction
    _features = extract_features(flow)

    # DDoS detection
    alert = _ddos.analyze(flow)

    # Calculate actual detection latency
    detection_time_ms = int((time.time() - start_time) * 1000)

    # Update the flow if a threat was detected
    if alert:
        flow.classification = ThreatClass.DDoS
        flow.confidence = alert.confidence
        flow.severity = alert.severity
        flow.isSuspicious = True
    # Otherwise, flow keeps its original (Normal) classification

    # Store the flow
    store.insert_flow(flow)

    # If an alert was generated, store it
    if alert:
        # Use the actual detection time, not the detector's internal time
        alert.detectionLatencyMs = detection_time_ms
        store.insert_alert(alert)

    return PredictResponse(
        alert=alert,
        updatedFlow=flow,
        detectionTimeMs=detection_time_ms,
    )
