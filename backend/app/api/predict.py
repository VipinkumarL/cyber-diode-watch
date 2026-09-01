"""Prediction API endpoint."""

import time

from fastapi import APIRouter

from ..detection.pipeline import pipeline
from ..features.common import extract_features
from ..models.schemas import (
    PredictRequest,
    PredictResponse,
    Severity,
    ThreatClass,
)
from ..services import store

router = APIRouter()


@router.post("/api/predict", response_model=PredictResponse)
async def predict(request: PredictRequest) -> PredictResponse:
    """
    Accept a network flow, run ALL detectors, and return the best result.

    Pipeline:
      1. Record start time
      2. Extract features
      3. Run all 6 detectors via the detection pipeline
      4. Select the highest-confidence alert (if any)
      5. Calculate actual detection latency
      6. Update flow classification if threat detected
      7. Store the flow
      8. Store all alerts
      9. Return PredictResponse with best alert
    """
    flow = request.flow
    start_time = time.time()

    # Feature extraction (for logging / future use)
    _features = extract_features(flow)

    # Run the full detection pipeline
    alerts = pipeline.analyze(flow, _start_time=start_time)

    # Calculate actual detection latency
    detection_time_ms = int((time.time() - start_time) * 1000)

    # Select the best alert (highest confidence)
    best_alert = pipeline.get_best_alert(alerts)

    # Update the flow if any threat was detected
    if best_alert:
        flow.classification = best_alert.threatClass
        flow.confidence = best_alert.confidence
        flow.severity = best_alert.severity
        flow.isSuspicious = True

    # Store the flow
    store.insert_flow(flow)

    # Store ALL alerts (not just the best one)
    for alert in alerts:
        alert.detectionLatencyMs = detection_time_ms
        store.insert_alert(alert)

    return PredictResponse(
        alert=best_alert,
        updatedFlow=flow,
        detectionTimeMs=detection_time_ms,
    )
