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
    Accept a network flow, run ML model + all detectors, return best result.

    Pipeline:
      1. Record start time
      2. Extract features
      3. Run ML Random Forest classifier (if model loaded)
      4. Run all 6 baseline detectors via the detection pipeline
      5. Combine ML prediction + detector alerts
      6. Select the best result (ML preferred when available)
      7. Calculate actual detection latency
      8. Update flow classification
      9. Store the flow and all alerts
      10. Return PredictResponse
    """
    flow = request.flow
    start_time = time.time()

    # Feature extraction
    _features = extract_features(flow)

    # Run ML prediction
    ml_prediction = pipeline.predict_ml(flow)

    # Run the full baseline detection pipeline
    alerts = pipeline.analyze(flow, _start_time=start_time)

    # If ML model is loaded, add its prediction as an alert
    if ml_prediction is not None:
        ml_alert = pipeline.ml_to_alert(ml_prediction, flow)
        alerts.append(ml_alert)

    # Calculate actual detection latency
    detection_time_ms = int((time.time() - start_time) * 1000)

    # Select the best alert (ML preferred, then scenario, then confidence)
    best_alert = pipeline.get_best_alert(alerts)

    # Update the flow if any threat was detected
    if best_alert:
        flow.classification = best_alert.threatClass
        flow.confidence = best_alert.confidence
        flow.severity = best_alert.severity
        flow.isSuspicious = best_alert.threatClass != ThreatClass.Normal

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
