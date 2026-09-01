"""Prediction API endpoint."""

from fastapi import APIRouter

from ..detection.ddos import DDoSDetector
from ..features.common import extract_features
from ..models.schemas import PredictRequest, PredictResponse
from ..services import store

router = APIRouter()

_ddos = DDoSDetector()


@router.post("/api/predict", response_model=PredictResponse)
async def predict(request: PredictRequest) -> PredictResponse:
    """
    Accept a network flow and return a prediction.

    Currently returns the flow as-is (no ML model loaded).
    When the DDoS model is implemented, this endpoint will:
    1. Extract features
    2. Run the detector
    3. Return alert + classification if threat detected
    """
    flow = request.flow

    # Feature extraction (for logging / future use)
    _features = extract_features(flow)

    # Detection — placeholder returns None
    alert = _ddos.analyze(flow)

    # Store the flow
    store.insert_flow(flow)

    # If an alert was generated, store it
    if alert:
        store.insert_alert(alert)

    return PredictResponse(
        alert=alert,
        updatedFlow=flow,
        detectionTimeMs=0,  # No real detection latency yet
    )
