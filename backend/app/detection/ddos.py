"""
SIH26145 DDoS Detector — PLACEHOLDER.

This module provides the interface for a DDoS detector.
The actual ML model (Random Forest / XGBoost trained on CICIDS2017)
will be implemented in a later phase.

Status: NOT_IMPLEMENTED — interface only, no real detection.
"""

from __future__ import annotations

from typing import Optional

from ..models.schemas import (
    Alert,
    DetectorInfo,
    DetectorStatus,
    NetworkFlow,
    Severity,
    ThreatClass,
)
from ..services import store


class DDoSDetector:
    """
    DDoS detection using flow-level features.

    PLACEHOLDER: This detector does not perform real ML inference.
    When a model is trained and loaded, replace the body of analyze()
    with actual feature extraction + model.predict().
    """

    def analyze(self, flow: NetworkFlow) -> Optional[Alert]:
        """
        Analyze a flow for DDoS indicators.

        Current implementation: always returns None (no detection).
        Replace with ML model inference when ready.
        """
        # TODO: Implement when ML model is trained
        # 1. Extract features from flow
        # 2. Run model.predict(features)
        # 3. If prediction == DDoS, create and return Alert
        return None

    def get_info(self) -> DetectorInfo:
        return DetectorInfo(
            name="DDoS Detector",
            threatClass=ThreatClass.DDoS,
            status=DetectorStatus.NOT_IMPLEMENTED,
            method="Random Forest Classifier (not yet loaded)",
            description=(
                "Detects volumetric and protocol DDoS attacks using "
                "flow-level features. Requires CICIDS2017 model training."
            ),
        )
