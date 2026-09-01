"""
SIH26145 ML Predictor — Inference-time threat classification.

Uses the trained Random Forest model to classify network flows.
Returns predicted class, probability, and inference latency.

This module does NOT replace the existing six baseline detectors.
It adds an ML-based classification layer that runs alongside them.
"""

from __future__ import annotations

import time
from dataclasses import dataclass
from typing import Optional

import numpy as np

from ..models.schemas import NetworkFlow, Severity, ThreatClass
from .features import FEATURE_NAMES, flow_to_feature_vector
from .model import (
    get_label_encoder,
    get_model,
    get_model_info,
    get_scaler,
    is_model_loaded,
)


@dataclass
class MLPrediction:
    """Result of an ML model prediction."""

    threat_class: ThreatClass
    confidence: float
    severity: Severity
    model_name: str
    model_version: str
    inference_latency_ms: int
    class_probabilities: dict[str, float]
    is_model_available: bool


# Severity mapping from predicted class
_SEVERITY_MAP: dict[ThreatClass, Severity] = {
    ThreatClass.DDoS: Severity.CRITICAL,
    ThreatClass.C2_Beaconing: Severity.HIGH,
    ThreatClass.DGA_DNS_Tunneling: Severity.MEDIUM,
    ThreatClass.Encrypted_Malware: Severity.HIGH,
    ThreatClass.Reconnaissance: Severity.MEDIUM,
    ThreatClass.Data_Exfiltration: Severity.HIGH,
    ThreatClass.Normal: Severity.INFO,
}


def predict_flow(flow: NetworkFlow) -> Optional[MLPrediction]:
    """
    Run ML inference on a single network flow.

    Args:
        flow: The network flow to classify.

    Returns:
        MLPrediction if model is loaded, None otherwise.
    """
    if not is_model_loaded():
        return None

    model = get_model()
    scaler = get_scaler()
    encoder = get_label_encoder()
    info = get_model_info()

    if model is None or scaler is None or encoder is None:
        return None

    start_time = time.time()

    # Extract features in the exact order used during training
    features = flow_to_feature_vector(flow)

    # Reshape for single-sample prediction and scale
    X = np.array([features], dtype=np.float64)
    X_scaled = scaler.transform(X)

    # Predict class and probabilities
    predicted_idx = int(model.predict(X_scaled)[0])
    probabilities = model.predict_proba(X_scaled)[0]

    # Map index to class name
    class_name = encoder.inverse_transform([predicted_idx])[0]
    confidence = float(probabilities[predicted_idx])

    # Build probability dict
    class_names = encoder.classes_
    class_probabilities = {
        name: round(float(prob), 4) for name, prob in zip(class_names, probabilities)
    }

    # Map class name to ThreatClass enum
    threat_class = _class_name_to_threat(class_name)
    severity = _SEVERITY_MAP.get(threat_class, Severity.MEDIUM)

    inference_latency_ms = int((time.time() - start_time) * 1000)

    return MLPrediction(
        threat_class=threat_class,
        confidence=round(confidence, 4),
        severity=severity,
        model_name=info.get("model_name", "RandomForest"),
        model_version=info.get("model_version", "1.0"),
        inference_latency_ms=inference_latency_ms,
        class_probabilities=class_probabilities,
        is_model_available=True,
    )


def _class_name_to_threat(class_name: str) -> ThreatClass:
    """Map a string class name to a ThreatClass enum value."""
    mapping = {
        "Normal": ThreatClass.Normal,
        "DDoS": ThreatClass.DDoS,
        "C2_Beaconing": ThreatClass.C2_Beaconing,
        "DGA_DNS_Tunneling": ThreatClass.DGA_DNS_Tunneling,
        "Encrypted_Malware": ThreatClass.Encrypted_Malware,
        "Reconnaissance": ThreatClass.Reconnaissance,
        "Data_Exfiltration": ThreatClass.Data_Exfiltration,
    }
    return mapping.get(class_name, ThreatClass.Normal)
