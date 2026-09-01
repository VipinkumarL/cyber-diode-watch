"""
SIH26145 ML Predictor — Inference-time threat classification.

Uses the trained Random Forest model to classify network flows.
Returns predicted class, probability, and inference latency.

This module does NOT replace the existing six baseline detectors.
It adds an ML-based classification layer that runs alongside them.

Supports two model types:
  1. CICIDS2017 binary (BENIGN/ATTACK) — real data
  2. Synthetic multi-class (7 classes) — legacy fallback

For binary models, ATTACK prediction triggers an alert.
For multi-class models, each predicted class maps to a ThreatClass.
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
    get_model_source,
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
    model_source: str  # "CICIDS2017" or "synthetic"


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

# For binary CICIDS2017: ATTACK maps to HIGH severity
_BINARY_ATTACK_SEVERITY = Severity.HIGH
_BINARY_BENIGN_SEVERITY = Severity.INFO


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
    model_source = get_model_source()

    if model is None or scaler is None or encoder is None:
        return None

    start_time = time.time()

    # Extract features in the order used during training
    # The model stores its own feature_names in model_info
    model_feature_names = info.get("feature_names", FEATURE_NAMES)

    # Map NetworkFlow to features compatible with the model's training features
    features = _extract_model_features(flow, model_feature_names)

    # Reshape for single-sample prediction and scale
    X = np.array([features], dtype=np.float64)

    # Handle NaN/inf
    X = np.nan_to_num(X, nan=0.0, posinf=0.0, neginf=0.0)

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
    threat_class = _class_name_to_threat(class_name, model_source)

    # Severity based on model source
    if model_source == "CICIDS2017":
        severity = _BINARY_ATTACK_SEVERITY if class_name == "ATTACK" else _BINARY_BENIGN_SEVERITY
        if class_name == "BENIGN":
            threat_class = ThreatClass.Normal
            severity = Severity.INFO
        else:
            severity = _BINARY_ATTACK_SEVERITY
    else:
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
        model_source=model_source,
    )


def _extract_model_features(
    flow: NetworkFlow, model_feature_names: list[str]
) -> list[float]:
    """
    Extract features from a NetworkFlow matching the model's feature order.

    Supports both:
      - Synthetic model features (camelCase): flowDuration, totalPackets, etc.
      - CICIDS2017 model features (snake_case): flow_duration, total_fwd_packets, etc.

    The model stores its feature_names in model_info. We map both naming
    conventions to the correct NetworkFlow fields.
    """
    # Unified lookup supporting both naming conventions
    # CICIDS2017 snake_case names AND synthetic camelCase names
    pml = flow.packetLengthMean if flow.packetLengthMean is not None else 0.0
    pstd = flow.packetLengthStd if flow.packetLengthStd is not None else 0.0
    se = flow.sourceEntropy if flow.sourceEntropy is not None else 0.0
    dc = (
        flow.destinationConcentration
        if flow.destinationConcentration is not None
        else 0.0
    )

    feature_map = {
        # CamelCase (synthetic model)
        "flowDuration": float(flow.flowDuration),
        "totalPackets": float(flow.totalPackets),
        "totalFwdPackets": float(flow.totalPackets),
        "totalBwdPackets": 0.0,
        "packetsPerSecond": float(flow.packetsPerSecond),
        "bytesPerSecond": float(flow.bytesPerSecond),
        "totalBytes": float(flow.totalBytes),
        "sourcePort": float(flow.sourcePort),
        "destinationPort": float(flow.destinationPort),
        "sourceEntropy": se,
        "destinationConcentration": dc,
        "packetLengthMean": pml,
        "packetLengthStd": pstd,
        "fwdPacketLengthMean": pml,
        "bwdPacketLengthMean": 0.0,
        # Snake_case (CICIDS2017 model)
        "flow_duration": float(flow.flowDuration),
        "total_fwd_packets": float(flow.totalPackets),
        "total_backward_packets": 0.0,
        "total_bytes": float(flow.totalBytes),
        "flow_bytes_s": float(flow.bytesPerSecond),
        "flow_packets_s": float(flow.packetsPerSecond),
        "destination_port": float(flow.destinationPort),
        "source_port": float(flow.sourcePort),
        "packet_length_mean": pml,
        "packet_length_std": pstd,
        "fwd_packet_length_mean": pml,
        "bwd_packet_length_mean": 0.0,
    }

    features = []
    for name in model_feature_names:
        features.append(feature_map.get(name, 0.0))

    return features


def _class_name_to_threat(class_name: str, model_source: str) -> ThreatClass:
    """
    Map a string class name to a ThreatClass enum value.

    For CICIDS2017 binary: "BENIGN" → Normal, "ATTACK" → DDoS (generic attack).
    For synthetic multi-class: maps each class directly.
    """
    if model_source == "CICIDS2017":
        # Binary classification
        mapping = {
            "BENIGN": ThreatClass.Normal,
            "ATTACK": ThreatClass.DDoS,  # Generic attack placeholder
        }
        return mapping.get(class_name, ThreatClass.Normal)
    else:
        # Multi-class synthetic model
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
