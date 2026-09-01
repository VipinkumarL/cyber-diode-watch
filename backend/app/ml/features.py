"""
SIH26145 ML Feature Extraction.

Extracts and orders features for the ML model. The feature order
must be IDENTICAL during training and inference.

Feature set maps NetworkFlow fields to a fixed-size numeric vector
compatible with scikit-learn's Random Forest classifier.

FEATURE ORDER (must match training):
  0: flowDuration
  1: totalPackets
  2: packetsPerSecond
  3: bytesPerSecond
  4: totalBytes
  5: sourcePort
  6: destinationPort
  7: sourceEntropy
  8: destinationConcentration
  9: packetLengthMean
  10: packetLengthStd
"""

from __future__ import annotations

from ..models.schemas import NetworkFlow

# Canonical feature names in exact order used by the model.
# This list MUST stay in sync with training/data generation.
FEATURE_NAMES: list[str] = [
    "flowDuration",
    "totalPackets",
    "packetsPerSecond",
    "bytesPerSecond",
    "totalBytes",
    "sourcePort",
    "destinationPort",
    "sourceEntropy",
    "destinationConcentration",
    "packetLengthMean",
    "packetLengthStd",
]

NUM_FEATURES = len(FEATURE_NAMES)


def flow_to_feature_vector(flow: NetworkFlow) -> list[float]:
    """
    Convert a NetworkFlow to a fixed-order numeric feature vector.

    The output list length and order must match FEATURE_NAMES exactly.
    This function is the single source of truth for inference-time
    feature extraction.
    """
    return [
        float(flow.flowDuration),
        float(flow.totalPackets),
        float(flow.packetsPerSecond),
        float(flow.bytesPerSecond),
        float(flow.totalBytes),
        float(flow.sourcePort),
        float(flow.destinationPort),
        flow.sourceEntropy if flow.sourceEntropy is not None else 0.0,
        flow.destinationConcentration if flow.destinationConcentration is not None else 0.0,
        flow.packetLengthMean if flow.packetLengthMean is not None else 0.0,
        flow.packetLengthStd if flow.packetLengthStd is not None else 0.0,
    ]
