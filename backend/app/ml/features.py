"""
SIH26145 ML Feature Extraction.

Extracts and orders features for the ML model. The feature order
must be IDENTICAL during training and inference.

Feature set maps NetworkFlow fields to a fixed-size numeric vector
compatible with scikit-learn's Random Forest classifier.

FEATURE ORDER (must match CICIDS2017 training):
  0: flow_duration
  1: total_fwd_packets
  2: total_backward_packets
  3: total_bytes
  4: flow_bytes_s
  5: flow_packets_s
  6: destination_port
  7: source_port
  8: packet_length_mean
  9: packet_length_std
  10: fwd_packet_length_mean
  11: bwd_packet_length_mean
"""

from __future__ import annotations

from ..models.schemas import NetworkFlow

# Canonical feature names in exact order used by the model.
# This list MUST stay in sync with training/data generation.
FEATURE_NAMES: list[str] = [
    "flow_duration",
    "total_fwd_packets",
    "total_backward_packets",
    "total_bytes",
    "flow_bytes_s",
    "flow_packets_s",
    "destination_port",
    "source_port",
    "packet_length_mean",
    "packet_length_std",
    "fwd_packet_length_mean",
    "bwd_packet_length_mean",
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
        0.0,
        float(flow.totalBytes),
        float(flow.bytesPerSecond),
        float(flow.packetsPerSecond),
        float(flow.destinationPort),
        float(flow.sourcePort),
        flow.packetLengthMean if flow.packetLengthMean is not None else 0.0,
        flow.packetLengthStd if flow.packetLengthStd is not None else 0.0,
        flow.packetLengthMean if flow.packetLengthMean is not None else 0.0,
        0.0,
    ]
