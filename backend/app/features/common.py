"""
SIH26145 Feature Extraction.

Extracts security-relevant features from network flow records.
These features feed into the detection pipeline.
"""

from __future__ import annotations

import math
from collections import Counter

from ..models.schemas import FeatureVector, NetworkFlow


def extract_features(flow: NetworkFlow) -> FeatureVector:
    """
    Extract a feature vector from a network flow.

    This is the baseline feature set used by all detectors.
    Individual detectors may compute additional features.
    """
    return FeatureVector(
        flowDuration=flow.flowDuration,
        packetsPerSecond=flow.packetsPerSecond,
        bytesPerSecond=flow.bytesPerSecond,
        totalPackets=flow.totalPackets,
        totalBytes=flow.totalBytes,
        sourcePort=flow.sourcePort,
        destinationPort=flow.destinationPort,
        sourceEntropy=flow.sourceEntropy or 0.0,
        destinationConcentration=flow.destinationConcentration or 0.0,
        packetLengthMean=flow.packetLengthMean or 0.0,
        packetLengthStd=flow.packetLengthStd or 0.0,
    )


def shannon_entropy(values: list[int]) -> float:
    """Compute Shannon entropy over a list of integer values."""
    if not values:
        return 0.0
    counts = Counter(values)
    length = len(values)
    entropy = 0.0
    for count in counts.values():
        p = count / length
        entropy -= p * math.log2(p)
    return entropy
