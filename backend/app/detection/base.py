"""
SIH26145 Detector Base Interface.

All detectors implement this protocol. Each detector receives a flow
and returns either an Alert (if a threat is detected) or None.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from typing import Optional

from ..models.schemas import Alert, DetectorInfo, NetworkFlow


class BaseDetector(ABC):
    """Abstract base class for all SIH26145 threat detectors."""

    @abstractmethod
    def analyze(self, flow: NetworkFlow) -> Optional[Alert]:
        """
        Analyze a network flow and return an Alert if a threat is detected.
        Returns None if the flow is benign.
        """
        ...

    @abstractmethod
    def get_info(self) -> DetectorInfo:
        """Return metadata about this detector."""
        ...
