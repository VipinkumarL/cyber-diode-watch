"""
SIH26145 Detection Pipeline — Central Detector Registry and Runner.

Runs all registered detectors against each flow and returns alerts.
Prevents duplicate alerts for the same detector/flow combination.

Architecture:
  NetworkFlow → [Detector₁, Detector₂, ..., Detector₆] → list[Alert]

Each detector returns an Alert or None. The pipeline collects all
non-None alerts and deduplicates by (detector, flowId).
"""

from __future__ import annotations

import time
from typing import Optional

from ..models.schemas import (
    Alert,
    DetectorInfo,
    NetworkFlow,
    Severity,
    ThreatClass,
)
# ThreatClass imported for type hints in _SCENARIO_PRIORITY
from .c2_beaconing import C2BeaconDetector
from .ddos import DDoSDetector
from .dga_dns import DGADnsDetector
from .encrypted_malware import EncryptedMalwareDetector
from .exfiltration import ExfiltrationDetector
from .reconnaissance import ReconDetector


class DetectionPipeline:
    """
    Central detection pipeline.

    Registers all detectors and runs them against incoming flows.
    Returns all triggered alerts without duplicate detector/flow pairs.
    """

    def __init__(self) -> None:
        self._detectors = [
            DDoSDetector(),
            C2BeaconDetector(),
            DGADnsDetector(),
            EncryptedMalwareDetector(),
            ReconDetector(),
            ExfiltrationDetector(),
        ]

    def analyze(
        self, flow: NetworkFlow, *, _start_time: Optional[float] = None
    ) -> list[Alert]:
        """
        Run all detectors against a single flow.

        Args:
            flow: The network flow to analyze.
            _start_time: Optional start time for latency measurement.

        Returns:
            List of alerts generated (may be empty).
        """
        start = _start_time or time.time()
        alerts: list[Alert] = []
        seen_detectors: set[str] = set()

        for detector in self._detectors:
            try:
                alert = detector.analyze(flow)
                if alert is not None:
                    # Deduplicate by detector name + flowId
                    key = f"{alert.detector}:{alert.flowId}"
                    if key not in seen_detectors:
                        seen_detectors.add(key)
                        # Override detection latency with pipeline latency
                        alert.detectionLatencyMs = int((time.time() - start) * 1000)
                        alerts.append(alert)
            except Exception:
                # Never let one detector crash the pipeline
                continue

        return alerts

    # Scenario → preferred ThreatClass mapping
    _SCENARIO_PRIORITY: dict[str, ThreatClass] = {
        "ddos": ThreatClass.DDoS,
        "c2": ThreatClass.C2_Beaconing,
        "dns": ThreatClass.DGA_DNS_Tunneling,
        "encrypted_malware": ThreatClass.Encrypted_Malware,
        "recon": ThreatClass.Reconnaissance,
        "reconnaissance": ThreatClass.Reconnaissance,
        "exfiltration": ThreatClass.Data_Exfiltration,
        "exfil": ThreatClass.Data_Exfiltration,
    }

    def get_best_alert(
        self, alerts: list[Alert]
    ) -> Optional[Alert]:
        """
        From a list of alerts, return the most relevant one.

        Priority:
          1. If a scenario tag matches a detector's threat class, prefer that.
          2. Otherwise, highest confidence wins (ties broken by severity).
        """
        if not alerts:
            return None

        severity_order = {
            Severity.CRITICAL: 0,
            Severity.HIGH: 1,
            Severity.MEDIUM: 2,
            Severity.LOW: 3,
            Severity.INFO: 4,
        }

        # Check if any alert's scenario matches its own threat class
        for alert in alerts:
            if alert.scenario and alert.scenario in self._SCENARIO_PRIORITY:
                preferred = self._SCENARIO_PRIORITY[alert.scenario]
                if alert.threatClass == preferred:
                    return alert

        # Fallback: highest confidence, then severity
        return max(
            alerts,
            key=lambda a: (-a.confidence, severity_order.get(a.severity, 5)),
        )

    def get_all_detectors(self) -> list[DetectorInfo]:
        """Return info for all registered detectors."""
        return [d.get_info() for d in self._detectors]

    @property
    def detector_count(self) -> int:
        return len(self._detectors)


# Module-level singleton
pipeline = DetectionPipeline()
