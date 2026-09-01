"""
SIH26145 Detection Pipeline — Central Detector Registry and Runner.

Runs all registered detectors against each flow and returns alerts.
Also runs the ML model when available, providing both ML and
rule-based detections in a single pass.

Architecture:
  NetworkFlow
    ├── ML Model (Random Forest) → MLPrediction
    └── [Detector₁, ..., Detector₆] → list[Alert]

The ML prediction is included in the response alongside detector alerts.
"""

from __future__ import annotations

import time
from typing import Optional

from ..models.schemas import (
    Alert,
    DetectorInfo,
    DetectorStatus,
    NetworkFlow,
    Severity,
    ThreatClass,
)
from ..ml.model import is_model_loaded
from ..ml.predictor import MLPrediction, predict_flow
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
    Also runs the ML model when available.
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

    def predict_ml(
        self, flow: NetworkFlow
    ) -> Optional[MLPrediction]:
        """
        Run ML inference on a flow. Returns None if model not loaded.
        """
        return predict_flow(flow)

    def ml_to_alert(
        self, prediction: MLPrediction, flow: NetworkFlow
    ) -> Alert:
        """Convert an ML prediction to an Alert for storage/display."""
        return Alert(
            alertId=f"ML-{flow.timestamp}-{flow.flowId[-7:]}",
            timestamp=flow.timestamp,
            flowId=flow.flowId,
            threatClass=prediction.threat_class,
            confidence=prediction.confidence,
            severity=prediction.severity,
            sourceIp=flow.sourceIp,
            destinationIp=flow.destinationIp,
            protocol=flow.protocol,
            destinationPort=flow.destinationPort,
            detector=f"ML {prediction.model_name} v{prediction.model_version}",
            detectionLatencyMs=prediction.inference_latency_ms,
            supportingEvidence={
                "model": prediction.model_name,
                "version": prediction.model_version,
                "class_probabilities": prediction.class_probabilities,
                "inference_latency_ms": prediction.inference_latency_ms,
                "method": "Random Forest Classifier (trained on synthetic CICIDS2017-like data)",
            },
            description=(
                f"ML classification: {prediction.threat_class.value} "
                f"(confidence {prediction.confidence:.1%}) "
                f"by {prediction.model_name} v{prediction.model_version}"
            ),
            status="new",
            scenario=flow.scenario,
        )

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
          1. ML prediction (highest priority when available)
          2. Scenario tag matching detector's threat class
          3. Highest confidence
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

        # Prefer ML alerts (they have the highest predictive power)
        ml_alerts = [a for a in alerts if a.detector.startswith("ML ")]
        if ml_alerts:
            return max(
                ml_alerts,
                key=lambda a: (-a.confidence, severity_order.get(a.severity, 5)),
            )

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
        """Return info for all registered detectors (including ML status)."""
        infos = [d.get_info() for d in self._detectors]

        # Add ML detector info
        ml_status = DetectorStatus.ACTIVE if is_model_loaded() else DetectorStatus.NOT_TRAINED
        ml_info = DetectorInfo(
            name="ML Random Forest Classifier",
            threatClass=ThreatClass.Normal,  # Multi-class, not specific
            status=ml_status,
            method="Random Forest (trained on synthetic CICIDS2017-like data)",
            description=(
                "Multi-class Random Forest classifier trained on synthetic "
                "network flow data mimicking CICIDS2017 patterns. Classifies "
                "flows into 7 categories: Normal, DDoS, C2_Beaconing, "
                "DGA_DNS_Tunneling, Encrypted_Malware, Reconnaissance, "
                "Data_Exfiltration. Uses 11 flow-level features with "
                "StandardScaler normalization."
            ),
        )
        infos.append(ml_info)
        return infos

    @property
    def detector_count(self) -> int:
        return len(self._detectors) + (1 if is_model_loaded() else 0)


# Module-level singleton
pipeline = DetectionPipeline()
