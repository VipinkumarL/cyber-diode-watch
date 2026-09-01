"""
SIH26145 C2 Beaconing Detector — Baseline Statistical/Rule-Based.

Detects command-and-control beaconing patterns using flow-level features.
C2 beacons are characterized by:
  - Periodic, regular connection intervals
  - Low-volume, short-duration flows
  - Repeated connections to the same destination
  - Suspicious destination ports (non-standard or known C2 ports)
  - Consistent packet sizes (heartbeats)

LIMITATION: Without access to multiple flows from the same source,
this detector uses per-flow heuristics. Multi-flow correlation
(e.g., inter-arrival time variance) would require a stateful
correlation engine — noted as a future enhancement.

Status: ACTIVE — working baseline detector.
"""

from __future__ import annotations

import math
import time
from typing import Optional

from ..features.common import extract_features
from ..models.schemas import (
    Alert,
    DetectorInfo,
    DetectorStatus,
    FeatureVector,
    NetworkFlow,
    Severity,
    ThreatClass,
)


# ═══════════════════════════════════════════════════════════════════
# CONFIGURATION
# ═══════════════════════════════════════════════════════════════════

# C2 beacons typically use low-volume, periodic communication
C2_MAX_PPS = 50.0            # Beacons are low packet rate
C2_MAX_BPS = 50000.0         # Beacons send small payloads
C2_MAX_BYTES = 5000          # Small heartbeat payloads
C2_MIN_DURATION = 0.05       # Non-instantaneous (real connection)
C2_MAX_DURATION = 5.0        # Short-lived connections
C2_MAX_PACKETS = 50          # Few packets per beacon

# Suspicious ports commonly used by C2 frameworks
# NOTE: Port 443 (HTTPS) is excluded — it is overwhelmingly legitimate.
C2_SUSPICIOUS_PORTS = {
    8443, 993, 995,        # TLS-wrapped C2 on non-standard ports
    8080, 8888, 4444,      # Common reverse shell / C2
    53,                    # DNS tunneling
    123,                   # NTP-based C2
    6667, 6697,            # IRC-based C2
    80,                    # HTTP C2 (only suspicious with other indicators)
}

# Scoring weights (total = 100)
C2_WEIGHT_LOW_VOLUME = 25
C2_WEIGHT_SHORT_FLOW = 20
C2_WEIGHT_SUSPICIOUS_PORT = 20
C2_WEIGHT_SMALL_PAYLOAD = 15
C2_WEIGHT_DEST_CONC = 10
C2_WEIGHT_ENTROPY_LOW = 10

C2_MIN_SCORE = 50

SEVERITY_CRITICAL_MIN = 75
SEVERITY_HIGH_MIN = 55
SEVERITY_MEDIUM_MIN = 40


# ═══════════════════════════════════════════════════════════════════
# DETECTOR
# ═══════════════════════════════════════════════════════════════════

class C2BeaconDetector:
    """
    Baseline C2 beaconing detector.

    Evaluates individual flows for characteristics consistent with
    command-and-control beaconing: low-volume, periodic, short-lived
    connections to potentially suspicious destinations.
    """

    def analyze(self, flow: NetworkFlow) -> Optional[Alert]:
        """Analyze a flow for C2 beaconing indicators."""
        start_time = time.time()
        features = extract_features(flow)
        score, indicators, evidence = self._score(features, flow)
        latency_ms = int((time.time() - start_time) * 1000)

        if score < C2_MIN_SCORE:
            return None

        severity = self._score_to_severity(score)
        confidence = self._score_to_confidence(score)

        return Alert(
            alertId=f"ALT-{flow.timestamp}-{flow.flowId[-7:]}",
            timestamp=flow.timestamp,
            flowId=flow.flowId,
            threatClass=ThreatClass.C2_Beaconing,
            confidence=confidence,
            severity=severity,
            sourceIp=flow.sourceIp,
            destinationIp=flow.destinationIp,
            protocol=flow.protocol,
            destinationPort=flow.destinationPort,
            detector="C2 Beaconing Baseline Detector",
            detectionLatencyMs=latency_ms,
            supportingEvidence=evidence,
            description=(
                f"C2 beacon baseline detector: score {score}/100, "
                f"confidence {confidence:.0%}. "
                f"Triggered: {', '.join(indicators)}."
            ),
            status="new",
            scenario=flow.scenario,
        )

    def _score(
        self, features: FeatureVector, flow: NetworkFlow
    ) -> tuple[int, list[str], dict[str, float | str]]:
        score = 0
        indicators: list[str] = []
        evidence: dict[str, float | str] = {}

        pps = features.packetsPerSecond
        bps = features.bytesPerSecond
        duration = features.flowDuration
        total_bytes = features.totalBytes
        total_pkts = features.totalPackets
        dest_port = features.destinationPort
        dest_conc = features.destinationConcentration
        src_entropy = features.sourceEntropy

        evidence["packets_per_second"] = round(pps, 1)
        evidence["bytes_per_second"] = round(bps, 1)
        evidence["flow_duration"] = round(duration, 3)
        evidence["total_bytes"] = total_bytes
        evidence["total_packets"] = total_pkts
        evidence["destination_port"] = dest_port
        evidence["destination_concentration"] = round(dest_conc, 3)
        evidence["source_entropy"] = round(src_entropy, 3)

        # Indicator 1: Low packet rate (beacons are quiet)
        if pps <= C2_MAX_PPS:
            score += C2_WEIGHT_LOW_VOLUME
            indicators.append("low_pps")
            evidence["pps_assessment"] = f"Low packet rate ({pps:.1f} <= {C2_MAX_PPS})"
        else:
            evidence["pps_assessment"] = f"High packet rate ({pps:.1f} > {C2_MAX_PPS})"

        # Indicator 2: Short flow duration (quick beacon exchange)
        if C2_MIN_DURATION <= duration <= C2_MAX_DURATION:
            score += C2_WEIGHT_SHORT_FLOW
            indicators.append("short_flow")
            evidence["duration_assessment"] = (
                f"Short connection ({duration:.3f}s in [{C2_MIN_DURATION}, {C2_MAX_DURATION}])"
            )
        else:
            evidence["duration_assessment"] = f"Duration outside beacon range ({duration:.3f}s)"

        # Indicator 3: Suspicious destination port
        if dest_port in C2_SUSPICIOUS_PORTS:
            score += C2_WEIGHT_SUSPICIOUS_PORT
            indicators.append("suspicious_port")
            evidence["port_assessment"] = (
                f"Suspicious port {dest_port} (known C2/encrypted port)"
            )
        else:
            evidence["port_assessment"] = f"Port {dest_port} not in known C2 list"

        # Indicator 4: Small payload size (heartbeat-like)
        if total_bytes <= C2_MAX_BYTES and total_pkts <= C2_MAX_PACKETS:
            score += C2_WEIGHT_SMALL_PAYLOAD
            indicators.append("small_payload")
            evidence["payload_assessment"] = (
                f"Small payload ({total_bytes} bytes, {total_pkts} pkts)"
            )
        else:
            evidence["payload_assessment"] = (
                f"Large payload ({total_bytes} bytes, {total_pkts} pkts)"
            )

        # Indicator 5: High destination concentration (repeated target)
        if dest_conc >= 0.7:
            score += C2_WEIGHT_DEST_CONC
            indicators.append("dest_concentrated")
            evidence["dest_assessment"] = (
                f"High destination concentration ({dest_conc:.3f} >= 0.7)"
            )
        else:
            evidence["dest_assessment"] = (
                f"Distributed destinations ({dest_conc:.3f} < 0.7)"
            )

        # Indicator 6: Low source entropy (single compromised host, not distributed)
        if src_entropy < 3.0:
            score += C2_WEIGHT_ENTROPY_LOW
            indicators.append("low_src_entropy")
            evidence["entropy_assessment"] = (
                f"Low source diversity ({src_entropy:.3f} < 3.0, single host pattern)"
            )
        else:
            evidence["entropy_assessment"] = (
                f"Moderate source diversity ({src_entropy:.3f} >= 3.0)"
            )

        evidence["detector"] = "C2 Beaconing Baseline Detector"
        evidence["method"] = "Statistical/Rule-Based Low-Volume Beacon Scoring"
        evidence["score"] = score
        evidence["max_possible_score"] = 100
        evidence["detection_threshold"] = C2_MIN_SCORE

        return score, indicators, evidence

    @staticmethod
    def _score_to_severity(score: int) -> Severity:
        if score >= SEVERITY_CRITICAL_MIN:
            return Severity.CRITICAL
        if score >= SEVERITY_HIGH_MIN:
            return Severity.HIGH
        if score >= SEVERITY_MEDIUM_MIN:
            return Severity.MEDIUM
        return Severity.LOW

    @staticmethod
    def _score_to_confidence(score: int) -> float:
        return round(min(0.99, score / 100.0), 4)

    def get_info(self) -> DetectorInfo:
        return DetectorInfo(
            name="C2 Beaconing Detector",
            threatClass=ThreatClass.C2_Beaconing,
            status=DetectorStatus.ACTIVE,
            method="Statistical Low-Volume Beacon Pattern Scoring",
            description=(
                "Baseline C2 beaconing detector using flow-level heuristics. "
                "Evaluates packet rate, flow duration, destination port, payload "
                "size, destination concentration, and source entropy. "
                "Not a trained ML model — future phase will add multi-flow "
                "correlation and periodicity analysis."
            ),
        )
