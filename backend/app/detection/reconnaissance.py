"""
SIH26145 Reconnaissance Detector — Baseline Statistical/Rule-Based.

Detects network reconnaissance and scanning activity using
flow-level features.

Key indicators:
  - High destination-port fan-out (port scanning)
  - High destination-IP fan-out (network scanning)
  - Many short-duration flows (connection attempts)
  - Low packet count per flow (SYN scans, half-open)
  - High packet rate with low byte count (scan probes)
  - Elevated source entropy (simultaneous scanning)

Status: ACTIVE — working baseline detector.
"""

from __future__ import annotations

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

# Reconnaissance indicators
RECON_SHORT_DURATION = 0.5        # Scan probes are very short
RECON_VERY_SHORT_DURATION = 0.05  # SYN scan / connect scan
RECON_MIN_PORT_FANOUT = 5         # Multiple ports probed
RECON_HIGH_PORT_FANOUT = 20       # Aggressive scan
RECON_MIN_IP_FANOUT = 5           # Multiple hosts targeted
RECON_HIGH_IP_FANOUT = 20         # Network-wide scan
RECON_LOW_PKTS = 5                # Few packets per probe
RECON_MIN_PPS = 50.0              # Rapid probing rate
RECON_HIGH_PPS = 500.0            # Aggressive scan rate
RECON_LOW_BYTES = 1000            # Small probe packets
RECON_HIGH_ENTROPY = 5.0          # Diverse scanning sources
RECON_DEST_CONC_LOW = 0.15        # Low concentration = distributed scan

# Scoring weights (total = 100)
RECON_WEIGHT_PORT_FANOUT = 25
RECON_WEIGHT_IP_FANOUT = 25
RECON_WEIGHT_SHORT_FLOW = 15
RECON_WEIGHT_LOW_PKTS = 15
RECON_WEIGHT_PPS = 10
RECON_WEIGHT_ENTROPY = 10

RECON_MIN_SCORE = 40

SEVERITY_CRITICAL_MIN = 75
SEVERITY_HIGH_MIN = 55
SEVERITY_MEDIUM_MIN = 40


# ═══════════════════════════════════════════════════════════════════
# DETECTOR
# ═══════════════════════════════════════════════════════════════════

class ReconDetector:
    """
    Baseline reconnaissance detector.

    Identifies scanning and probing activity from flow-level features.
    Detects port scanning, network scanning, and service enumeration
    patterns.
    """

    def analyze(self, flow: NetworkFlow) -> Optional[Alert]:
        """Analyze a flow for reconnaissance indicators."""
        start_time = time.time()
        features = extract_features(flow)
        score, indicators, evidence = self._score(features, flow)
        latency_ms = int((time.time() - start_time) * 1000)

        if score < RECON_MIN_SCORE:
            return None

        severity = self._score_to_severity(score)
        confidence = self._score_to_confidence(score)

        return Alert(
            alertId=f"ALT-{flow.timestamp}-{flow.flowId[-7:]}",
            timestamp=flow.timestamp,
            flowId=flow.flowId,
            threatClass=ThreatClass.Reconnaissance,
            confidence=confidence,
            severity=severity,
            sourceIp=flow.sourceIp,
            destinationIp=flow.destinationIp,
            protocol=flow.protocol,
            destinationPort=flow.destinationPort,
            detector="Reconnaissance Baseline Detector",
            detectionLatencyMs=latency_ms,
            supportingEvidence=evidence,
            description=(
                f"Reconnaissance baseline detector: score {score}/100, "
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

        duration = features.flowDuration
        total_pkts = features.totalPackets
        pps = features.packetsPerSecond
        total_bytes = features.totalBytes
        dest_conc = features.destinationConcentration
        entropy = features.sourceEntropy
        dest_port = features.destinationPort
        bps = features.bytesPerSecond

        evidence["flow_duration"] = round(duration, 3)
        evidence["total_packets"] = total_pkts
        evidence["packets_per_second"] = round(pps, 1)
        evidence["total_bytes"] = total_bytes
        evidence["destination_concentration"] = round(dest_conc, 3)
        evidence["source_entropy"] = round(entropy, 3)
        evidence["destination_port"] = dest_port
        evidence["bytes_per_second"] = round(bps, 1)

        # Indicator 1: Port fan-out — inferred from low destination concentration
        # Low concentration = many different destinations or ports
        # We use the existing destinationConcentration as a proxy
        if dest_conc <= RECON_DEST_CONC_LOW:
            # Low concentration suggests scanning many targets
            score += RECON_WEIGHT_PORT_FANOUT
            indicators.append("low_dest_concentration")
            evidence["port_fanout_assessment"] = (
                f"Low destination concentration ({dest_conc:.3f} <= {RECON_DEST_CONC_LOW}, "
                f"scan-like distribution)"
            )
        elif dest_conc <= 0.4:
            score += int(RECON_WEIGHT_PORT_FANOUT * 0.4)
            indicators.append("moderate_dest_dispersion")
            evidence["port_fanout_assessment"] = (
                f"Moderate dispersion ({dest_conc:.3f})"
            )
        else:
            evidence["port_fanout_assessment"] = (
                f"Concentrated ({dest_conc:.3f} > 0.4, not scan pattern)"
            )

        # Indicator 2: IP fan-out — multiple short flows to different hosts
        # Use entropy as proxy for diversity of destinations
        if entropy >= RECON_HIGH_IP_FANOUT / 4.0:  # Normalize to entropy scale
            score += RECON_WEIGHT_IP_FANOUT
            indicators.append("high_ip_diversity")
            evidence["ip_fanout_assessment"] = (
                f"High IP diversity (entropy {entropy:.3f} >= {RECON_HIGH_IP_FANOUT / 4:.1f})"
            )
        elif entropy >= RECON_MIN_IP_FANOUT / 4.0:
            score += int(RECON_WEIGHT_IP_FANOUT * 0.5)
            indicators.append("moderate_ip_diversity")
            evidence["ip_fanout_assessment"] = (
                f"Moderate IP diversity (entropy {entropy:.3f})"
            )
        else:
            evidence["ip_fanout_assessment"] = (
                f"Low IP diversity (entropy {entropy:.3f})"
            )

        # Indicator 3: Very short flow duration (scan probe)
        if duration <= RECON_VERY_SHORT_DURATION:
            score += RECON_WEIGHT_SHORT_FLOW
            indicators.append("very_short_flow")
            evidence["duration_assessment"] = (
                f"Very short probe ({duration:.3f}s <= {RECON_VERY_SHORT_DURATION}s)"
            )
        elif duration <= RECON_SHORT_DURATION:
            score += int(RECON_WEIGHT_SHORT_FLOW * 0.6)
            indicators.append("short_flow")
            evidence["duration_assessment"] = (
                f"Short flow ({duration:.3f}s <= {RECON_SHORT_DURATION}s)"
            )
        else:
            evidence["duration_assessment"] = f"Normal duration ({duration:.3f}s)"

        # Indicator 4: Low packet count (half-open / SYN scan)
        if total_pkts <= RECON_LOW_PKTS:
            score += RECON_WEIGHT_LOW_PKTS
            indicators.append("low_pkt_count")
            evidence["pkts_assessment"] = (
                f"Very few packets ({total_pkts} <= {RECON_LOW_PKTS}, scan probe pattern)"
            )
        elif total_pkts <= 15:
            score += int(RECON_WEIGHT_LOW_PKTS * 0.4)
            evidence["pkts_assessment"] = f"Low packet count ({total_pkts})"
        else:
            evidence["pkts_assessment"] = f"Normal packet count ({total_pkts})"

        # Indicator 5: High packet rate with low bytes (rapid probes)
        if pps >= RECON_HIGH_PPS and total_bytes < RECON_LOW_BYTES * 10:
            score += RECON_WEIGHT_PPS
            indicators.append("high_pps_low_bytes")
            evidence["pps_assessment"] = (
                f"Rapid probing ({pps:.0f} pps, {total_bytes} bytes)"
            )
        elif pps >= RECON_MIN_PPS:
            score += int(RECON_WEIGHT_PPS * 0.4)
            evidence["pps_assessment"] = f"Elevated rate ({pps:.0f} pps)"
        else:
            evidence["pps_assessment"] = f"Normal rate ({pps:.0f} pps)"

        # Indicator 6: High source entropy (distributed scan sources)
        if entropy >= RECON_HIGH_ENTROPY:
            score += RECON_WEIGHT_ENTROPY
            indicators.append("high_src_entropy")
            evidence["entropy_assessment"] = (
                f"High source diversity ({entropy:.3f} >= {RECON_HIGH_ENTROPY})"
            )
        else:
            evidence["entropy_assessment"] = f"Normal entropy ({entropy:.3f})"

        evidence["detector"] = "Reconnaissance Baseline Detector"
        evidence["method"] = "Statistical/Rule-Based Scan Pattern Scoring"
        evidence["score"] = score
        evidence["max_possible_score"] = 100
        evidence["detection_threshold"] = RECON_MIN_SCORE

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
            name="Reconnaissance Detector",
            threatClass=ThreatClass.Reconnaissance,
            status=DetectorStatus.ACTIVE,
            method="Statistical Scan Pattern Flow Scoring",
            description=(
                "Baseline reconnaissance detector using flow-level heuristics. "
                "Detects port scanning and network probing via short flow duration, "
                "low packet counts, destination dispersion, and scan-like traffic "
                "patterns. Future phase will add multi-flow port/IP correlation."
            ),
        )
