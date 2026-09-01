"""
SIH26145 Data Exfiltration Detector — Baseline Statistical/Rule-Based.

Detects potential data exfiltration using flow-level features.

Key indicators:
  - Unusually high outbound bytes (data leaving the network)
  - High bytes-to-packets ratio (large payloads per packet)
  - Long-duration high-throughput transfers
  - High destination concentration (data sent to single external host)
  - Large total byte transfers
  - Elevated source entropy (automated exfiltration tool)

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

# Exfiltration indicators
EXFIL_HIGH_BPS = 500000.0         # 500KB/s sustained
EXFIL_VERY_HIGH_BPS = 5000000.0   # 5MB/s — strong indicator
EXFIL_HIGH_TOTAL_BYTES = 50000000  # 50MB total transfer
EXFIL_VERY_HIGH_TOTAL = 500000000  # 500MB — very strong
EXFIL_HIGH_DURATION = 30.0         # Long transfer
EXFIL_VERY_LONG_DURATION = 300.0   # 5+ minutes
EXFIL_HIGH_BPS_RATIO = 10000.0     # Bytes/packet > 10KB (bulk data)
EXFIL_HIGH_DEST_CONC = 0.8         # Single destination (staging)
EXFIL_MIN_TOTAL_BYTES = 1000000    # At least 1MB transfer
EXFIL_HIGH_ENTROPY = 5.0           # Automated tool traffic

# Scoring weights (total = 100)
EXFIL_WEIGHT_BPS = 25
EXFIL_WEIGHT_TOTAL = 20
EXFIL_WEIGHT_DURATION = 15
EXFIL_WEIGHT_RATIO = 15
EXFIL_WEIGHT_DEST_CONC = 10
EXFIL_WEIGHT_ENTROPY = 10
EXFIL_WEIGHT_PORT = 5

# Suspicious exfiltration ports
EXFIL_SUSPICIOUS_PORTS = {443, 8443, 993, 995, 25, 587, 465}

EXFIL_MIN_SCORE = 40

SEVERITY_CRITICAL_MIN = 75
SEVERITY_HIGH_MIN = 55
SEVERITY_MEDIUM_MIN = 40


# ═══════════════════════════════════════════════════════════════════
# DETECTOR
# ═══════════════════════════════════════════════════════════════════

class ExfiltrationDetector:
    """
    Baseline data exfiltration detector.

    Identifies suspicious outbound data transfers using flow-level
    features: high byte rates, large transfers, long durations,
    and unusual traffic patterns.
    """

    def analyze(self, flow: NetworkFlow) -> Optional[Alert]:
        """Analyze a flow for data exfiltration indicators."""
        start_time = time.time()
        features = extract_features(flow)
        score, indicators, evidence = self._score(features, flow)
        latency_ms = int((time.time() - start_time) * 1000)

        if score < EXFIL_MIN_SCORE:
            return None

        severity = self._score_to_severity(score)
        confidence = self._score_to_confidence(score)

        return Alert(
            alertId=f"ALT-{flow.timestamp}-{flow.flowId[-7:]}",
            timestamp=flow.timestamp,
            flowId=flow.flowId,
            threatClass=ThreatClass.Data_Exfiltration,
            confidence=confidence,
            severity=severity,
            sourceIp=flow.sourceIp,
            destinationIp=flow.destinationIp,
            protocol=flow.protocol,
            destinationPort=flow.destinationPort,
            detector="Exfiltration Baseline Detector",
            detectionLatencyMs=latency_ms,
            supportingEvidence=evidence,
            description=(
                f"Exfiltration baseline detector: score {score}/100, "
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

        bps = features.bytesPerSecond
        total_bytes = features.totalBytes
        duration = features.flowDuration
        total_pkts = features.totalPackets
        dest_conc = features.destinationConcentration
        entropy = features.sourceEntropy
        dest_port = features.destinationPort

        # Bytes per packet ratio (bulk data indicator)
        bytes_per_pkt = total_bytes / max(total_pkts, 1)

        evidence["bytes_per_second"] = round(bps, 1)
        evidence["total_bytes"] = total_bytes
        evidence["flow_duration"] = round(duration, 3)
        evidence["total_packets"] = total_pkts
        evidence["bytes_per_packet"] = round(bytes_per_pkt, 1)
        evidence["destination_concentration"] = round(dest_conc, 3)
        evidence["source_entropy"] = round(entropy, 3)
        evidence["destination_port"] = dest_port

        # Indicator 1: High byte rate
        if bps >= EXFIL_VERY_HIGH_BPS:
            score += EXFIL_WEIGHT_BPS
            indicators.append("exfil_very_high_bps")
            evidence["bps_assessment"] = (
                f"Very high throughput ({bps:.0f} B/s >= {EXFIL_VERY_HIGH_BPS})"
            )
        elif bps >= EXFIL_HIGH_BPS:
            score += int(EXFIL_WEIGHT_BPS * 0.6)
            indicators.append("exfil_high_bps")
            evidence["bps_assessment"] = (
                f"High throughput ({bps:.0f} B/s >= {EXFIL_HIGH_BPS})"
            )
        else:
            evidence["bps_assessment"] = f"Normal throughput ({bps:.0f} B/s)"

        # Indicator 2: Large total transfer
        if total_bytes >= EXFIL_VERY_HIGH_TOTAL:
            score += EXFIL_WEIGHT_TOTAL
            indicators.append("exfil_very_large_transfer")
            evidence["total_assessment"] = (
                f"Very large transfer ({total_bytes:,} bytes >= {EXFIL_VERY_HIGH_TOTAL:,})"
            )
        elif total_bytes >= EXFIL_HIGH_TOTAL_BYTES:
            score += int(EXFIL_WEIGHT_TOTAL * 0.6)
            indicators.append("exfil_large_transfer")
            evidence["total_assessment"] = (
                f"Large transfer ({total_bytes:,} bytes >= {EXFIL_HIGH_TOTAL_BYTES:,})"
            )
        elif total_bytes >= EXFIL_MIN_TOTAL_BYTES:
            score += int(EXFIL_WEIGHT_TOTAL * 0.3)
            evidence["total_assessment"] = (
                f"Moderate transfer ({total_bytes:,} bytes >= {EXFIL_MIN_TOTAL_BYTES:,})"
            )
        else:
            evidence["total_assessment"] = (
                f"Small transfer ({total_bytes:,} bytes)"
            )

        # Indicator 3: Long duration (sustained transfer)
        if duration >= EXFIL_VERY_LONG_DURATION:
            score += EXFIL_WEIGHT_DURATION
            indicators.append("exfil_very_long_duration")
            evidence["duration_assessment"] = (
                f"Very long transfer ({duration:.1f}s >= {EXFIL_VERY_LONG_DURATION}s)"
            )
        elif duration >= EXFIL_HIGH_DURATION:
            score += int(EXFIL_WEIGHT_DURATION * 0.6)
            indicators.append("exfil_long_duration")
            evidence["duration_assessment"] = (
                f"Long transfer ({duration:.1f}s >= {EXFIL_HIGH_DURATION}s)"
            )
        else:
            evidence["duration_assessment"] = f"Short transfer ({duration:.1f}s)"

        # Indicator 4: High bytes-per-packet ratio (bulk data)
        if bytes_per_pkt >= EXFIL_HIGH_BPS_RATIO:
            score += EXFIL_WEIGHT_RATIO
            indicators.append("exfil_high_ratio")
            evidence["ratio_assessment"] = (
                f"High bytes/packet ({bytes_per_pkt:.0f} >= {EXFIL_HIGH_BPS_RATIO}, bulk data)"
            )
        elif bytes_per_pkt >= 1000:
            score += int(EXFIL_WEIGHT_RATIO * 0.4)
            evidence["ratio_assessment"] = (
                f"Moderate bytes/packet ({bytes_per_pkt:.0f})"
            )
        else:
            evidence["ratio_assessment"] = (
                f"Normal bytes/packet ({bytes_per_pkt:.0f})"
            )

        # Indicator 5: Destination concentration (data staging)
        if dest_conc >= EXFIL_HIGH_DEST_CONC:
            score += EXFIL_WEIGHT_DEST_CONC
            indicators.append("exfil_dest_concentrated")
            evidence["dest_assessment"] = (
                f"High concentration ({dest_conc:.3f} >= {EXFIL_HIGH_DEST_CONC}, data staging)"
            )
        else:
            evidence["dest_assessment"] = f"Distributed ({dest_conc:.3f})"

        # Indicator 6: High entropy (automated tool)
        if entropy >= EXFIL_HIGH_ENTROPY:
            score += EXFIL_WEIGHT_ENTROPY
            indicators.append("exfil_high_entropy")
            evidence["entropy_assessment"] = (
                f"High entropy ({entropy:.3f} >= {EXFIL_HIGH_ENTROPY})"
            )
        else:
            evidence["entropy_assessment"] = f"Normal entropy ({entropy:.3f})"

        # Indicator 7: Suspicious exfiltration port
        if dest_port in EXFIL_SUSPICIOUS_PORTS:
            score += EXFIL_WEIGHT_PORT
            indicators.append("exfil_suspicious_port")
            evidence["port_assessment"] = (
                f"Suspicious port {dest_port} (known exfiltration channel)"
            )
        else:
            evidence["port_assessment"] = f"Port {dest_port}"

        evidence["detector"] = "Exfiltration Baseline Detector"
        evidence["method"] = "Statistical/Rule-Based Outbound Transfer Scoring"
        evidence["score"] = score
        evidence["max_possible_score"] = 100
        evidence["detection_threshold"] = EXFIL_MIN_SCORE

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
            name="Data Exfiltration Detector",
            threatClass=ThreatClass.Data_Exfiltration,
            status=DetectorStatus.ACTIVE,
            method="Statistical Outbound Transfer Anomaly Scoring",
            description=(
                "Baseline data exfiltration detector using flow-level heuristics. "
                "Evaluates byte rate, total transfer volume, duration, bytes-per-packet "
                "ratio, destination concentration, and entropy to identify suspicious "
                "outbound data transfers. Future phase will add outbound/inbound "
                "ratio analysis and flow correlation."
            ),
        )
