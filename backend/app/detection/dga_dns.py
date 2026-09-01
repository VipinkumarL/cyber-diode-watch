"""
SIH26145 DGA/DNS Tunneling Detector — Baseline Statistical/Rule-Based.

Detects DNS-based threats using flow-level features:
  - DNS tunneling: encoding data in DNS queries/responses
  - DGA (Domain Generation Algorithm): algorithmically generated domains

Key indicators (from available flow features):
  - DNS traffic (port 53) with high entropy values
  - High bytes-per-second on DNS (data exfiltration via DNS)
  - Unusually high packet counts for DNS
  - Short, frequent DNS flows (tunneling pattern)
  - High destination concentration (single DNS server)
  - Elevated source entropy (multiple queries from one host)

LIMITATION: Without access to domain names or query content, this
detector uses flow-level heuristics. Full DGA detection would
require domain name entropy analysis — noted as future enhancement.

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

DNS_PORT = 53

# DNS tunneling indicators
DNS_HIGH_BPS = 5000.0        # Normal DNS: ~100-500 B/s; tunneling: >5KB/s
DNS_VERY_HIGH_BPS = 20000.0  # Strong tunneling indicator
DNS_HIGH_PACKETS = 20        # Normal DNS: 2-6 packets; tunneling: many more
DNS_VERY_HIGH_PACKETS = 50   # Strong indicator
DNS_HIGH_PPS = 100.0         # High query rate
DNS_MAX_DURATION = 2.0       # Tunneling flows are often short
DNS_MIN_DURATION = 0.01      # Non-zero duration
DNS_HIGH_DEST_CONC = 0.8     # Queries to single resolver
DNS_HIGH_ENTROPY = 4.0       # High entropy suggests encoded data
DNS_MAX_BYTES = 500          # Normal DNS response: 51-4096 bytes

# Scoring weights (total = 100)
DNS_WEIGHT_BPS = 30
DNS_WEIGHT_PACKETS = 25
DNS_WEIGHT_PPS = 15
DNS_WEIGHT_ENTROPY = 15
DNS_WEIGHT_DEST_CONC = 10
DNS_WEIGHT_DURATION = 5

DNS_MIN_SCORE = 40

SEVERITY_CRITICAL_MIN = 75
SEVERITY_HIGH_MIN = 55
SEVERITY_MEDIUM_MIN = 40


# ═══════════════════════════════════════════════════════════════════
# DETECTOR
# ═══════════════════════════════════════════════════════════════════

class DGADnsDetector:
    """
    Baseline DGA/DNS tunneling detector.

    Uses flow-level features to identify DNS-based threats.
    Focuses on DNS traffic characteristics that suggest tunneling
    or DGA activity.
    """

    def analyze(self, flow: NetworkFlow) -> Optional[Alert]:
        """Analyze a flow for DGA/DNS tunneling indicators."""
        start_time = time.time()
        features = extract_features(flow)
        score, indicators, evidence = self._score(features, flow)
        latency_ms = int((time.time() - start_time) * 1000)

        if score < DNS_MIN_SCORE:
            return None

        severity = self._score_to_severity(score)
        confidence = self._score_to_confidence(score)

        return Alert(
            alertId=f"ALT-{flow.timestamp}-{flow.flowId[-7:]}",
            timestamp=flow.timestamp,
            flowId=flow.flowId,
            threatClass=ThreatClass.DGA_DNS_Tunneling,
            confidence=confidence,
            severity=severity,
            sourceIp=flow.sourceIp,
            destinationIp=flow.destinationIp,
            protocol=flow.protocol,
            destinationPort=flow.destinationPort,
            detector="DGA/DNS Baseline Detector",
            detectionLatencyMs=latency_ms,
            supportingEvidence=evidence,
            description=(
                f"DGA/DNS baseline detector: score {score}/100, "
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
        total_pkts = features.totalPackets
        pps = features.packetsPerSecond
        dest_conc = features.destinationConcentration
        entropy = features.sourceEntropy
        duration = features.flowDuration
        dest_port = features.destinationPort
        total_bytes = features.totalBytes

        evidence["bytes_per_second"] = round(bps, 1)
        evidence["total_packets"] = total_pkts
        evidence["packets_per_second"] = round(pps, 1)
        evidence["destination_port"] = dest_port
        evidence["destination_concentration"] = round(dest_conc, 3)
        evidence["source_entropy"] = round(entropy, 3)
        evidence["flow_duration"] = round(duration, 3)
        evidence["total_bytes"] = total_bytes

        # Only score DNS traffic (port 53)
        is_dns = dest_port == DNS_PORT

        if not is_dns:
            # Non-DNS traffic: return immediately with zero score
            evidence["dns_assessment"] = f"Not DNS traffic (port {dest_port}, proto {flow.protocol})"
            evidence["detector"] = "DGA/DNS Baseline Detector"
            evidence["method"] = "Statistical/Rule-Based DNS Anomaly Scoring"
            evidence["score"] = 0
            evidence["max_possible_score"] = 100
            evidence["detection_threshold"] = DNS_MIN_SCORE
            return 0, indicators, evidence
        else:
            evidence["dns_assessment"] = f"DNS traffic detected (port {dest_port})"

        # Indicator 1: High bytes/sec on DNS (data in DNS)
        if bps >= DNS_VERY_HIGH_BPS:
            score += DNS_WEIGHT_BPS
            indicators.append("dns_very_high_bps")
            evidence["bps_assessment"] = f"Very high for DNS ({bps:.0f} B/s >= {DNS_VERY_HIGH_BPS})"
        elif bps >= DNS_HIGH_BPS:
            score += int(DNS_WEIGHT_BPS * 0.65)
            indicators.append("dns_high_bps")
            evidence["bps_assessment"] = f"High for DNS ({bps:.0f} B/s >= {DNS_HIGH_BPS})"
        else:
            evidence["bps_assessment"] = f"Normal for DNS ({bps:.0f} B/s)"

        # Indicator 2: High packet count (many queries = tunneling)
        if total_pkts >= DNS_VERY_HIGH_PACKETS:
            score += DNS_WEIGHT_PACKETS
            indicators.append("dns_very_high_pkts")
            evidence["pkts_assessment"] = f"Very high packet count ({total_pkts} >= {DNS_VERY_HIGH_PACKETS})"
        elif total_pkts >= DNS_HIGH_PACKETS:
            score += int(DNS_WEIGHT_PACKETS * 0.6)
            indicators.append("dns_high_pkts")
            evidence["pkts_assessment"] = f"High packet count ({total_pkts} >= {DNS_HIGH_PACKETS})"
        else:
            evidence["pkts_assessment"] = f"Normal packet count ({total_pkts})"

        # Indicator 3: High query rate
        if pps >= DNS_HIGH_PPS:
            score += DNS_WEIGHT_PPS
            indicators.append("dns_high_pps")
            evidence["pps_assessment"] = f"High query rate ({pps:.0f} >= {DNS_HIGH_PPS})"
        else:
            evidence["pps_assessment"] = f"Normal query rate ({pps:.0f})"

        # Indicator 4: High source entropy (many unique queries encoded)
        if entropy >= DNS_HIGH_ENTROPY:
            score += DNS_WEIGHT_ENTROPY
            indicators.append("dns_high_entropy")
            evidence["entropy_assessment"] = (
                f"High entropy ({entropy:.3f} >= {DNS_HIGH_ENTROPY}, suggests encoded data)"
            )
        else:
            evidence["entropy_assessment"] = f"Normal entropy ({entropy:.3f})"

        # Indicator 5: High destination concentration (single resolver)
        if dest_conc >= DNS_HIGH_DEST_CONC:
            score += DNS_WEIGHT_DEST_CONC
            indicators.append("dns_dest_concentrated")
            evidence["dest_assessment"] = (
                f"High destination concentration ({dest_conc:.3f} >= {DNS_HIGH_DEST_CONC})"
            )
        else:
            evidence["dest_assessment"] = f"Distributed ({dest_conc:.3f})"

        # Indicator 6: Short, frequent flow (tunneling pattern)
        if DNS_MIN_DURATION <= duration <= DNS_MAX_DURATION and total_pkts > 10:
            score += DNS_WEIGHT_DURATION
            indicators.append("dns_short_frequent")
            evidence["duration_assessment"] = (
                f"Short frequent flow ({duration:.3f}s, {total_pkts} pkts)"
            )
        else:
            evidence["duration_assessment"] = f"Duration: {duration:.3f}s"

        evidence["detector"] = "DGA/DNS Baseline Detector"
        evidence["method"] = "Statistical/Rule-Based DNS Anomaly Scoring"
        evidence["score"] = score
        evidence["max_possible_score"] = 100
        evidence["detection_threshold"] = DNS_MIN_SCORE

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
            name="DGA/DNS Tunnelling Detector",
            threatClass=ThreatClass.DGA_DNS_Tunneling,
            status=DetectorStatus.ACTIVE,
            method="Statistical DNS Anomaly Flow Scoring",
            description=(
                "Baseline DGA/DNS tunneling detector using flow-level heuristics. "
                "Evaluates DNS traffic byte rate, packet count, query rate, entropy, "
                "and destination concentration. Limited without domain name access — "
                "future phase will add domain entropy analysis and n-gram scoring."
            ),
        )
