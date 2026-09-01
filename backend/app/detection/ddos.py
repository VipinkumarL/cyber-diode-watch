"""
SIH26145 DDoS Detector — Baseline Statistical/Rule-Based Detector.

This is a BASELINE detector, NOT an ML model. It uses statistically
derived thresholds from CICIDS2017 DDoS traffic patterns to score
flow records against known volumetric attack signatures.

The scoring is deterministic, explainable, and configurable.

Thresholds were chosen based on published CICIDS2017 flow statistics:
  - Normal traffic: typically <500 pps, <500KB/s per flow
  - DDoS traffic: typically >5000 pps, >5MB/s, high source entropy,
    short bursts, high destination concentration

Status: ACTIVE — working baseline detector.
Future phase: Replace heuristic scoring with trained Random Forest/XGBoost.
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
from ..services import store


# ═══════════════════════════════════════════════════════════════════
# CONFIGURATION — All detection thresholds in one place
# ═══════════════════════════════════════════════════════════════════
#
# Thresholds derived from CICIDS2017 published statistics:
#   - Normal flows: median ~100 pps, ~50KB/s
#   - DDoS flows: median ~15,000 pps, ~7.5MB/s
#   - Source entropy for DDoS: typically 5-8 (many spoofed sources)
#   - Destination concentration for DDoS: 0.6-1.0 (targeted)
#
# Scoring weights reflect indicator reliability based on
# empirical separation between normal and DDoS distributions.
# ═══════════════════════════════════════════════════════════════════

# ── Packet Rate Thresholds (pps) ─────────────────────────────────
# Normal: median ~100 pps, 95th percentile ~500 pps
# DDoS: median ~15,000 pps, minimum detectable ~1,000 pps
PPS_VERY_HIGH = 10000   # Strong DDoS indicator
PPS_HIGH = 5000         # Moderate DDoS indicator
PPS_MEDIUM = 2000       # Weak DDoS indicator
PPS_ELEVATED = 1000     # Borderline — needs corroboration

# ── Byte Rate Thresholds (bytes/sec) ─────────────────────────────
# Normal: median ~50KB/s, 95th percentile ~500KB/s
# DDoS: median ~7.5MB/s
BPS_VERY_HIGH = 50_000_000  # 50 MB/s — strong indicator
BPS_HIGH = 10_000_000        # 10 MB/s — moderate indicator
BPS_MEDIUM = 5_000_000       # 5 MB/s — weak indicator
BPS_ELEVATED = 1_000_000     # 1 MB/s — borderline

# ── Total Packet Count ────────────────────────────────────────────
# DDoS flows tend to carry massive packet counts in short bursts
PKTS_VERY_HIGH = 100_000
PKTS_HIGH = 50_000
PKTS_MEDIUM = 10_000

# ── Flow Duration ─────────────────────────────────────────────────
# DDoS floods are often short, intense bursts (<2s at high pps)
DURATION_SHORT_BURST = 0.5   # Very short — suspicious if pps is high
DURATION_SHORT = 2.0         # Short — mildly suspicious

# ── Destination Concentration ─────────────────────────────────────
# Normal: 0.0-0.3 (distributed destinations)
# DDoS: 0.6-1.0 (all traffic toward one target)
DEST_CONCENTRATED = 0.8     # Strong indicator
DEST_MODERATE = 0.5         # Moderate indicator

# ── Source IP Entropy ─────────────────────────────────────────────
# Normal: 1-4 (few distinct sources)
# DDoS: 5-8 (many spoofed/distinct sources)
SRC_ENTROPY_HIGH = 7.0      # Many sources — strong indicator
SRC_ENTROPY_ELEVATED = 5.0  # Moderate number of sources
SRC_ENTROPY_MILD = 3.0      # Slightly elevated

# ── Scoring Weights ───────────────────────────────────────────────
# Each indicator contributes a maximum score. Total possible = 100.
# Weights reflect empirical reliability of each indicator.
WEIGHT_PPS = 35          # Most reliable single indicator
WEIGHT_BYTES = 25        # Second most reliable
WEIGHT_PACKETS = 15      # Good corroborating indicator
WEIGHT_DURATION = 10     # Short burst at high pps is suspicious
WEIGHT_DEST_CONC = 10    # Targeted attack indicator
WEIGHT_SRC_ENTROPY = 5   # Source diversity indicator

# ── Classification Thresholds ─────────────────────────────────────
# Minimum score to trigger a DDoS classification
MIN_DETECTION_SCORE = 35

# ── Severity Mapping ──────────────────────────────────────────────
SEVERITY_CRITICAL_MIN = 75  # score >= 75 → CRITICAL
SEVERITY_HIGH_MIN = 50      # score >= 50 → HIGH
SEVERITY_MEDIUM_MIN = 35    # score >= 35 → MEDIUM
# score < 35 → Normal (no alert)


# ═══════════════════════════════════════════════════════════════════
# DETECTION ENGINE
# ═══════════════════════════════════════════════════════════════════

class DDoSDetector:
    """
    Statistical/rule-based DDoS baseline detector.

    Uses multi-factor scoring against CICIDS2017-derived thresholds.
    Deterministic, explainable, and configurable via module constants.

    Each flow is scored on six indicators:
      1. Packets per second (weight: 35)
      2. Bytes per second (weight: 25)
      3. Total packet count (weight: 15)
      4. Flow duration pattern (weight: 10)
      5. Destination concentration (weight: 10)
      6. Source IP entropy (weight: 5)

    Total possible score: 100.
    Detection threshold: 35 (MEDIUM severity minimum).
    """

    def analyze(self, flow: NetworkFlow) -> Optional[Alert]:
        """
        Analyze a network flow for DDoS indicators.

        Args:
            flow: The network flow record to analyze.

        Returns:
            An Alert if DDoS behavior is detected, None otherwise.
        """
        start_time = time.time()

        features = extract_features(flow)
        score, indicators, evidence = self._score_flow(features, features)

        detection_latency_ms = int((time.time() - start_time) * 1000)

        if score < MIN_DETECTION_SCORE:
            return None

        severity = self._score_to_severity(score)
        confidence = self._score_to_confidence(score)

        alert = Alert(
            alertId=f"ALT-{flow.timestamp}-{flow.flowId[-7:]}",
            timestamp=flow.timestamp,
            flowId=flow.flowId,
            threatClass=ThreatClass.DDoS,
            confidence=confidence,
            severity=severity,
            sourceIp=flow.sourceIp,
            destinationIp=flow.destinationIp,
            protocol=flow.protocol,
            destinationPort=flow.destinationPort,
            detector="DDoS Baseline Detector",
            detectionLatencyMs=detection_latency_ms,
            supportingEvidence=evidence,
            description=(
                f"DDoS baseline detector: score {score}/100, "
                f"confidence {confidence:.0%}. "
                f"Triggered indicators: {', '.join(indicators)}."
            ),
            status="new",
            scenario=flow.scenario,
        )

        return alert

    def _score_flow(
        self,
        features: FeatureVector,
        raw_features: FeatureVector,
    ) -> tuple[int, list[str], dict[str, float | str]]:
        """
        Score a flow against DDoS thresholds.

        Returns:
            (score, triggered_indicators, evidence_dict)
        """
        score = 0
        indicators: list[str] = []
        evidence: dict[str, float | str] = {}

        # ── Indicator 1: Packets per second ──────────────────────
        pps = features.packetsPerSecond
        evidence["packets_per_second"] = round(pps, 1)

        if pps >= PPS_VERY_HIGH:
            score += WEIGHT_PPS
            indicators.append("pps_very_high")
            evidence["pps_assessment"] = f"Very high ({pps:.0f} pps >= {PPS_VERY_HIGH})"
        elif pps >= PPS_HIGH:
            score += int(WEIGHT_PPS * 0.8)
            indicators.append("pps_high")
            evidence["pps_assessment"] = f"High ({pps:.0f} pps >= {PPS_HIGH})"
        elif pps >= PPS_MEDIUM:
            score += int(WEIGHT_PPS * 0.55)
            indicators.append("pps_medium")
            evidence["pps_assessment"] = f"Elevated ({pps:.0f} pps >= {PPS_MEDIUM})"
        elif pps >= PPS_ELEVATED:
            score += int(WEIGHT_PPS * 0.3)
            indicators.append("pps_elevated")
            evidence["pps_assessment"] = f"Slightly elevated ({pps:.0f} pps >= {PPS_ELEVATED})"
        else:
            evidence["pps_assessment"] = f"Normal ({pps:.0f} pps < {PPS_ELEVATED})"

        # ── Indicator 2: Bytes per second ────────────────────────
        bps = features.bytesPerSecond
        evidence["bytes_per_second"] = round(bps, 1)

        if bps >= BPS_VERY_HIGH:
            score += WEIGHT_BYTES
            indicators.append("bps_very_high")
            evidence["bps_assessment"] = f"Very high ({bps:.0f} B/s >= {BPS_VERY_HIGH})"
        elif bps >= BPS_HIGH:
            score += int(WEIGHT_BYTES * 0.75)
            indicators.append("bps_high")
            evidence["bps_assessment"] = f"High ({bps:.0f} B/s >= {BPS_HIGH})"
        elif bps >= BPS_MEDIUM:
            score += int(WEIGHT_BYTES * 0.5)
            indicators.append("bps_medium")
            evidence["bps_assessment"] = f"Moderate ({bps:.0f} B/s >= {BPS_MEDIUM})"
        elif bps >= BPS_ELEVATED:
            score += int(WEIGHT_BYTES * 0.25)
            indicators.append("bps_elevated")
            evidence["bps_assessment"] = f"Slightly elevated ({bps:.0f} B/s >= {BPS_ELEVATED})"
        else:
            evidence["bps_assessment"] = f"Normal ({bps:.0f} B/s < {BPS_ELEVATED})"

        # ── Indicator 3: Total packet count ──────────────────────
        pkts = features.totalPackets
        evidence["total_packets"] = pkts

        if pkts >= PKTS_VERY_HIGH:
            score += WEIGHT_PACKETS
            indicators.append("pkts_very_high")
            evidence["pkts_assessment"] = f"Very high ({pkts:,} >= {PKTS_VERY_HIGH:,})"
        elif pkts >= PKTS_HIGH:
            score += int(WEIGHT_PACKETS * 0.7)
            indicators.append("pkts_high")
            evidence["pkts_assessment"] = f"High ({pkts:,} >= {PKTS_HIGH:,})"
        elif pkts >= PKTS_MEDIUM:
            score += int(WEIGHT_PACKETS * 0.4)
            indicators.append("pkts_medium")
            evidence["pkts_assessment"] = f"Moderate ({pkts:,} >= {PKTS_MEDIUM:,})"
        else:
            evidence["pkts_assessment"] = f"Normal ({pkts:,} < {PKTS_MEDIUM:,})"

        # ── Indicator 4: Flow duration pattern ───────────────────
        # Short, intense bursts are characteristic of DDoS floods
        duration = features.flowDuration
        evidence["flow_duration"] = round(duration, 3)

        if duration < DURATION_SHORT_BURST and pps >= PPS_MEDIUM:
            score += WEIGHT_DURATION
            indicators.append("short_burst")
            evidence["duration_assessment"] = (
                f"Short burst ({duration:.3f}s < {DURATION_SHORT_BURST}s at {pps:.0f} pps)"
            )
        elif duration < DURATION_SHORT and pps >= PPS_HIGH:
            score += int(WEIGHT_DURATION * 0.6)
            indicators.append("short_duration")
            evidence["duration_assessment"] = (
                f"Short duration ({duration:.3f}s < {DURATION_SHORT}s at {pps:.0f} pps)"
            )
        else:
            evidence["duration_assessment"] = (
                f"Normal ({duration:.3f}s)"
            )

        # ── Indicator 5: Destination concentration ───────────────
        # DDoS targets specific hosts; high concentration = suspicious
        dest_conc = features.destinationConcentration
        evidence["destination_concentration"] = round(dest_conc, 3)

        if dest_conc >= DEST_CONCENTRATED:
            score += WEIGHT_DEST_CONC
            indicators.append("dest_concentrated")
            evidence["dest_assessment"] = (
                f"Highly concentrated ({dest_conc:.3f} >= {DEST_CONCENTRATED})"
            )
        elif dest_conc >= DEST_MODERATE:
            score += int(WEIGHT_DEST_CONC * 0.5)
            indicators.append("dest_moderate")
            evidence["dest_assessment"] = (
                f"Moderately concentrated ({dest_conc:.3f} >= {DEST_MODERATE})"
            )
        else:
            evidence["dest_assessment"] = (
                f"Distributed ({dest_conc:.3f} < {DEST_MODERATE})"
            )

        # ── Indicator 6: Source IP entropy ───────────────────────
        # High entropy = many distinct source IPs (spoofed/flood)
        src_ent = features.sourceEntropy
        evidence["source_entropy"] = round(src_ent, 3)

        if src_ent >= SRC_ENTROPY_HIGH:
            score += WEIGHT_SRC_ENTROPY
            indicators.append("src_entropy_high")
            evidence["entropy_assessment"] = (
                f"High source diversity ({src_ent:.3f} >= {SRC_ENTROPY_HIGH})"
            )
        elif src_ent >= SRC_ENTROPY_ELEVATED:
            score += int(WEIGHT_SRC_ENTROPY * 0.6)
            indicators.append("src_entropy_elevated")
            evidence["entropy_assessment"] = (
                f"Moderate source diversity ({src_ent:.3f} >= {SRC_ENTROPY_ELEVATED})"
            )
        elif src_ent >= SRC_ENTROPY_MILD:
            score += int(WEIGHT_SRC_ENTROPY * 0.3)
            indicators.append("src_entropy_mild")
            evidence["entropy_assessment"] = (
                f"Slightly elevated ({src_ent:.3f} >= {SRC_ENTROPY_MILD})"
            )
        else:
            evidence["entropy_assessment"] = (
                f"Low source diversity ({src_ent:.3f} < {SRC_ENTROPY_MILD})"
            )

        # ── Summary evidence ─────────────────────────────────────
        evidence["detector"] = "DDoS Baseline Detector"
        evidence["method"] = "Statistical/Rule-Based Multi-Factor Scoring"
        evidence["score"] = score
        evidence["max_possible_score"] = 100
        evidence["detection_threshold"] = MIN_DETECTION_SCORE

        return score, indicators, evidence

    @staticmethod
    def _score_to_severity(score: int) -> Severity:
        """Map a detection score to a severity level."""
        if score >= SEVERITY_CRITICAL_MIN:
            return Severity.CRITICAL
        if score >= SEVERITY_HIGH_MIN:
            return Severity.HIGH
        if score >= SEVERITY_MEDIUM_MIN:
            return Severity.MEDIUM
        return Severity.LOW

    @staticmethod
    def _score_to_confidence(score: int) -> float:
        """
        Convert a detection score to a heuristic confidence value.

        NOTE: This is NOT an ML probability. It is a linear mapping
        from the [0, 100] score range to [0.0, 0.99] confidence range.
        The 0.99 cap prevents false certainty.

        Future phase: Replace with actual model.predict_proba() output.
        """
        # Linear mapping: score 35 (threshold) → ~0.35, score 100 → 0.99
        confidence = min(0.99, score / 100.0)
        return round(confidence, 4)

    def get_info(self) -> DetectorInfo:
        """Return detector metadata for the /api/detectors endpoint."""
        return DetectorInfo(
            name="DDoS Detector",
            threatClass=ThreatClass.DDoS,
            status=DetectorStatus.ACTIVE,
            method="Statistical/Rule-Based Flow Anomaly Baseline",
            description=(
                "Baseline DDoS detector using multi-factor statistical scoring. "
                "Evaluates packets/sec, bytes/sec, flow duration, destination "
                "concentration, and source entropy against CICIDS2017-derived "
                "thresholds. Deterministic and explainable. "
                "Not a trained ML model — future phase will integrate "
                "Random Forest/XGBoost trained on labeled CICIDS2017 data."
            ),
        )
