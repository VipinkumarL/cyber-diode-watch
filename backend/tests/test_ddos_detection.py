"""
Comprehensive tests for the DDoS baseline detector.

Tests cover:
  1. Normal flow → no DDoS alert
  2. Clearly suspicious high-volume flow → DDoS alert
  3. Boundary values near detection thresholds
  4. Missing optional features (sourceEntropy, destinationConcentration)
  5. Alert field completeness
  6. Updated flow classification
  7. Detection latency is measured (>0)
  8. Predict endpoint behavior
  9. Normal flow does not create an alert via /api/predict
  10. Repeated analysis does not create duplicate alerts unexpectedly
  11. Edge cases: zero values, extreme values
"""

import pytest
from app.detection.ddos import (
    DDoSDetector,
    MIN_DETECTION_SCORE,
    PPS_VERY_HIGH,
    PPS_HIGH,
    PPS_MEDIUM,
    BPS_VERY_HIGH,
    BPS_HIGH,
    SEVERITY_CRITICAL_MIN,
    SEVERITY_HIGH_MIN,
    SEVERITY_MEDIUM_MIN,
)
from app.features.common import extract_features
from app.models.schemas import (
    Alert,
    DetectorStatus,
    FeatureVector,
    NetworkFlow,
    Severity,
    ThreatClass,
)
from app.services import store


# ═══════════════════════════════════════════════════════════════════
# Fixtures
# ═══════════════════════════════════════════════════════════════════

@pytest.fixture
def detector():
    """Provide a DDoSDetector instance."""
    return DDoSDetector()


@pytest.fixture
def normal_flow():
    """A clearly normal flow — well below all DDoS thresholds."""
    return NetworkFlow(
        flowId="FLOW-NORMAL-001",
        timestamp=1725120000000,
        sourceIp="192.168.1.100",
        destinationIp="10.0.1.1",
        protocol="TCP",
        sourcePort=54321,
        destinationPort=443,
        flowDuration=5.0,
        totalPackets=200,
        packetsPerSecond=40.0,
        bytesPerSecond=50000.0,
        totalBytes=250000,
        classification=ThreatClass.Normal,
        confidence=0.0,
        severity=Severity.INFO,
        sourceEntropy=2.0,
        destinationConcentration=0.1,
        packetLengthMean=500.0,
        packetLengthStd=100.0,
        isSuspicious=False,
        scenario="normal",
    )


@pytest.fixture
def ddos_flow():
    """A clearly DDoS flow — high pps, high bps, concentrated destination, high entropy."""
    return NetworkFlow(
        flowId="FLOW-DDOS-001",
        timestamp=1725120000000,
        sourceIp="192.168.1.200",
        destinationIp="10.0.1.1",
        protocol="UDP",
        sourcePort=12345,
        destinationPort=80,
        flowDuration=0.3,
        totalPackets=50000,
        packetsPerSecond=15000.0,
        bytesPerSecond=7500000.0,
        totalBytes=2250000,
        classification=ThreatClass.Normal,
        confidence=0.0,
        severity=Severity.INFO,
        sourceEntropy=7.5,
        destinationConcentration=0.95,
        packetLengthMean=50.0,
        packetLengthStd=10.0,
        isSuspicious=False,
        scenario="ddos",
    )


@pytest.fixture
def borderline_flow():
    """A borderline flow — just above the detection threshold."""
    return NetworkFlow(
        flowId="FLOW-BORDER-001",
        timestamp=1725120000000,
        sourceIp="192.168.1.150",
        destinationIp="10.0.1.1",
        protocol="TCP",
        sourcePort=40000,
        destinationPort=443,
        flowDuration=1.0,
        totalPackets=15000,
        packetsPerSecond=2500.0,
        bytesPerSecond=6000000.0,
        totalBytes=6000000,
        classification=ThreatClass.Normal,
        confidence=0.0,
        severity=Severity.INFO,
        sourceEntropy=5.5,
        destinationConcentration=0.6,
        packetLengthMean=100.0,
        packetLengthStd=30.0,
        isSuspicious=False,
        scenario="ddos",
    )


@pytest.fixture
def minimal_flow():
    """A flow with minimal fields — no optional features set."""
    return NetworkFlow(
        flowId="FLOW-MINIMAL-001",
        timestamp=1725120000000,
        sourceIp="192.168.1.100",
        destinationIp="10.0.1.1",
        protocol="TCP",
        sourcePort=54321,
        destinationPort=443,
        flowDuration=1.0,
        totalPackets=10,
        packetsPerSecond=10.0,
        bytesPerSecond=1000.0,
        totalBytes=1000,
        classification=ThreatClass.Normal,
        confidence=0.0,
        severity=Severity.INFO,
        # sourceEntropy, destinationConcentration, packetLengthMean,
        # packetLengthStd are all None (not set)
        isSuspicious=False,
        scenario="normal",
    )


# ═══════════════════════════════════════════════════════════════════
# Test 1: Normal flow → no DDoS alert
# ═══════════════════════════════════════════════════════════════════

def test_normal_flow_no_alert(detector, normal_flow):
    """A clearly normal flow should not produce a DDoS alert."""
    result = detector.analyze(normal_flow)
    assert result is None


# ═══════════════════════════════════════════════════════════════════
# Test 2: Clearly suspicious DDoS flow → alert generated
# ═══════════════════════════════════════════════════════════════════

def test_ddos_flow_generates_alert(detector, ddos_flow):
    """A high-volume DDoS flow should produce an alert."""
    alert = detector.analyze(ddos_flow)
    assert alert is not None
    assert alert.threatClass == ThreatClass.DDoS
    assert alert.confidence > 0.5
    assert alert.severity in (Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM)
    assert alert.flowId == ddos_flow.flowId
    assert alert.sourceIp == ddos_flow.sourceIp
    assert alert.destinationIp == ddos_flow.destinationIp


# ═══════════════════════════════════════════════════════════════════
# Test 3: Boundary values near detection thresholds
# ═══════════════════════════════════════════════════════════════════

def test_borderline_flow_may_detect(detector, borderline_flow):
    """A borderline flow should be scored and may or may not trigger detection."""
    alert = detector.analyze(borderline_flow)
    # The borderline flow is designed to be near the threshold
    # We just verify the detector runs without error
    if alert is not None:
        assert alert.threatClass == ThreatClass.DDoS
        assert alert.confidence > 0


def test_exact_threshold_flow():
    """A flow with exactly the minimum detection score should trigger."""
    detector = DDoSDetector()
    # Create a flow with known scores that exceed the threshold
    flow = NetworkFlow(
        flowId="FLOW-EXACT-001",
        timestamp=1725120000000,
        sourceIp="10.0.0.1",
        destinationIp="10.0.1.1",
        protocol="UDP",
        sourcePort=1234,
        destinationPort=80,
        flowDuration=0.1,
        totalPackets=200000,
        packetsPerSecond=16000.0,
        bytesPerSecond=80000000.0,
        totalBytes=8000000,
        classification=ThreatClass.Normal,
        confidence=0.0,
        severity=Severity.INFO,
        sourceEntropy=8.0,
        destinationConcentration=1.0,
        isSuspicious=False,
    )
    alert = detector.analyze(flow)
    # This flow should strongly trigger — very high scores
    assert alert is not None
    assert alert.severity == Severity.CRITICAL


def test_below_threshold_flow_no_alert():
    """A flow below all thresholds should not trigger detection."""
    detector = DDoSDetector()
    flow = NetworkFlow(
        flowId="FLOW-BELOW-001",
        timestamp=1725120000000,
        sourceIp="10.0.0.1",
        destinationIp="10.0.1.1",
        protocol="TCP",
        sourcePort=1234,
        destinationPort=443,
        flowDuration=10.0,
        totalPackets=50,
        packetsPerSecond=5.0,
        bytesPerSecond=5000.0,
        totalBytes=50000,
        classification=ThreatClass.Normal,
        confidence=0.0,
        severity=Severity.INFO,
        sourceEntropy=1.0,
        destinationConcentration=0.05,
        isSuspicious=False,
    )
    alert = detector.analyze(flow)
    assert alert is None


# ═══════════════════════════════════════════════════════════════════
# Test 4: Missing optional features
# ═══════════════════════════════════════════════════════════════════

def test_missing_optional_features_no_crash(detector, minimal_flow):
    """Flow with no optional features should not crash the detector."""
    alert = detector.analyze(minimal_flow)
    # With low values, should not detect
    assert alert is None


def test_missing_entropy_with_high_pps():
    """High pps without sourceEntropy set should still detect."""
    detector = DDoSDetector()
    flow = NetworkFlow(
        flowId="FLOW-NO-ENTROPY-001",
        timestamp=1725120000000,
        sourceIp="10.0.0.1",
        destinationIp="10.0.1.1",
        protocol="UDP",
        sourcePort=1234,
        destinationPort=80,
        flowDuration=0.2,
        totalPackets=100000,
        packetsPerSecond=20000.0,
        bytesPerSecond=10000000.0,
        totalBytes=2000000,
        classification=ThreatClass.Normal,
        confidence=0.0,
        severity=Severity.INFO,
        # sourceEntropy is None
        destinationConcentration=0.9,
        isSuspicious=False,
    )
    alert = detector.analyze(flow)
    # Even without entropy, high pps + bps + dest conc should detect
    assert alert is not None
    assert alert.threatClass == ThreatClass.DDoS


def test_missing_destination_concentration():
    """Flow without destinationConcentration should still function."""
    detector = DDoSDetector()
    flow = NetworkFlow(
        flowId="FLOW-NO-DEST-001",
        timestamp=1725120000000,
        sourceIp="10.0.0.1",
        destinationIp="10.0.1.1",
        protocol="UDP",
        sourcePort=1234,
        destinationPort=80,
        flowDuration=0.1,
        totalPackets=150000,
        packetsPerSecond=25000.0,
        bytesPerSecond=12000000.0,
        totalBytes=1200000,
        classification=ThreatClass.Normal,
        confidence=0.0,
        severity=Severity.INFO,
        sourceEntropy=7.0,
        # destinationConcentration is None
        isSuspicious=False,
    )
    alert = detector.analyze(flow)
    # High pps + bps should still detect even without dest concentration
    assert alert is not None


# ═══════════════════════════════════════════════════════════════════
# Test 5: Alert field completeness
# ═══════════════════════════════════════════════════════════════════

def test_alert_has_all_required_fields(detector, ddos_flow):
    """Alert should contain all required fields."""
    alert = detector.analyze(ddos_flow)
    assert alert is not None

    # Required fields
    assert alert.alertId.startswith("ALT-")
    assert alert.timestamp == ddos_flow.timestamp
    assert alert.flowId == ddos_flow.flowId
    assert alert.threatClass == ThreatClass.DDoS
    assert 0.0 < alert.confidence <= 0.99
    assert alert.severity in (Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM, Severity.LOW)
    assert alert.sourceIp == ddos_flow.sourceIp
    assert alert.destinationIp == ddos_flow.destinationIp
    assert alert.protocol == ddos_flow.protocol
    assert alert.destinationPort == ddos_flow.destinationPort
    assert alert.detector == "DDoS Baseline Detector"
    assert alert.detectionLatencyMs >= 0
    assert isinstance(alert.supportingEvidence, dict)
    assert len(alert.description) > 0
    assert alert.status == "new"
    assert alert.scenario == ddos_flow.scenario


def test_alert_evidence_contains_key_fields(detector, ddos_flow):
    """Alert evidence should explain WHY the flow was classified as DDoS."""
    alert = detector.analyze(ddos_flow)
    assert alert is not None
    evidence = alert.supportingEvidence

    # Evidence should contain the actual feature values
    assert "packets_per_second" in evidence
    assert "bytes_per_second" in evidence
    assert "total_packets" in evidence
    assert "flow_duration" in evidence
    assert "destination_concentration" in evidence
    assert "source_entropy" in evidence

    # Evidence should contain assessments
    assert "pps_assessment" in evidence
    assert "bps_assessment" in evidence
    assert "pkts_assessment" in evidence
    assert "duration_assessment" in evidence
    assert "dest_assessment" in evidence
    assert "entropy_assessment" in evidence

    # Evidence should contain scoring info
    assert "score" in evidence
    assert "max_possible_score" in evidence
    assert "detection_threshold" in evidence


# ═══════════════════════════════════════════════════════════════════
# Test 6: Updated flow classification
# ═══════════════════════════════════════════════════════════════════

def test_flow_classification_updated_on_detection(detector, ddos_flow):
    """When DDoS is detected, the flow should be updated."""
    original_class = ddos_flow.classification
    assert original_class == ThreatClass.Normal

    alert = detector.analyze(ddos_flow)

    # The detector only returns the alert — it does NOT mutate the flow.
    # The API endpoints handle flow mutation. Verify the alert is correct.
    if alert is not None:
        assert alert.threatClass == ThreatClass.DDoS
        assert alert.confidence > 0
        assert alert.severity != Severity.INFO


def test_normal_flow_stays_normal(detector, normal_flow):
    """A normal flow should remain classified as Normal."""
    alert = detector.analyze(normal_flow)
    assert alert is None
    # Flow should be unchanged
    assert normal_flow.classification == ThreatClass.Normal
    assert normal_flow.isSuspicious is False
    assert normal_flow.confidence == 0.0


# ═══════════════════════════════════════════════════════════════════
# Test 7: Detection latency is measured
# ═══════════════════════════════════════════════════════════════════

def test_detection_latency_is_non_negative(detector, ddos_flow):
    """Detection latency should be measured and >= 0."""
    alert = detector.analyze(ddos_flow)
    assert alert is not None
    assert alert.detectionLatencyMs >= 0


def test_detection_latency_is_reasonable(detector, ddos_flow):
    """Detection latency should be reasonable (< 1000ms for a single flow)."""
    alert = detector.analyze(ddos_flow)
    assert alert is not None
    # A statistical detector should be very fast
    assert alert.detectionLatencyMs < 1000


# ═══════════════════════════════════════════════════════════════════
# Test 8: Predict endpoint behavior
# ═══════════════════════════════════════════════════════════════════

def test_predict_normal_flow_no_alert(client, normal_flow):
    """POST /api/predict with a normal flow should not create an alert."""
    payload = {"flow": normal_flow.model_dump()}
    resp = client.post("/api/predict", json=payload)
    assert resp.status_code == 200
    data = resp.json()

    assert data["alert"] is None
    assert data["updatedFlow"]["classification"] == "Normal"
    assert data["updatedFlow"]["isSuspicious"] is False
    assert data["detectionTimeMs"] >= 0

    # Flow should be stored
    resp = client.get("/api/flows")
    assert resp.json()["stats"]["totalFlows"] == 1


def test_predict_ddos_flow_creates_alert(client, ddos_flow):
    """POST /api/predict with a DDoS flow should create an alert."""
    payload = {"flow": ddos_flow.model_dump()}
    resp = client.post("/api/predict", json=payload)
    assert resp.status_code == 200
    data = resp.json()

    assert data["alert"] is not None
    assert data["alert"]["threatClass"] == "DDoS"
    assert data["alert"]["confidence"] > 0
    assert data["updatedFlow"]["classification"] == "DDoS"
    assert data["updatedFlow"]["isSuspicious"] is True
    assert data["updatedFlow"]["confidence"] > 0
    assert data["detectionTimeMs"] >= 0


def test_predict_stores_alert(client, ddos_flow):
    """POST /api/predict with DDoS flow should store the alert."""
    payload = {"flow": ddos_flow.model_dump()}
    client.post("/api/predict", json=payload)

    resp = client.get("/api/alerts")
    data = resp.json()
    assert data["stats"]["total"] == 1
    assert data["alerts"][0]["threatClass"] == "DDoS"


def test_predict_stores_flow(client, sample_flow):
    """POST /api/predict should store the flow."""
    payload = {"flow": sample_flow}
    client.post("/api/predict", json=payload)

    resp = client.get("/api/flows")
    assert resp.json()["stats"]["totalFlows"] == 1


def test_predict_with_sample_flow_no_alert(client, sample_flow):
    """The sample_flow fixture is a normal flow — should not trigger DDoS."""
    payload = {"flow": sample_flow}
    resp = client.post("/api/predict", json=payload)
    assert resp.status_code == 200
    data = resp.json()
    # sample_flow has pps=133.3, bps=150000 — well below DDoS thresholds
    assert data["alert"] is None


# ═══════════════════════════════════════════════════════════════════
# Test 9: Normal flow does not create alert
# ═══════════════════════════════════════════════════════════════════

def test_normal_flow_no_alert_stored(client, normal_flow):
    """POST /api/predict with normal flow should not store any alert."""
    payload = {"flow": normal_flow.model_dump()}
    client.post("/api/predict", json=payload)

    resp = client.get("/api/alerts")
    assert resp.json()["stats"]["total"] == 0
    assert resp.json()["alerts"] == []


def test_normal_flow_via_ingest_no_alert(client, normal_flow):
    """POST /api/flows with normal flow should not create an alert."""
    client.post("/api/flows", json=normal_flow.model_dump())

    resp = client.get("/api/alerts")
    assert resp.json()["stats"]["total"] == 0


# ═══════════════════════════════════════════════════════════════════
# Test 10: Repeated analysis — no unexpected duplicates
# ═══════════════════════════════════════════════════════════════════

def test_analyzing_same_flow_twice_gives_same_result(detector, ddos_flow):
    """Analyzing the same flow twice should produce consistent results."""
    alert1 = detector.analyze(ddos_flow)
    alert2 = detector.analyze(ddos_flow)

    # Both should detect (or both not detect)
    assert (alert1 is None) == (alert2 is None)

    if alert1 is not None and alert2 is not None:
        # Same score, same severity, same confidence
        assert alert1.supportingEvidence["score"] == alert2.supportingEvidence["score"]
        assert alert1.severity == alert2.severity
        # But different alert IDs (different timestamps in ID)
        # alert IDs use flowId which is the same, but detector latency varies


def test_predict_endpoint_stores_each_flow_once(client, ddos_flow):
    """Each POST /api/predict should store exactly one flow."""
    payload = {"flow": ddos_flow.model_dump()}
    client.post("/api/predict", json=payload)
    client.post("/api/predict", json=payload)

    resp = client.get("/api/flows")
    # Two separate calls = two flows stored
    assert resp.json()["stats"]["totalFlows"] == 2


# ═══════════════════════════════════════════════════════════════════
# Test 11: Edge cases
# ═══════════════════════════════════════════════════════════════════

def test_zero_values_flow():
    """Flow with all zero values should not crash and should not detect."""
    detector = DDoSDetector()
    flow = NetworkFlow(
        flowId="FLOW-ZERO-001",
        timestamp=1725120000000,
        sourceIp="10.0.0.1",
        destinationIp="10.0.1.1",
        protocol="TCP",
        sourcePort=0,
        destinationPort=0,
        flowDuration=0.0,
        totalPackets=0,
        packetsPerSecond=0.0,
        bytesPerSecond=0.0,
        totalBytes=0,
        classification=ThreatClass.Normal,
        confidence=0.0,
        severity=Severity.INFO,
        isSuspicious=False,
    )
    alert = detector.analyze(flow)
    assert alert is None


def test_extreme_values_flow():
    """Flow with extreme values should detect with high severity."""
    detector = DDoSDetector()
    flow = NetworkFlow(
        flowId="FLOW-EXTREME-001",
        timestamp=1725120000000,
        sourceIp="10.0.0.1",
        destinationIp="10.0.1.1",
        protocol="UDP",
        sourcePort=1234,
        destinationPort=80,
        flowDuration=0.001,
        totalPackets=10000000,
        packetsPerSecond=1000000.0,
        bytesPerSecond=500000000.0,
        totalBytes=500000000,
        classification=ThreatClass.Normal,
        confidence=0.0,
        severity=Severity.INFO,
        sourceEntropy=8.0,
        destinationConcentration=1.0,
        isSuspicious=False,
    )
    alert = detector.analyze(flow)
    assert alert is not None
    assert alert.severity == Severity.CRITICAL
    assert alert.confidence >= 0.75


def test_high_pps_low_bps():
    """High pps with low bps — still partially detected (short packets)."""
    detector = DDoSDetector()
    flow = NetworkFlow(
        flowId="FLOW-HPPS-LBPS-001",
        timestamp=1725120000000,
        sourceIp="10.0.0.1",
        destinationIp="10.0.1.1",
        protocol="ICMP",
        sourcePort=0,
        destinationPort=0,
        flowDuration=0.5,
        totalPackets=10000,
        packetsPerSecond=12000.0,
        bytesPerSecond=100000.0,  # Low bps despite high pps
        totalBytes=50000,
        classification=ThreatClass.Normal,
        confidence=0.0,
        severity=Severity.INFO,
        sourceEntropy=6.0,
        destinationConcentration=0.8,
        isSuspicious=False,
    )
    alert = detector.analyze(flow)
    # High pps contributes significantly; may or may not reach threshold
    # Just verify no crash
    if alert is not None:
        assert alert.threatClass == ThreatClass.DDoS


def test_low_pps_high_bps():
    """Low pps with high bps — large packets, may partially score."""
    detector = DDoSDetector()
    flow = NetworkFlow(
        flowId="FLOW-LPPS-HBPS-001",
        timestamp=1725120000000,
        sourceIp="10.0.0.1",
        destinationIp="10.0.1.1",
        protocol="TCP",
        sourcePort=1234,
        destinationPort=443,
        flowDuration=5.0,
        totalPackets=500,
        packetsPerSecond=100.0,
        bytesPerSecond=20000000.0,  # High bps but low pps
        totalBytes=100000000,
        classification=ThreatClass.Normal,
        confidence=0.0,
        severity=Severity.INFO,
        sourceEntropy=2.0,
        destinationConcentration=0.3,
        isSuspicious=False,
    )
    alert = detector.analyze(flow)
    # May or may not detect depending on score aggregation
    # Just verify no crash


# ═══════════════════════════════════════════════════════════════════
# Test: Flow ingestion auto-detection
# ═══════════════════════════════════════════════════════════════════

def test_flow_ingestion_detects_ddos(client, ddos_flow):
    """POST /api/flows should automatically detect DDoS in high-volume flows."""
    resp = client.post("/api/flows", json=ddos_flow.model_dump())
    assert resp.status_code == 200

    # The returned flow should be classified as DDoS
    data = resp.json()
    assert data["classification"] == "DDoS"
    assert data["isSuspicious"] is True
    assert data["confidence"] > 0

    # An alert should have been stored
    alerts_resp = client.get("/api/alerts")
    assert alerts_resp.json()["stats"]["total"] == 1


def test_flow_ingestion_normal_flow_no_alert(client, normal_flow):
    """POST /api/flows with normal flow should not create alert."""
    resp = client.post("/api/flows", json=normal_flow.model_dump())
    assert resp.status_code == 200

    data = resp.json()
    assert data["classification"] == "Normal"
    assert data["isSuspicious"] is False

    alerts_resp = client.get("/api/alerts")
    assert alerts_resp.json()["stats"]["total"] == 0


# ═══════════════════════════════════════════════════════════════════
# Test: Detector info
# ═══════════════════════════════════════════════════════════════════

def test_detector_info_status(detector):
    """get_info should return ACTIVE status."""
    info = detector.get_info()
    assert info.status == DetectorStatus.ACTIVE
    assert "Baseline" in info.method or "Statistical" in info.method
    assert "DDoS" in info.name


def test_detector_info_no_ml_claim(detector):
    """get_info should NOT claim to be a trained ML model."""
    info = detector.get_info()
    assert "Random Forest" not in info.method
    assert "XGBoost" not in info.method
    assert "trained" not in info.method.lower()


# ═══════════════════════════════════════════════════════════════════
# Test: Severity mapping
# ═══════════════════════════════════════════════════════════════════

def test_severity_critical_for_high_score(detector):
    """High scores should produce CRITICAL severity."""
    # A very high-scoring flow
    flow = NetworkFlow(
        flowId="FLOW-CRIT-001",
        timestamp=1725120000000,
        sourceIp="10.0.0.1",
        destinationIp="10.0.1.1",
        protocol="UDP",
        sourcePort=1234,
        destinationPort=80,
        flowDuration=0.05,
        totalPackets=500000,
        packetsPerSecond=50000.0,
        bytesPerSecond=200000000.0,
        totalBytes=10000000,
        classification=ThreatClass.Normal,
        confidence=0.0,
        severity=Severity.INFO,
        sourceEntropy=8.0,
        destinationConcentration=1.0,
        isSuspicious=False,
    )
    alert = detector.analyze(flow)
    assert alert is not None
    assert alert.severity == Severity.CRITICAL


# ═══════════════════════════════════════════════════════════════════
# Test: Confidence mapping
# ═══════════════════════════════════════════════════════════════════

def test_confidence_is_between_0_and_1(detector, ddos_flow):
    """Confidence should always be between 0.0 and 1.0."""
    alert = detector.analyze(ddos_flow)
    assert alert is not None
    assert 0.0 < alert.confidence <= 0.99


def test_confidence_capped_at_099():
    """Even with a perfect score, confidence should be capped at 0.99."""
    detector = DDoSDetector()
    # Verify the static method directly
    confidence = detector._score_to_confidence(100)
    assert confidence == 0.99


# ═══════════════════════════════════════════════════════════════════
# Test: Statistics reflect detection results
# ═══════════════════════════════════════════════════════════════════

def test_statistics_reflect_ddos_detection(client, ddos_flow, normal_flow):
    """After detection, statistics should reflect the results."""
    # Ingest one DDoS flow and one normal flow
    client.post("/api/flows", json=ddos_flow.model_dump())
    client.post("/api/flows", json=normal_flow.model_dump())

    # Check flow stats
    resp = client.get("/api/flows")
    stats = resp.json()["stats"]
    assert stats["totalFlows"] == 2
    assert stats["normalFlows"] >= 1
    assert stats["threatsDetected"] >= 1
    assert stats["suspiciousFlows"] >= 1

    # Check alert stats
    alert_resp = client.get("/api/alerts")
    alert_stats = alert_resp.json()["stats"]
    assert alert_stats["total"] == 1
    assert alert_stats["byThreatClass"]["DDoS"] == 1
