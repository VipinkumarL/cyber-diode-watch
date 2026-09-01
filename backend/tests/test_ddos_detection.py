"""
Comprehensive tests for the DDoS baseline detector.

Tests cover:
  1. Normal flow → no DDoS alert
  2. Clearly suspicious high-volume flow → DDoS alert
  3. Boundary values near detection thresholds
  4. Missing optional features
  5. Alert field completeness
  6. Updated flow classification
  7. Detection latency is measured
  8. Predict endpoint behavior (with full pipeline)
  9. Normal flow does not create DDoS alert
  10. Repeated analysis consistency
"""

import pytest
from app.detection.ddos import (
    DDoSDetector,
    MIN_DETECTION_SCORE,
)
from app.detection.pipeline import pipeline
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


# ═══════════════════════════════════════════════════════════════════
# Test 1: Normal flow → no DDoS alert (standalone detector)
# ═══════════════════════════════════════════════════════════════════

def test_normal_flow_no_alert(detector, normal_flow):
    assert detector.analyze(normal_flow) is None


# ═══════════════════════════════════════════════════════════════════
# Test 2: Clearly suspicious DDoS flow → alert generated
# ═══════════════════════════════════════════════════════════════════

def test_ddos_flow_generates_alert(detector, ddos_flow):
    alert = detector.analyze(ddos_flow)
    assert alert is not None
    assert alert.threatClass == ThreatClass.DDoS
    assert alert.confidence > 0.5
    assert alert.severity in (Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM)
    assert alert.flowId == ddos_flow.flowId


# ═══════════════════════════════════════════════════════════════════
# Test 3: Boundary values
# ═══════════════════════════════════════════════════════════════════

def test_borderline_flow_may_detect(detector):
    flow = NetworkFlow(
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
    # Just verify no crash
    detector.analyze(flow)


def test_below_threshold_flow_no_alert():
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

def test_missing_optional_features_no_crash(detector):
    flow = NetworkFlow(
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
        isSuspicious=False,
    )
    alert = detector.analyze(flow)
    assert alert is None


def test_missing_entropy_with_high_pps():
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
        destinationConcentration=0.9,
        isSuspicious=False,
    )
    alert = detector.analyze(flow)
    assert alert is not None
    assert alert.threatClass == ThreatClass.DDoS


# ═══════════════════════════════════════════════════════════════════
# Test 5: Alert field completeness
# ═══════════════════════════════════════════════════════════════════

def test_alert_has_all_required_fields(detector, ddos_flow):
    alert = detector.analyze(ddos_flow)
    assert alert is not None
    assert alert.alertId.startswith("ALT-")
    assert alert.timestamp == ddos_flow.timestamp
    assert alert.flowId == ddos_flow.flowId
    assert alert.threatClass == ThreatClass.DDoS
    assert 0.0 < alert.confidence <= 0.99
    assert alert.severity in (Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM, Severity.LOW)
    assert alert.sourceIp == ddos_flow.sourceIp
    assert alert.destinationIp == ddos_flow.destinationIp
    assert alert.protocol == ddos_flow.protocol
    assert alert.detector == "DDoS Baseline Detector"
    assert alert.detectionLatencyMs >= 0
    assert isinstance(alert.supportingEvidence, dict)
    assert len(alert.description) > 0
    assert alert.status == "new"


def test_alert_evidence_contains_key_fields(detector, ddos_flow):
    alert = detector.analyze(ddos_flow)
    assert alert is not None
    evidence = alert.supportingEvidence
    assert "packets_per_second" in evidence
    assert "bytes_per_second" in evidence
    assert "total_packets" in evidence
    assert "flow_duration" in evidence
    assert "destination_concentration" in evidence
    assert "source_entropy" in evidence
    assert "score" in evidence


# ═══════════════════════════════════════════════════════════════════
# Test 6: Flow classification
# ═══════════════════════════════════════════════════════════════════

def test_flow_classification_updated_on_detection(detector, ddos_flow):
    alert = detector.analyze(ddos_flow)
    if alert is not None:
        assert alert.threatClass == ThreatClass.DDoS
        assert alert.confidence > 0
        assert alert.severity != Severity.INFO


def test_normal_flow_stays_normal(detector, normal_flow):
    alert = detector.analyze(normal_flow)
    assert alert is None
    assert normal_flow.classification == ThreatClass.Normal
    assert normal_flow.isSuspicious is False
    assert normal_flow.confidence == 0.0


# ═══════════════════════════════════════════════════════════════════
# Test 7: Detection latency
# ═══════════════════════════════════════════════════════════════════

def test_detection_latency_is_non_negative(detector, ddos_flow):
    alert = detector.analyze(ddos_flow)
    assert alert is not None
    assert alert.detectionLatencyMs >= 0


def test_detection_latency_is_reasonable(detector, ddos_flow):
    alert = detector.analyze(ddos_flow)
    assert alert is not None
    assert alert.detectionLatencyMs < 1000


# ═══════════════════════════════════════════════════════════════════
# Test 8: Predict endpoint (with full pipeline)
# ═══════════════════════════════════════════════════════════════════

def test_predict_ddos_flow_creates_alert(client, ddos_flow):
    """POST /api/predict with DDoS flow should create at least one alert."""
    payload = {"flow": ddos_flow.model_dump()}
    resp = client.post("/api/predict", json=payload)
    assert resp.status_code == 200
    data = resp.json()
    assert data["alert"] is not None
    # The best alert should be DDoS (scenario-matched)
    assert data["alert"]["threatClass"] == "DDoS"
    assert data["updatedFlow"]["classification"] == "DDoS"
    assert data["updatedFlow"]["isSuspicious"] is True


def test_predict_stores_alert(client, ddos_flow):
    """POST /api/predict with DDoS flow should store alerts."""
    payload = {"flow": ddos_flow.model_dump()}
    client.post("/api/predict", json=payload)
    resp = client.get("/api/alerts")
    data = resp.json()
    # Pipeline may produce multiple alerts for the same flow
    assert data["stats"]["total"] >= 1
    # At least one should be DDoS
    assert any(a["threatClass"] == "DDoS" for a in data["alerts"])


def test_predict_stores_flow(client, ddos_flow):
    payload = {"flow": ddos_flow.model_dump()}
    client.post("/api/predict", json=payload)
    resp = client.get("/api/flows")
    assert resp.json()["stats"]["totalFlows"] == 1


def test_predict_normal_flow_may_trigger_non_ddos(client, normal_flow):
    """A normal flow should not trigger DDoS, but may trigger other detectors."""
    payload = {"flow": normal_flow.model_dump()}
    resp = client.post("/api/predict", json=payload)
    assert resp.status_code == 200
    data = resp.json()
    # Should NOT be classified as DDoS
    if data["alert"] is not None:
        assert data["alert"]["threatClass"] != ThreatClass.DDoS


def test_analyzing_same_flow_twice_gives_same_result(detector, ddos_flow):
    alert1 = detector.analyze(ddos_flow)
    alert2 = detector.analyze(ddos_flow)
    assert (alert1 is None) == (alert2 is None)
    if alert1 is not None and alert2 is not None:
        assert alert1.supportingEvidence["score"] == alert2.supportingEvidence["score"]
        assert alert1.severity == alert2.severity


def test_predict_endpoint_stores_each_flow_once(client, ddos_flow):
    payload = {"flow": ddos_flow.model_dump()}
    client.post("/api/predict", json=payload)
    client.post("/api/predict", json=payload)
    resp = client.get("/api/flows")
    assert resp.json()["stats"]["totalFlows"] == 2


# ═══════════════════════════════════════════════════════════════════
# Test: Edge cases
# ═══════════════════════════════════════════════════════════════════

def test_zero_values_flow():
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


# ═══════════════════════════════════════════════════════════════════
# Test: Flow ingestion auto-detection (pipeline)
# ═══════════════════════════════════════════════════════════════════

def test_flow_ingestion_detects_ddos(client, ddos_flow):
    resp = client.post("/api/flows", json=ddos_flow.model_dump())
    assert resp.status_code == 200
    data = resp.json()
    assert data["classification"] == "DDoS"
    assert data["isSuspicious"] is True
    assert data["confidence"] > 0

    alerts_resp = client.get("/api/alerts")
    assert alerts_resp.json()["stats"]["total"] >= 1


# ═══════════════════════════════════════════════════════════════════
# Test: Detector info
# ═══════════════════════════════════════════════════════════════════

def test_detector_info_status(detector):
    info = detector.get_info()
    assert info.status == DetectorStatus.ACTIVE
    assert "Baseline" in info.method or "Statistical" in info.method


def test_detector_info_no_ml_claim(detector):
    info = detector.get_info()
    assert "Random Forest" not in info.method
    assert "XGBoost" not in info.method


# ═══════════════════════════════════════════════════════════════════
# Test: Confidence
# ═══════════════════════════════════════════════════════════════════

def test_confidence_is_between_0_and_1(detector, ddos_flow):
    alert = detector.analyze(ddos_flow)
    assert alert is not None
    assert 0.0 < alert.confidence <= 0.99


def test_confidence_capped_at_099():
    detector = DDoSDetector()
    confidence = detector._score_to_confidence(100)
    assert confidence == 0.99


# ═══════════════════════════════════════════════════════════════════
# Test: Statistics
# ═══════════════════════════════════════════════════════════════════

def test_statistics_reflect_ddos_detection(client, ddos_flow):
    client.post("/api/flows", json=ddos_flow.model_dump())
    resp = client.get("/api/flows")
    stats = resp.json()["stats"]
    assert stats["totalFlows"] == 1
    assert stats["threatsDetected"] >= 1
    assert stats["suspiciousFlows"] >= 1

    alert_resp = client.get("/api/alerts")
    alert_stats = alert_resp.json()["stats"]
    assert alert_stats["total"] >= 1
    assert alert_stats["byThreatClass"]["DDoS"] >= 1
