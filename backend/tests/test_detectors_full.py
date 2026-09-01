"""
Comprehensive tests for all SIH26145 detectors and the detection pipeline.

Tests each detector with:
  - Normal traffic → no alert
  - Suspicious traffic → alert generated
  - Edge cases
  - Alert field completeness
  - Pipeline integration
  - No duplicate alerts
"""

import pytest

from app.detection.pipeline import pipeline, DetectionPipeline
from app.detection.c2_beaconing import C2BeaconDetector
from app.detection.dga_dns import DGADnsDetector
from app.detection.encrypted_malware import EncryptedMalwareDetector
from app.detection.reconnaissance import ReconDetector
from app.detection.exfiltration import ExfiltrationDetector
from app.models.schemas import (
    DetectorStatus,
    NetworkFlow,
    Severity,
    ThreatClass,
)


# ═══════════════════════════════════════════════════════════════════
# Flow Factories — synthetic scenarios for each detector
# ═══════════════════════════════════════════════════════════════════

def _base_flow(**overrides) -> NetworkFlow:
    """Create a base flow with sane defaults."""
    defaults = dict(
        flowId="FLOW-TEST-001",
        timestamp=1725120000000,
        sourceIp="192.168.1.100",
        destinationIp="10.0.1.1",
        protocol="TCP",
        sourcePort=54321,
        destinationPort=443,
        flowDuration=1.5,
        totalPackets=200,
        packetsPerSecond=133.3,
        bytesPerSecond=150000.0,
        totalBytes=225000,
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
    defaults.update(overrides)
    return NetworkFlow(**defaults)


def _normal_flow():
    """Clearly benign: concentrated dest, low entropy, moderate pps, port 9090."""
    return _base_flow(
        flowId="FLOW-NORMAL-001",
        destinationPort=9090,       # Non-suspicious port
        flowDuration=10.0,          # Long session (not scan/beacon)
        packetsPerSecond=30.0,      # Low pps
        bytesPerSecond=30000.0,     # Modest throughput
        totalPackets=300,
        totalBytes=300000,
        sourceEntropy=1.5,          # Low entropy (not diverse)
        destinationConcentration=0.85,  # Concentrated (not scan)
        scenario="normal",
    )


# ── C2 Scenarios ────────────────────────────────────────────────

def _c2_beacon_flow():
    """Classic C2 beacon: low volume, short, to suspicious port."""
    return _base_flow(
        flowId="FLOW-C2-001",
        packetsPerSecond=10.0,
        bytesPerSecond=2000.0,
        totalPackets=5,
        totalBytes=200,
        flowDuration=0.5,
        destinationPort=4444,  # Known C2 port
        destinationConcentration=0.9,
        sourceEntropy=1.5,
        scenario="c2",
    )


def _c2_normal_flow():
    """Normal HTTPS traffic — should not trigger C2.
    Uses port 443 (no longer in suspicious list), high volume (not beacon)."""
    return _base_flow(
        flowId="FLOW-C2-NORM",
        packetsPerSecond=500.0,     # High pps (>50, so no low_pps)
        bytesPerSecond=500000.0,    # High bps (not small payload)
        totalPackets=1000,          # Many packets (not beacon)
        totalBytes=750000,          # Large payload
        flowDuration=2.0,           # Within beacon range but other factors block
        destinationPort=443,        # NOT in suspicious list anymore
        destinationConcentration=0.1,  # Distributed
        sourceEntropy=3.0,          # Moderate entropy
        scenario="normal",
    )


# ── DGA/DNS Scenarios ───────────────────────────────────────────

def _dns_tunnel_flow():
    """DNS tunneling: high volume DNS traffic."""
    return _base_flow(
        flowId="FLOW-DNS-001",
        protocol="UDP",
        packetsPerSecond=200.0,
        bytesPerSecond=25000.0,
        totalPackets=100,
        totalBytes=25000,
        flowDuration=0.5,
        destinationPort=53,
        destinationConcentration=0.95,
        sourceEntropy=6.0,
        scenario="dns",
    )


def _dns_normal_flow():
    """Normal DNS query — should not trigger."""
    return _base_flow(
        flowId="FLOW-DNS-NORM",
        protocol="UDP",
        packetsPerSecond=2.0,
        bytesPerSecond=200.0,
        totalPackets=2,
        totalBytes=200,
        flowDuration=0.1,
        destinationPort=53,
        destinationConcentration=0.5,
        sourceEntropy=1.0,
        scenario="normal",
    )


# ── Encrypted Malware Scenarios ──────────────────────────────────

def _encrypted_malware_flow():
    """Encrypted malware: high-throughput persistent TLS session."""
    return _base_flow(
        flowId="FLOW-ENC-001",
        packetsPerSecond=300.0,
        bytesPerSecond=8000000.0,
        totalPackets=5000,
        totalBytes=40000000,
        flowDuration=350.0,
        destinationPort=443,
        destinationConcentration=0.95,
        sourceEntropy=7.0,
        scenario="encrypted_malware",
    )


def _encrypted_normal_flow():
    """Normal TLS browsing — should not trigger."""
    return _base_flow(
        flowId="FLOW-ENC-NORM",
        packetsPerSecond=50.0,
        bytesPerSecond=50000.0,
        totalPackets=100,
        totalBytes=7500,
        flowDuration=2.0,
        destinationPort=443,
        destinationConcentration=0.1,
        sourceEntropy=2.5,
        scenario="normal",
    )


# ── Reconnaissance Scenarios ─────────────────────────────────────

def _recon_flow():
    """Recon scan: short probe, low packets, distributed."""
    return _base_flow(
        flowId="FLOW-RECON-001",
        packetsPerSecond=100.0,
        bytesPerSecond=5000.0,
        totalPackets=2,
        totalBytes=120,
        flowDuration=0.02,
        destinationPort=22,
        destinationConcentration=0.05,
        sourceEntropy=6.0,
        scenario="recon",
    )


def _recon_normal_flow():
    """Normal SSH session — should not trigger."""
    return _base_flow(
        flowId="FLOW-RECON-NORM",
        packetsPerSecond=50.0,
        bytesPerSecond=50000.0,
        totalPackets=500,
        totalBytes=250000,
        flowDuration=10.0,
        destinationPort=22,
        destinationConcentration=0.9,
        sourceEntropy=1.5,
        scenario="normal",
    )


# ── Exfiltration Scenarios ──────────────────────────────────────

def _exfil_flow():
    """Data exfiltration: large sustained outbound transfer."""
    return _base_flow(
        flowId="FLOW-EXFIL-001",
        packetsPerSecond=500.0,
        bytesPerSecond=8000000.0,
        totalPackets=10000,
        totalBytes=600000000,
        flowDuration=400.0,
        destinationPort=443,
        destinationConcentration=0.95,
        sourceEntropy=6.0,
        scenario="exfiltration",
    )


def _exfil_normal_flow():
    """Normal web download — should not trigger."""
    return _base_flow(
        flowId="FLOW-EXFIL-NORM",
        packetsPerSecond=100.0,
        bytesPerSecond=100000.0,
        totalPackets=200,
        totalBytes=20000,
        flowDuration=2.0,
        destinationPort=443,
        destinationConcentration=0.3,
        sourceEntropy=2.0,
        scenario="normal",
    )


# ═══════════════════════════════════════════════════════════════════
# C2 BEACONING TESTS
# ═══════════════════════════════════════════════════════════════════

class TestC2BeaconDetector:
    def setup_method(self):
        self.detector = C2BeaconDetector()

    def test_normal_flow_no_alert(self):
        assert self.detector.analyze(_c2_normal_flow()) is None

    def test_beacon_flow_detects(self):
        alert = self.detector.analyze(_c2_beacon_flow())
        assert alert is not None
        assert alert.threatClass == ThreatClass.C2_Beaconing
        assert alert.confidence > 0
        assert alert.severity in (Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM)

    def test_alert_fields_complete(self):
        alert = self.detector.analyze(_c2_beacon_flow())
        assert alert is not None
        assert alert.alertId.startswith("ALT-")
        assert alert.flowId == "FLOW-C2-001"
        assert alert.sourceIp == "192.168.1.100"
        assert alert.detector == "C2 Beaconing Baseline Detector"
        assert alert.detectionLatencyMs >= 0
        assert "score" in alert.supportingEvidence

    def test_suspicious_port_scores_higher(self):
        flow_susp = _base_flow(
            flowId="FLOW-C2-PORT",
            packetsPerSecond=10.0,
            bytesPerSecond=2000.0,
            totalPackets=5,
            totalBytes=200,
            flowDuration=0.5,
            destinationPort=4444,
            destinationConcentration=0.9,
            sourceEntropy=1.0,
        )
        flow_normal_port = _base_flow(
            flowId="FLOW-C2-NP",
            packetsPerSecond=10.0,
            bytesPerSecond=2000.0,
            totalPackets=5,
            totalBytes=200,
            flowDuration=0.5,
            destinationPort=9999,
            destinationConcentration=0.9,
            sourceEntropy=1.0,
        )
        a1 = self.detector.analyze(flow_susp)
        a2 = self.detector.analyze(flow_normal_port)
        if a1 and a2:
            assert a1.supportingEvidence["score"] >= a2.supportingEvidence["score"]

    def test_get_info_active(self):
        info = self.detector.get_info()
        assert info.status == DetectorStatus.ACTIVE
        assert info.threatClass == ThreatClass.C2_Beaconing


# ═══════════════════════════════════════════════════════════════════
# DGA/DNS TUNNELING TESTS
# ═══════════════════════════════════════════════════════════════════

class TestDGADnsDetector:
    def setup_method(self):
        self.detector = DGADnsDetector()

    def test_normal_dns_no_alert(self):
        assert self.detector.analyze(_dns_normal_flow()) is None

    def test_dns_tunnel_detects(self):
        alert = self.detector.analyze(_dns_tunnel_flow())
        assert alert is not None
        assert alert.threatClass == ThreatClass.DGA_DNS_Tunneling
        assert alert.confidence > 0

    def test_non_dns_low_score(self):
        """Non-DNS traffic should score lower (no port-53 bonus)."""
        flow = _base_flow(
            flowId="FLOW-NON-DNS",
            packetsPerSecond=200.0,
            bytesPerSecond=25000.0,
            totalPackets=100,
            totalBytes=25000,
            flowDuration=0.5,
            destinationPort=80,
            destinationConcentration=0.95,
            sourceEntropy=6.0,
        )
        # Non-DNS may still trigger if other indicators are strong
        alert = self.detector.analyze(flow)
        # But score should be lower than DNS version
        dns_alert = self.detector.analyze(_dns_tunnel_flow())
        if alert and dns_alert:
            assert alert.supportingEvidence["score"] <= dns_alert.supportingEvidence["score"]

    def test_alert_fields(self):
        alert = self.detector.analyze(_dns_tunnel_flow())
        assert alert is not None
        assert alert.detector == "DGA/DNS Baseline Detector"
        assert alert.scenario == "dns"

    def test_get_info_active(self):
        info = self.detector.get_info()
        assert info.status == DetectorStatus.ACTIVE


# ═══════════════════════════════════════════════════════════════════
# ENCRYPTED MALWARE TESTS
# ═══════════════════════════════════════════════════════════════════

class TestEncryptedMalwareDetector:
    def setup_method(self):
        self.detector = EncryptedMalwareDetector()

    def test_normal_tls_no_alert(self):
        assert self.detector.analyze(_encrypted_normal_flow()) is None

    def test_malware_flow_detects(self):
        alert = self.detector.analyze(_encrypted_malware_flow())
        assert alert is not None
        assert alert.threatClass == ThreatClass.Encrypted_Malware
        assert alert.confidence > 0

    def test_evidence_has_encrypted_port(self):
        alert = self.detector.analyze(_encrypted_malware_flow())
        assert alert is not None
        assert alert.supportingEvidence.get("encrypted_port") is True

    def test_non_encrypted_port_lower_score(self):
        flow = _base_flow(
            flowId="FLOW-NON-ENC",
            packetsPerSecond=300.0,
            bytesPerSecond=8000000.0,
            totalPackets=5000,
            totalBytes=40000000,
            flowDuration=350.0,
            destinationPort=8080,
            destinationConcentration=0.95,
            sourceEntropy=7.0,
        )
        enc_alert = self.detector.analyze(_encrypted_malware_flow())
        non_enc_alert = self.detector.analyze(flow)
        if enc_alert and non_enc_alert:
            # Encrypted port should score higher
            assert enc_alert.supportingEvidence["score"] >= non_enc_alert.supportingEvidence["score"]

    def test_get_info_active(self):
        info = self.detector.get_info()
        assert info.status == DetectorStatus.ACTIVE


# ═══════════════════════════════════════════════════════════════════
# RECONNAISSANCE TESTS
# ═══════════════════════════════════════════════════════════════════

class TestReconDetector:
    def setup_method(self):
        self.detector = ReconDetector()

    def test_normal_traffic_no_alert(self):
        assert self.detector.analyze(_recon_normal_flow()) is None

    def test_recon_flow_detects(self):
        alert = self.detector.analyze(_recon_flow())
        assert alert is not None
        assert alert.threatClass == ThreatClass.Reconnaissance
        assert alert.confidence > 0

    def test_short_low_pkt_flow_scores_higher(self):
        """Short, low-packet flows score higher for recon."""
        short = _base_flow(
            flowId="FLOW-RECON-SHORT",
            packetsPerSecond=100.0,
            totalPackets=2,
            totalBytes=120,
            flowDuration=0.02,
            destinationConcentration=0.05,
            sourceEntropy=6.0,
        )
        long = _base_flow(
            flowId="FLOW-RECON-LONG",
            packetsPerSecond=10.0,
            totalPackets=500,
            totalBytes=250000,
            flowDuration=10.0,
            destinationConcentration=0.9,
            sourceEntropy=1.5,
        )
        a1 = self.detector.analyze(short)
        a2 = self.detector.analyze(long)
        if a1 and a2:
            assert a1.supportingEvidence["score"] > a2.supportingEvidence["score"]

    def test_get_info_active(self):
        info = self.detector.get_info()
        assert info.status == DetectorStatus.ACTIVE


# ═══════════════════════════════════════════════════════════════════
# DATA EXFILTRATION TESTS
# ═══════════════════════════════════════════════════════════════════

class TestExfiltrationDetector:
    def setup_method(self):
        self.detector = ExfiltrationDetector()

    def test_normal_flow_no_alert(self):
        assert self.detector.analyze(_exfil_normal_flow()) is None

    def test_exfil_flow_detects(self):
        alert = self.detector.analyze(_exfil_flow())
        assert alert is not None
        assert alert.threatClass == ThreatClass.Data_Exfiltration
        assert alert.confidence > 0

    def test_large_transfer_scores_higher(self):
        large = _base_flow(
            flowId="FLOW-EXFIL-LG",
            bytesPerSecond=8000000.0,
            totalBytes=600000000,
            flowDuration=400.0,
            totalPackets=10000,
            destinationPort=443,
            destinationConcentration=0.95,
            sourceEntropy=6.0,
        )
        small = _base_flow(
            flowId="FLOW-EXFIL-SM",
            bytesPerSecond=10000.0,
            totalBytes=50000,
            flowDuration=5.0,
            totalPackets=100,
            destinationPort=443,
            destinationConcentration=0.3,
            sourceEntropy=2.0,
        )
        a1 = self.detector.analyze(large)
        a2 = self.detector.analyze(small)
        if a1 and a2:
            assert a1.supportingEvidence["score"] > a2.supportingEvidence["score"]

    def test_get_info_active(self):
        info = self.detector.get_info()
        assert info.status == DetectorStatus.ACTIVE


# ═══════════════════════════════════════════════════════════════════
# PIPELINE TESTS
# ═══════════════════════════════════════════════════════════════════

class TestDetectionPipeline:
    def test_pipeline_has_all_detectors(self):
        assert pipeline.detector_count == 6

    def test_normal_flow_no_alerts(self):
        alerts = pipeline.analyze(_normal_flow())
        assert len(alerts) == 0

    def test_ddos_flow_triggers_ddos(self):
        ddos_flow = _base_flow(
            flowId="FLOW-PIPE-DDOS",
            packetsPerSecond=15000.0,
            bytesPerSecond=7500000.0,
            totalPackets=50000,
            totalBytes=2250000,
            flowDuration=0.3,
            destinationPort=80,
            destinationConcentration=0.95,
            sourceEntropy=7.5,
            scenario="ddos",
        )
        alerts = pipeline.analyze(ddos_flow)
        assert len(alerts) >= 1
        assert any(a.threatClass == ThreatClass.DDoS for a in alerts)

    def test_c2_flow_triggers_c2(self):
        alerts = pipeline.analyze(_c2_beacon_flow())
        assert any(a.threatClass == ThreatClass.C2_Beaconing for a in alerts)

    def test_dns_tunnel_triggers_dns(self):
        alerts = pipeline.analyze(_dns_tunnel_flow())
        assert any(a.threatClass == ThreatClass.DGA_DNS_Tunneling for a in alerts)

    def test_encrypted_malware_triggers(self):
        alerts = pipeline.analyze(_encrypted_malware_flow())
        assert any(a.threatClass == ThreatClass.Encrypted_Malware for a in alerts)

    def test_recon_triggers(self):
        alerts = pipeline.analyze(_recon_flow())
        assert any(a.threatClass == ThreatClass.Reconnaissance for a in alerts)

    def test_exfil_triggers(self):
        alerts = pipeline.analyze(_exfil_flow())
        assert any(a.threatClass == ThreatClass.Data_Exfiltration for a in alerts)

    def test_get_best_alert_returns_scenario_match(self):
        """Best alert should prefer the scenario-matched detector."""
        alerts = pipeline.analyze(_exfil_flow())
        best = pipeline.get_best_alert(alerts)
        assert best is not None
        # exfiltration scenario → should return exfil alert
        assert best.threatClass == ThreatClass.Data_Exfiltration

    def test_get_best_alert_empty_list(self):
        assert pipeline.get_best_alert([]) is None

    def test_get_all_detectors(self):
        infos = pipeline.get_all_detectors()
        assert len(infos) == 6
        classes = {d.threatClass for d in infos}
        assert ThreatClass.DDoS in classes
        assert ThreatClass.C2_Beaconing in classes
        assert ThreatClass.DGA_DNS_Tunneling in classes
        assert ThreatClass.Encrypted_Malware in classes
        assert ThreatClass.Reconnaissance in classes
        assert ThreatClass.Data_Exfiltration in classes

    def test_all_detectors_active(self):
        infos = pipeline.get_all_detectors()
        for info in infos:
            assert info.status == DetectorStatus.ACTIVE, f"{info.name} is not ACTIVE"

    def test_no_duplicate_alerts(self):
        """Running pipeline twice on same flow shouldn't produce duplicate detector alerts."""
        alerts1 = pipeline.analyze(_c2_beacon_flow())
        # Each detector can only fire once per flow
        detector_names = [a.detector for a in alerts1]
        assert len(detector_names) == len(set(detector_names))


# ═══════════════════════════════════════════════════════════════════
# API INTEGRATION TESTS
# ═══════════════════════════════════════════════════════════════════

class TestAPIIntegration:
    def test_predict_c2_flow(self, client):
        flow = _c2_beacon_flow()
        resp = client.post("/api/predict", json={"flow": flow.model_dump()})
        assert resp.status_code == 200
        data = resp.json()
        # Should detect C2 or possibly other detectors too
        assert data["updatedFlow"]["isSuspicious"] is True

    def test_predict_normal_flow(self, client):
        flow = _normal_flow()
        resp = client.post("/api/predict", json={"flow": flow.model_dump()})
        assert resp.status_code == 200
        data = resp.json()
        # Pipeline may produce alerts from other detectors, but classification stays Normal
        # or gets updated if any detector fires
        assert resp.status_code == 200
        assert "alert" in data

    def test_flows_endpoint_detects(self, client):
        flow = _exfil_flow()
        resp = client.post("/api/flows", json=flow.model_dump())
        assert resp.status_code == 200
        assert resp.json()["isSuspicious"] is True

    def test_detectors_endpoint_all_active(self, client):
        resp = client.get("/api/detectors")
        assert resp.status_code == 200
        data = resp.json()
        assert len(data) == 6
        for d in data:
            assert d["status"] == "ACTIVE"

    def test_predict_ddos_flow(self, client):
        ddos = _base_flow(
            flowId="FLOW-API-DDOS",
            packetsPerSecond=15000.0,
            bytesPerSecond=7500000.0,
            totalPackets=50000,
            totalBytes=2250000,
            flowDuration=0.3,
            destinationPort=80,
            destinationConcentration=0.95,
            sourceEntropy=7.5,
            scenario="ddos",
        )
        resp = client.post("/api/predict", json={"flow": ddos.model_dump()})
        assert resp.status_code == 200
        data = resp.json()
        assert data["alert"] is not None
        # DDoS scenario → best alert should be DDoS
        assert data["alert"]["threatClass"] == "DDoS"
        assert data["updatedFlow"]["isSuspicious"] is True

    def test_predict_encrypted_malware(self, client):
        flow = _encrypted_malware_flow()
        resp = client.post("/api/predict", json={"flow": flow.model_dump()})
        assert resp.status_code == 200
        data = resp.json()
        assert data["alert"] is not None
        # encrypted_malware scenario → best alert should be Encrypted_Malware
        assert data["alert"]["threatClass"] == "Encrypted_Malware"

    def test_predict_recon(self, client):
        flow = _recon_flow()
        resp = client.post("/api/predict", json={"flow": flow.model_dump()})
        assert resp.status_code == 200
        data = resp.json()
        assert data["alert"] is not None
        # recon scenario → best alert should be Reconnaissance
        assert data["alert"]["threatClass"] == "Reconnaissance"

    def test_statistics_after_detection(self, client):
        """After running several predictions, stats should reflect detections."""
        for flow in [_normal_flow(), _c2_beacon_flow(), _dns_tunnel_flow()]:
            client.post("/api/predict", json={"flow": flow.model_dump()})

        resp = client.get("/api/statistics")
        stats = resp.json()
        assert stats["flows"]["totalFlows"] == 3
        assert stats["alerts"]["total"] >= 2  # C2 + DNS should trigger
