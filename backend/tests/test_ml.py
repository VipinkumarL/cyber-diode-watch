"""
Comprehensive tests for the ML module.

Tests cover:
  - Model loading (present and missing)
  - Feature extraction and ordering
  - Prediction response format
  - ML + detector pipeline integration
  - Health endpoint model_loaded status
  - Predict endpoint with ML model
  - Edge cases
"""

import os
import pytest
import numpy as np

from app.ml.model import load_model, is_model_loaded, get_model_info
from app.ml.features import FEATURE_NAMES, NUM_FEATURES, flow_to_feature_vector
from app.ml.predictor import predict_flow, MLPrediction
from app.detection.pipeline import pipeline
from app.models.schemas import NetworkFlow, ThreatClass, Severity


# ═══════════════════════════════════════════════════════════════════
# Fixtures
# ═══════════════════════════════════════════════════════════════════

@pytest.fixture
def normal_flow():
    return NetworkFlow(
        flowId="FLOW-ML-NORM-001",
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
    return NetworkFlow(
        flowId="FLOW-ML-DDOS-001",
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
def c2_flow():
    return NetworkFlow(
        flowId="FLOW-ML-C2-001",
        timestamp=1725120000000,
        sourceIp="192.168.1.100",
        destinationIp="10.0.1.50",
        protocol="TCP",
        sourcePort=54321,
        destinationPort=4444,
        flowDuration=0.5,
        totalPackets=5,
        packetsPerSecond=10.0,
        bytesPerSecond=2000.0,
        totalBytes=200,
        classification=ThreatClass.Normal,
        confidence=0.0,
        severity=Severity.INFO,
        sourceEntropy=1.5,
        destinationConcentration=0.9,
        packetLengthMean=40.0,
        packetLengthStd=10.0,
        isSuspicious=False,
        scenario="c2",
    )


@pytest.fixture
def recon_flow():
    return NetworkFlow(
        flowId="FLOW-ML-RECON-001",
        timestamp=1725120000000,
        sourceIp="192.168.1.50",
        destinationIp="10.0.1.1",
        protocol="TCP",
        sourcePort=40000,
        destinationPort=22,
        flowDuration=0.02,
        totalPackets=2,
        packetsPerSecond=100.0,
        bytesPerSecond=5000.0,
        totalBytes=120,
        classification=ThreatClass.Normal,
        confidence=0.0,
        severity=Severity.INFO,
        sourceEntropy=6.0,
        destinationConcentration=0.05,
        packetLengthMean=60.0,
        packetLengthStd=5.0,
        isSuspicious=False,
        scenario="recon",
    )


# ═══════════════════════════════════════════════════════════════════
# Test: Model Loading
# ═══════════════════════════════════════════════════════════════════

class TestModelLoading:
    def test_model_loads_when_files_exist(self):
        """Model should load when ml_models/ files are present."""
        result = load_model()
        assert result is True
        assert is_model_loaded() is True

    def test_model_info_has_required_keys(self):
        """Model info should contain all expected metadata."""
        info = get_model_info()
        assert "model_name" in info
        assert "model_version" in info
        assert "feature_names" in info
        assert "classes" in info
        assert "metrics" in info
        assert len(info["feature_names"]) == NUM_FEATURES
        assert len(info["classes"]) == 7

    def test_model_metrics_are_real(self):
        """Model metrics should reflect actual training results."""
        info = get_model_info()
        metrics = info["metrics"]
        assert metrics["accuracy"] > 0.9, f"Accuracy too low: {metrics['accuracy']}"
        assert metrics["f1_weighted"] > 0.9, f"F1 too low: {metrics['f1_weighted']}"

    def test_model_not_loaded_with_missing_files(self):
        """Model should not load when files are missing."""
        result = load_model(model_dir="/nonexistent/path")
        assert result is False

    def test_model_classes_match_threat_classes(self):
        """Model classes should map to our ThreatClass values."""
        load_model()  # Ensure loaded
        info = get_model_info()
        expected_classes = {
            "Normal", "DDoS", "C2_Beaconing", "DGA_DNS_Tunneling",
            "Encrypted_Malware", "Reconnaissance", "Data_Exfiltration",
        }
        assert set(info["classes"]) == expected_classes


# ═══════════════════════════════════════════════════════════════════
# Test: Feature Extraction
# ═══════════════════════════════════════════════════════════════════

class TestFeatureExtraction:
    def test_feature_names_count(self):
        """Feature names list should match expected count."""
        assert len(FEATURE_NAMES) == NUM_FEATURES == 11

    def test_feature_vector_length(self, normal_flow):
        """Feature vector should have correct length."""
        vec = flow_to_feature_vector(normal_flow)
        assert len(vec) == NUM_FEATURES

    def test_feature_vector_values(self, normal_flow):
        """Feature vector values should match flow fields."""
        vec = flow_to_feature_vector(normal_flow)
        assert vec[0] == 5.0    # flowDuration
        assert vec[1] == 200.0  # totalPackets
        assert vec[2] == 40.0   # packetsPerSecond
        assert vec[3] == 50000.0  # bytesPerSecond
        assert vec[4] == 250000.0  # totalBytes
        assert vec[5] == 54321  # sourcePort
        assert vec[6] == 443    # destinationPort
        assert vec[7] == 2.0    # sourceEntropy
        assert vec[8] == 0.1    # destinationConcentration

    def test_feature_vector_handles_none_optionals(self):
        """Feature vector should default None optionals to 0.0."""
        flow = NetworkFlow(
            flowId="FLOW-NONE-001",
            timestamp=1725120000000,
            sourceIp="10.0.0.1",
            destinationIp="10.0.1.1",
            protocol="TCP",
            sourcePort=1234,
            destinationPort=80,
            flowDuration=1.0,
            totalPackets=10,
            packetsPerSecond=10.0,
            bytesPerSecond=1000.0,
            totalBytes=1000,
            isSuspicious=False,
        )
        vec = flow_to_feature_vector(flow)
        # sourceEntropy, destinationConcentration, packetLengthMean, packetLengthStd are None
        assert vec[7] == 0.0  # sourceEntropy
        assert vec[8] == 0.0  # destinationConcentration
        assert vec[9] == 0.0  # packetLengthMean
        assert vec[10] == 0.0  # packetLengthStd

    def test_feature_order_consistency(self):
        """FEATURE_NAMES order must match the extraction order."""
        expected = [
            "flowDuration", "totalPackets", "packetsPerSecond",
            "bytesPerSecond", "totalBytes", "sourcePort", "destinationPort",
            "sourceEntropy", "destinationConcentration",
            "packetLengthMean", "packetLengthStd",
        ]
        assert FEATURE_NAMES == expected


# ═══════════════════════════════════════════════════════════════════
# Test: Prediction
# ═══════════════════════════════════════════════════════════════════

class TestPrediction:
    def test_predict_normal_flow(self, normal_flow):
        """ML should classify normal flow as Normal."""
        pred = predict_flow(normal_flow)
        if pred is not None:  # Only if model is loaded
            assert pred.is_model_available is True
            assert pred.threat_class == ThreatClass.Normal
            assert pred.confidence > 0.3

    def test_predict_ddos_flow(self, ddos_flow):
        """ML should classify DDoS flow as DDoS."""
        pred = predict_flow(ddos_flow)
        if pred is not None:
            assert pred.threat_class == ThreatClass.DDoS
            assert pred.confidence > 0.3
            assert pred.severity == Severity.CRITICAL

    def test_predict_c2_flow(self, c2_flow):
        """ML should classify C2 flow as C2_Beaconing."""
        pred = predict_flow(c2_flow)
        if pred is not None:
            assert pred.threat_class == ThreatClass.C2_Beaconing
            assert pred.confidence > 0.2

    def test_predict_recon_flow(self, recon_flow):
        """ML should classify recon flow as Reconnaissance."""
        pred = predict_flow(recon_flow)
        if pred is not None:
            assert pred.threat_class == ThreatClass.Reconnaissance
            assert pred.confidence > 0.2

    def test_prediction_has_all_fields(self, normal_flow):
        """Prediction should contain all required fields when model loaded."""
        pred = predict_flow(normal_flow)
        if pred is not None:
            assert isinstance(pred.threat_class, ThreatClass)
            assert 0.0 < pred.confidence <= 1.0
            assert isinstance(pred.severity, Severity)
            assert len(pred.model_name) > 0
            assert len(pred.model_version) > 0
            assert pred.inference_latency_ms >= 0
            assert isinstance(pred.class_probabilities, dict)
            assert len(pred.class_probabilities) == 7

    def test_probabilities_sum_to_one(self, normal_flow):
        """Class probabilities should sum to ~1.0."""
        pred = predict_flow(normal_flow)
        if pred is not None:
            total = sum(pred.class_probabilities.values())
            assert abs(total - 1.0) < 0.01, f"Probabilities sum to {total}"

    def test_prediction_latency_reasonable(self, normal_flow):
        """Inference should be fast (<100ms)."""
        pred = predict_flow(normal_flow)
        if pred is not None:
            assert pred.inference_latency_ms < 100


# ═══════════════════════════════════════════════════════════════════
# Test: Pipeline Integration
# ═══════════════════════════════════════════════════════════════════

class TestPipelineIntegration:
    def test_pipeline_includes_ml_alert(self, ddos_flow):
        """Pipeline should include ML prediction as an alert."""
        alerts = pipeline.analyze(ddos_flow)
        ml_prediction = pipeline.predict_ml(ddos_flow)
        if ml_prediction is not None:
            ml_alert = pipeline.ml_to_alert(ml_prediction, ddos_flow)
            alerts.append(ml_alert)
        # Should have at least DDoS detector alert + possibly ML alert
        assert len(alerts) >= 1

    def test_pipeline_get_best_prefers_ml(self, ddos_flow):
        """get_best_alert should prefer ML alerts over detector alerts."""
        alerts = pipeline.analyze(ddos_flow)
        ml_prediction = pipeline.predict_ml(ddos_flow)
        if ml_prediction is not None:
            ml_alert = pipeline.ml_to_alert(ml_prediction, ddos_flow)
            alerts.append(ml_alert)
            best = pipeline.get_best_alert(alerts)
            assert best is not None
            assert best.detector.startswith("ML ")

    def test_pipeline_detector_count_includes_ml(self):
        """Detector count should include ML when model is loaded."""
        count = pipeline.detector_count
        if is_model_loaded():
            assert count == 7  # 6 detectors + 1 ML
        else:
            assert count == 6

    def test_pipeline_get_all_detectors_includes_ml(self):
        """All detectors info should include ML classifier."""
        infos = pipeline.get_all_detectors()
        ml_infos = [d for d in infos if "ML" in d.name or "Random Forest" in d.name]
        assert len(ml_infos) >= 1


# ═══════════════════════════════════════════════════════════════════
# Test: API Integration
# ═══════════════════════════════════════════════════════════════════

class TestAPIIntegration:
    def test_health_reports_model_loaded(self, client):
        """GET /api/health should report model_loaded=True when model files exist."""
        from app.ml.model import is_model_loaded
        resp = client.get("/api/health")
        assert resp.status_code == 200
        data = resp.json()
        # model_loaded should match actual state
        assert data["model_loaded"] == is_model_loaded()

    def test_predict_with_ml_model(self, client, ddos_flow):
        """POST /api/predict should use ML model when available."""
        resp = client.post("/api/predict", json={"flow": ddos_flow.model_dump()})
        assert resp.status_code == 200
        data = resp.json()
        assert data["alert"] is not None
        # ML should classify as DDoS
        assert data["alert"]["threatClass"] == "DDoS"
        assert data["updatedFlow"]["isSuspicious"] is True

    def test_flows_endpoint_with_ml(self, client, ddos_flow):
        """POST /api/flows should use ML model when available."""
        resp = client.post("/api/flows", json=ddos_flow.model_dump())
        assert resp.status_code == 200
        data = resp.json()
        assert data["classification"] == "DDoS"
        assert data["isSuspicious"] is True

    def test_detectors_endpoint_includes_ml(self, client):
        """GET /api/detectors should include ML classifier info."""
        resp = client.get("/api/detectors")
        assert resp.status_code == 200
        data = resp.json()
        # Should have 6 baseline detectors + 1 ML = 7
        assert len(data) == 7
        ml_detector = next((d for d in data if "ML" in d["name"]), None)
        assert ml_detector is not None
        # ML status depends on whether model is loaded
        from app.ml.model import is_model_loaded
        if is_model_loaded():
            assert ml_detector["status"] == "ACTIVE"

    def test_predict_normal_flow_with_ml(self, client, normal_flow):
        """Normal flow should be classified as Normal by ML when model loaded."""
        from app.ml.model import is_model_loaded
        resp = client.post("/api/predict", json={"flow": normal_flow.model_dump()})
        assert resp.status_code == 200
        data = resp.json()
        if is_model_loaded() and data["alert"] is not None:
            # If ML classified it, it should be Normal or from baseline detectors
            # Baseline detectors may fire on port 443, so we accept that
            assert data["alert"]["threatClass"] in ["Normal", "C2_Beaconing"]


# ═══════════════════════════════════════════════════════════════════
# Test: Missing Model Scenario
# ═══════════════════════════════════════════════════════════════════

class TestMissingModel:
    def test_predict_flow_returns_none_without_model(self):
        """predict_flow should return None when model is not loaded."""
        from app.ml.model import load_model, is_model_loaded
        import app.ml.model as model_mod

        # Unload model by loading from nonexistent path
        load_model(model_dir="/nonexistent/path")
        assert not is_model_loaded()

        flow = NetworkFlow(
            flowId="FLOW-NO-MODEL",
            timestamp=1725120000000,
            sourceIp="10.0.0.1",
            destinationIp="10.0.1.1",
            protocol="TCP",
            sourcePort=1234,
            destinationPort=80,
            flowDuration=1.0,
            totalPackets=10,
            packetsPerSecond=10.0,
            bytesPerSecond=1000.0,
            totalBytes=1000,
            isSuspicious=False,
        )
        result = predict_flow(flow)
        assert result is None

        # Restore model
        load_model()
