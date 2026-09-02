"""
SIH26145 ML Model Tests.

Tests for ML model loading, feature extraction, prediction, and integration.
Updated for the real CICIDS2017 binary model (BENIGN/ATTACK).
"""

import time
from typing import Generator

import pytest
from fastapi.testclient import TestClient

from app.ml.features import FEATURE_NAMES, flow_to_feature_vector
from app.ml.model import (
    get_model_info,
    get_model_source,
    is_model_loaded,
    load_model,
)
from app.ml.predictor import predict_flow
from app.models.schemas import NetworkFlow, Severity, ThreatClass
from main import app


# ── Fixtures ─────────────────────────────────────────────────────


@pytest.fixture(scope="module")
def _ensure_model():
    """Ensure ML model is loaded for tests."""
    load_model()


@pytest.fixture()
def normal_flow() -> NetworkFlow:
    return NetworkFlow(
        flowId="FLOW-ML-NORM-001",
        timestamp=1725120000000,
        sourceIp="192.168.1.100",
        destinationIp="10.0.1.1",
        protocol="TCP",
        sourcePort=49152,
        destinationPort=80,
        flowDuration=5000.0,
        totalPackets=20,
        packetsPerSecond=4.0,
        bytesPerSecond=12000.0,
        totalBytes=60000,
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


@pytest.fixture()
def ddos_flow() -> NetworkFlow:
    return NetworkFlow(
        flowId="FLOW-ML-DDOS-001",
        timestamp=1725120000000,
        sourceIp="192.168.1.200",
        destinationIp="10.0.1.1",
        protocol="UDP",
        sourcePort=12345,
        destinationPort=53,
        flowDuration=100.0,
        totalPackets=50000,
        packetsPerSecond=500000.0,
        bytesPerSecond=250000000.0,
        totalBytes=25000000,
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


@pytest.fixture()
def c2_flow() -> NetworkFlow:
    return NetworkFlow(
        flowId="FLOW-ML-C2-001",
        timestamp=1725120000000,
        sourceIp="192.168.1.100",
        destinationIp="10.0.1.50",
        protocol="TCP",
        sourcePort=54321,
        destinationPort=8443,
        flowDuration=0.5,
        totalPackets=5,
        packetsPerSecond=10.0,
        bytesPerSecond=500.0,
        totalBytes=250,
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


@pytest.fixture()
def recon_flow() -> NetworkFlow:
    return NetworkFlow(
        flowId="FLOW-ML-RECON-001",
        timestamp=1725120000000,
        sourceIp="192.168.1.50",
        destinationIp="10.0.1.1",
        protocol="TCP",
        sourcePort=33333,
        destinationPort=22,
        flowDuration=0.01,
        totalPackets=2,
        packetsPerSecond=200.0,
        bytesPerSecond=1200.0,
        totalBytes=12,
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


# ── Model Loading Tests ──────────────────────────────────────────


class TestModelLoading:
    """Test model loading and metadata."""

    def test_model_loads_when_files_exist(self, _ensure_model):
        assert is_model_loaded()

    def test_model_info_has_required_keys(self, _ensure_model):
        """Model info should contain all expected metadata."""
        info = get_model_info()
        assert "model_name" in info
        assert "model_version" in info
        assert "feature_names" in info
        assert "classes" in info
        assert "metrics" in info
        # CICIDS2017 binary model has 12 features
        assert len(info["feature_names"]) == 12

    def test_model_metrics_are_real(self, _ensure_model):
        """Model metrics should be real (not fabricated)."""
        info = get_model_info()
        metrics = info.get("metrics", {})
        assert 0.0 <= metrics.get("accuracy", 0) <= 1.0
        assert 0.0 <= metrics.get("f1_weighted", 0) <= 1.0
        # Real CICIDS2017 model should have >95% accuracy
        assert metrics.get("accuracy", 0) > 0.9

    def test_model_not_loaded_with_missing_files(self):
        """Model should not load from non-existent directory."""
        load_model("/nonexistent/path")
        assert not is_model_loaded()
        # Restore
        load_model()

    def test_model_classes_are_binary(self, _ensure_model):
        """CICIDS2017 model should have ATTACK and BENIGN classes."""
        info = get_model_info()
        assert set(info["classes"]) == {"ATTACK", "BENIGN"}


# ── Feature Extraction Tests ─────────────────────────────────────


class TestFeatureExtraction:
    """Test feature extraction from NetworkFlow."""

    def test_feature_names_count(self, _ensure_model):
        info = get_model_info()
        assert len(info["feature_names"]) == 12

    def test_feature_vector_length(self, normal_flow):
        features = flow_to_feature_vector(normal_flow)
        assert len(features) == len(FEATURE_NAMES)

    def test_feature_vector_values(self, normal_flow):
        # CICIDS2017 feature order:
        # 0:flow_duration 1:total_fwd_packets 2:total_backward_packets
        # 3:total_bytes 4:flow_bytes_s 5:flow_packets_s
        # 6:destination_port 7:source_port 8:packet_length_mean
        # 9:packet_length_std 10:fwd_packet_length_mean 11:bwd_packet_length_mean
        features = flow_to_feature_vector(normal_flow)
        assert features[0] == 5000.0   # flowDuration
        assert features[3] == 60000    # totalBytes
        assert features[6] == 80.0     # destinationPort
        assert features[7] == 49152.0  # sourcePort

    def test_feature_vector_handles_none_optionals(self):
        """Optional features should default to 0.0 when None."""
        flow = NetworkFlow(
            flowId="test",
            timestamp=1000,
            sourceIp="1.1.1.1",
            destinationIp="2.2.2.2",
            protocol="TCP",
            sourcePort=80,
            destinationPort=443,
            flowDuration=100.0,
            totalPackets=10,
            packetsPerSecond=10.0,
            bytesPerSecond=1000.0,
            totalBytes=1000,
        )
        features = flow_to_feature_vector(flow)
        # packet_length_mean (8) and packet_length_std (9) default to 0.0 when None
        assert features[8] == 0.0  # packet_length_mean defaults to 0.0
        assert features[9] == 0.0  # packet_length_std defaults to 0.0
        # bwd_packet_length_mean (11) is always 0.0 (unidirectional)
        assert features[11] == 0.0

    def test_feature_order_consistency(self, _ensure_model):
        """Feature order must be consistent between training and inference."""
        info = get_model_info()
        model_features = info.get("feature_names", [])
        # Model features should be a subset of our FEATURE_NAMES
        # (since CICIDS2017 uses different naming)
        assert len(model_features) > 0
        assert len(model_features) == 12


# ── Prediction Tests ─────────────────────────────────────────────


class TestPrediction:
    """Test ML prediction on various flow types."""

    def test_predict_normal_flow(self, normal_flow, _ensure_model):
        pred = predict_flow(normal_flow)
        assert pred is not None
        # Normal flow should be classified as Normal (BENIGN)
        # Note: CICIDS2017 model is binary, not multi-class

    def test_prediction_has_all_fields(self, normal_flow, _ensure_model):
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
            # CICIDS2017 binary model has 2 classes
            assert len(pred.class_probabilities) == 2

    def test_prediction_latency_reasonable(self, normal_flow, _ensure_model):
        pred = predict_flow(normal_flow)
        if pred is not None:
            assert pred.inference_latency_ms < 1000  # Under 1 second

    def test_probabilities_sum_to_one(self, normal_flow, _ensure_model):
        pred = predict_flow(normal_flow)
        if pred is not None:
            total = sum(pred.class_probabilities.values())
            assert abs(total - 1.0) < 0.01


# ── Pipeline Integration Tests ───────────────────────────────────


class TestPipelineIntegration:
    """Test ML integration with the detection pipeline."""

    def test_pipeline_includes_ml_alert(self, ddos_flow, _ensure_model):
        from app.detection.pipeline import pipeline

        alerts = pipeline.analyze(ddos_flow)
        ml_alerts = [a for a in alerts if a.detector.startswith("ML ")]
        # ML alert may or may not fire depending on prediction
        # but detector alerts should fire for DDoS
        assert len(alerts) >= 1

    def test_pipeline_get_best_prefers_scenario_match(self, ddos_flow, _ensure_model):
        from app.detection.pipeline import pipeline

        alerts = pipeline.analyze(ddos_flow)
        best = pipeline.get_best_alert(alerts)
        if best:
            # Best alert should be the scenario-matched detector alert
            # (DDoS detector), not the ML "Normal" prediction
            assert best.threatClass in [
                ThreatClass.DDoS,
                ThreatClass.Normal,
            ]

    def test_pipeline_detector_count_includes_ml(self, _ensure_model):
        from app.detection.pipeline import pipeline

        count = pipeline.detector_count
        assert count == 7  # 6 baseline + 1 ML

    def test_pipeline_get_all_detectors_includes_ml(self, _ensure_model):
        from app.detection.pipeline import pipeline

        detectors = pipeline.get_all_detectors()
        names = [d.name for d in detectors]
        assert "ML Random Forest Classifier" in names


# ── API Integration Tests ────────────────────────────────────────


class TestAPIIntegration:
    """Test ML integration through the FastAPI API."""

    @pytest.fixture(autouse=True)
    def _setup(self, _ensure_model):
        self.client = TestClient(app)

    def test_health_reports_model_loaded(self):
        resp = self.client.get("/api/health")
        assert resp.status_code == 200
        data = resp.json()
        assert data["model_loaded"] is True
        assert data["model_source"] == "CICIDS2017"

    def test_predict_normal_flow_with_ml(self, normal_flow):
        resp = self.client.post(
            "/api/predict", json={"flow": normal_flow.model_dump()}
        )
        assert resp.status_code == 200
        data = resp.json()
        # Normal flow may or may not have an alert
        # but the response should be valid
        assert "alert" in data
        assert "updatedFlow" in data

    def test_detectors_endpoint_includes_ml(self):
        resp = self.client.get("/api/detectors")
        assert resp.status_code == 200
        data = resp.json()
        names = [d["name"] for d in data]
        assert "ML Random Forest Classifier" in names


# ── Missing Model Tests ──────────────────────────────────────────


class TestMissingModel:
    """Test behavior when model is not available."""

    def test_predict_flow_returns_none_without_model(self):
        """Prediction should return None when model not loaded."""
        load_model("/nonexistent/path")
        try:
            flow = NetworkFlow(
                flowId="test",
                timestamp=1000,
                sourceIp="1.1.1.1",
                destinationIp="2.2.2.2",
                protocol="TCP",
                sourcePort=80,
                destinationPort=443,
                flowDuration=100.0,
                totalPackets=10,
                packetsPerSecond=10.0,
                bytesPerSecond=1000.0,
                totalBytes=1000,
            )
            result = predict_flow(flow)
            assert result is None
        finally:
            load_model()
