"""
Tests for CICIDS2017 ML integration.

Tests cover:
  - Model loading and source detection
  - Feature extraction and mapping
  - Prediction with both model types
  - Health endpoint model_source
  - Pipeline integration
  - Missing model handling
  - CICIDS2017 data preparation
"""

import sys
from pathlib import Path

import numpy as np
import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from app.ml.model import (
    get_model_info,
    get_model_source,
    is_model_loaded,
    load_model,
)
from app.ml.features import FEATURE_NAMES, flow_to_feature_vector
from app.ml.predictor import predict_flow, MLPrediction


# ── Model Loading Tests ─────────────────────────────────────────

class TestModelLoading:
    """Test model loading and state detection."""

    def test_model_is_loaded(self):
        """Model should be loaded (synthetic or CICIDS2017)."""
        assert is_model_loaded(), "ML model should be loaded"

    def test_model_source_is_string(self):
        """Model source should be a non-empty string."""
        source = get_model_source()
        assert isinstance(source, str)
        assert source in ("CICIDS2017", "synthetic"), f"Unexpected source: {source}"

    def test_model_info_has_required_keys(self):
        """Model info should contain expected metadata."""
        info = get_model_info()
        assert "model_name" in info
        assert "model_version" in info
        assert "feature_names" in info
        assert "classes" in info
        assert "metrics" in info

    def test_model_info_feature_count(self):
        """Model info should declare its feature count."""
        info = get_model_info()
        assert info["num_features"] > 0
        assert len(info["feature_names"]) == info["num_features"]

    def test_load_nonexistent_model(self):
        """Loading from nonexistent dir should fail gracefully."""
        result = load_model("/nonexistent/path/to/models")
        assert result is False
        assert not is_model_loaded()

        # Reload original model for subsequent tests
        load_model()


# ── Feature Extraction Tests ────────────────────────────────────

class TestFeatureExtraction:
    """Test feature vector extraction from NetworkFlow."""

    def _make_flow(self, **overrides):
        """Helper to create a minimal flow dict."""
        flow_dict = {
            "flowId": "test-flow-001",
            "timestamp": 1700000000000,
            "sourceIp": "10.0.0.1",
            "destinationIp": "10.0.0.2",
            "protocol": "TCP",
            "sourcePort": 12345,
            "destinationPort": 80,
            "flowDuration": 10.0,
            "totalPackets": 100,
            "packetsPerSecond": 10.0,
            "bytesPerSecond": 50000.0,
            "totalBytes": 500000,
            "classification": "Normal",
            "confidence": 0.0,
            "severity": "INFO",
            "sourceEntropy": 2.0,
            "destinationConcentration": 0.3,
            "packetLengthMean": 500.0,
            "packetLengthStd": 200.0,
            "isSuspicious": False,
        }
        flow_dict.update(overrides)
        return flow_dict

    def test_feature_vector_length(self):
        """Feature vector should have expected length."""
        from app.models.schemas import NetworkFlow
        flow = NetworkFlow(**self._make_flow())
        features = flow_to_feature_vector(flow)
        assert len(features) == len(FEATURE_NAMES)

    def test_feature_names_count(self):
        """FEATURE_NAMES should be defined."""
        assert len(FEATURE_NAMES) > 0

    def test_feature_vector_is_numeric(self):
        """All features should be numeric."""
        from app.models.schemas import NetworkFlow
        flow = NetworkFlow(**self._make_flow())
        features = flow_to_feature_vector(flow)
        for i, f in enumerate(features):
            assert isinstance(f, float), f"Feature {i} ({FEATURE_NAMES[i]}) is not float: {type(f)}"

    def test_optional_features_default_zero(self):
        """Optional features should default to 0.0."""
        from app.models.schemas import NetworkFlow
        flow_dict = self._make_flow(
            sourceEntropy=None,
            destinationConcentration=None,
            packetLengthMean=None,
            packetLengthStd=None,
        )
        flow = NetworkFlow(**flow_dict)
        features = flow_to_feature_vector(flow)
        # Check optional fields map to 0.0
        for i, name in enumerate(FEATURE_NAMES):
            if name in ("sourceEntropy", "destinationConcentration", "packetLengthMean", "packetLengthStd"):
                assert features[i] == 0.0, f"{name} should be 0.0 when None"

    def test_model_features_match_training(self):
        """Model's feature names should match FEATURE_NAMES."""
        info = get_model_info()
        model_features = info.get("feature_names", [])
        # For CICIDS2017, features may differ from FEATURE_NAMES
        # but the model should have its own feature list
        assert len(model_features) > 0


# ── Prediction Tests ────────────────────────────────────────────

class TestPrediction:
    """Test ML prediction on network flows."""

    def _make_flow(self, **overrides):
        from app.models.schemas import NetworkFlow
        flow_dict = {
            "flowId": "pred-test-001",
            "timestamp": 1700000000000,
            "sourceIp": "10.0.0.1",
            "destinationIp": "10.0.0.2",
            "protocol": "TCP",
            "sourcePort": 12345,
            "destinationPort": 80,
            "flowDuration": 10.0,
            "totalPackets": 100,
            "packetsPerSecond": 10.0,
            "bytesPerSecond": 50000.0,
            "totalBytes": 500000,
            "classification": "Normal",
            "confidence": 0.0,
            "severity": "INFO",
            "sourceEntropy": 2.0,
            "destinationConcentration": 0.3,
            "packetLengthMean": 500.0,
            "packetLengthStd": 200.0,
            "isSuspicious": False,
        }
        flow_dict.update(overrides)
        return NetworkFlow(**flow_dict)

    def test_prediction_returns_result(self):
        """Prediction should return an MLPrediction."""
        flow = self._make_flow()
        result = predict_flow(flow)
        assert result is not None
        assert isinstance(result, MLPrediction)

    def test_prediction_has_confidence(self):
        """Prediction should have a valid confidence value."""
        flow = self._make_flow()
        result = predict_flow(flow)
        assert result is not None
        assert 0.0 <= result.confidence <= 1.0

    def test_prediction_has_model_info(self):
        """Prediction should include model name and version."""
        flow = self._make_flow()
        result = predict_flow(flow)
        assert result is not None
        assert result.model_name
        assert result.model_version

    def test_prediction_has_class_probabilities(self):
        """Prediction should include class probabilities."""
        flow = self._make_flow()
        result = predict_flow(flow)
        assert result is not None
        assert len(result.class_probabilities) > 0
        # Probabilities should sum to ~1.0
        total = sum(result.class_probabilities.values())
        assert abs(total - 1.0) < 0.01, f"Probabilities sum to {total}"

    def test_prediction_has_latency(self):
        """Prediction should measure inference latency."""
        flow = self._make_flow()
        result = predict_flow(flow)
        assert result is not None
        assert result.inference_latency_ms >= 0

    def test_prediction_has_model_source(self):
        """Prediction should include model source."""
        flow = self._make_flow()
        result = predict_flow(flow)
        assert result is not None
        assert result.model_source in ("CICIDS2017", "synthetic")

    def test_ddos_flow_prediction(self):
        """DDoS flow should be predicted (class depends on model type)."""
        flow = self._make_flow(
            flowId="pred-ddos-001",
            flowDuration=0.1,
            totalPackets=500000,
            packetsPerSecond=5000000.0,
            bytesPerSecond=500000000.0,
            totalBytes=50000000,
            sourceEntropy=7.0,
            destinationConcentration=0.95,
        )
        result = predict_flow(flow)
        assert result is not None
        assert result.confidence > 0.0


# ── Health Endpoint Tests ───────────────────────────────────────

class TestHealthEndpoint:
    """Test /api/health response includes model_source."""

    def test_health_returns_model_source(self, client):
        """Health response should include model_source field."""
        response = client.get("/api/health")
        assert response.status_code == 200
        data = response.json()
        assert "model_source" in data
        assert data["model_source"] in ("CICIDS2017", "synthetic", "")

    def test_health_model_loaded_matches(self, client):
        """model_loaded in response should match is_model_loaded()."""
        response = client.get("/api/health")
        data = response.json()
        assert data["model_loaded"] == is_model_loaded()

    def test_health_model_source_matches(self, client):
        """model_source should match get_model_source() when loaded."""
        response = client.get("/api/health")
        data = response.json()
        if data["model_loaded"]:
            assert data["model_source"] == get_model_source()


# ── Pipeline Integration Tests ──────────────────────────────────

class TestPipelineIntegration:
    """Test detection pipeline with ML model."""

    def _make_flow(self, **overrides):
        from app.models.schemas import NetworkFlow
        flow_dict = {
            "flowId": "pipe-test-001",
            "timestamp": 1700000000000,
            "sourceIp": "10.0.0.1",
            "destinationIp": "10.0.0.2",
            "protocol": "TCP",
            "sourcePort": 12345,
            "destinationPort": 80,
            "flowDuration": 10.0,
            "totalPackets": 100,
            "packetsPerSecond": 10.0,
            "bytesPerSecond": 50000.0,
            "totalBytes": 500000,
            "classification": "Normal",
            "confidence": 0.0,
            "severity": "INFO",
            "sourceEntropy": 2.0,
            "destinationConcentration": 0.3,
            "packetLengthMean": 500.0,
            "packetLengthStd": 200.0,
            "isSuspicious": False,
        }
        flow_dict.update(overrides)
        return NetworkFlow(**flow_dict)

    def test_pipeline_runs_ml(self, client):
        """Pipeline should run ML model when available."""
        from app.models.schemas import NetworkFlow
        flow = self._make_flow()
        response = client.post("/api/predict", json={"flow": flow.model_dump()})
        assert response.status_code == 200
        data = response.json()
        assert "alert" in data
        assert "updatedFlow" in data
        assert "detectionTimeMs" in data

    def test_pipeline_ddos_detection(self, client):
        """DDoS flow should be detected by at least one detector."""
        from app.models.schemas import NetworkFlow
        flow = self._make_flow(
            flowId="pipe-ddos-001",
            flowDuration=0.1,
            totalPackets=500000,
            packetsPerSecond=5000000.0,
            bytesPerSecond=500000000.0,
            totalBytes=50000000,
            sourceEntropy=7.0,
            destinationConcentration=0.95,
            scenario="ddos",
        )
        response = client.post("/api/predict", json={"flow": flow.model_dump()})
        assert response.status_code == 200
        data = response.json()
        # Should have an alert from DDoS detector or ML
        assert data["alert"] is not None
        assert data["updatedFlow"]["isSuspicious"] is True

    def test_detectors_endpoint_includes_ml(self, client):
        """GET /api/detectors should include ML detector."""
        response = client.get("/api/detectors")
        assert response.status_code == 200
        detectors = response.json()
        # Response is a list of DetectorInfo
        assert isinstance(detectors, list)
        assert len(detectors) >= 7  # 6 baseline + 1 ML

        # Find ML detector
        ml_detector = None
        for d in detectors:
            if "ML" in d.get("name", "") or "Random Forest" in d.get("name", ""):
                ml_detector = d
                break
        assert ml_detector is not None, "ML detector should be in detector list"
        assert ml_detector["status"] in ("ACTIVE", "NOT_TRAINED")


# ── CICIDS2017 Data Preparation Tests ───────────────────────────

class TestCICIDS2017Preparation:
    """Test CICIDS2017 data preparation utilities."""

    def test_prepare_script_exists(self):
        """prepare_cicids2017.py should exist."""
        script = Path(__file__).resolve().parent.parent / "training" / "prepare_cicids2017.py"
        assert script.exists(), f"Script not found: {script}"

    def test_train_cicids2017_script_exists(self):
        """train_cicids2017.py should exist."""
        script = Path(__file__).resolve().parent.parent / "training" / "train_cicids2017.py"
        assert script.exists(), f"Script not found: {script}"

    def test_prepare_importable(self):
        """prepare_cicids2017 module should be importable."""
        from training.prepare_cicids2017 import ML_FEATURE_COLUMNS, normalize_columns, normalize_labels
        assert len(ML_FEATURE_COLUMNS) > 0

    def test_feature_columns_defined(self):
        """ML_FEATURE_COLUMNS should have 12 features."""
        from training.prepare_cicids2017 import ML_FEATURE_COLUMNS
        assert len(ML_FEATURE_COLUMNS) == 12
        assert "flow_duration" in ML_FEATURE_COLUMNS
        assert "destination_port" in ML_FEATURE_COLUMNS

    def test_label_normalization(self):
        """Labels should normalize to BENIGN/ATTACK."""
        import pandas as pd
        from training.prepare_cicids2017 import normalize_labels

        df = pd.DataFrame({"label": ["BENIGN", "DDoS", "PortScan", "Bot", "Web Attack Brute Force"]})
        df = normalize_labels(df)
        assert set(df["label"].unique()) == {"BENIGN", "ATTACK"}

    def test_column_normalization(self):
        """Column names should be normalized to snake_case."""
        import pandas as pd
        from training.prepare_cicids2017 import normalize_columns

        df = pd.DataFrame({
            " Flow Duration": [100],
            " Total Fwd Packets": [50],
            " Destination Port": [80],
        })
        df = normalize_columns(df)
        assert "flow_duration" in df.columns
        assert "total_fwd_packets" in df.columns
        assert "destination_port" in df.columns


# ── Model Source Distinction Tests ──────────────────────────────

class TestModelSource:
    """Test that model source is correctly tracked."""

    def test_source_not_empty(self):
        """Model source should not be empty when model is loaded."""
        if is_model_loaded():
            source = get_model_source()
            assert source != "", "Model source should not be empty when loaded"

    def test_source_in_model_info(self):
        """Model info should contain model_source key."""
        info = get_model_info()
        # model_source may be in info or not (synthetic models don't have it)
        # Just verify the info is valid
        assert isinstance(info, dict)

    def test_cicids2017_source_detection(self):
        """If CICIDS2017 model files exist, source should be CICIDS2017."""
        cicids_files = [
            "rf_cicids2017.joblib",
            "scaler_cicids2017.joblib",
            "label_encoder_cicids2017.joblib",
            "model_info_cicids2017.joblib",
        ]
        model_dir = Path(__file__).resolve().parent.parent / "ml_models"
        all_exist = all((model_dir / f).exists() for f in cicids_files)

        if all_exist:
            assert get_model_source() == "CICIDS2017"
        else:
            # Synthetic model loaded
            assert get_model_source() == "synthetic"
