"""Shared test fixtures for the backend test suite."""

import sys
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

# Add backend/ to path so imports work
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from app.ml.model import load_model
from main import app


@pytest.fixture(scope="session", autouse=True)
def load_ml_model():
    """Load the ML model once for all tests."""
    # Load from default location (backend/ml_models/)
    success = load_model()
    yield success


@pytest.fixture(scope="session")
def client(load_ml_model):
    """Create a test client for the FastAPI app."""
    return TestClient(app, raise_server_exceptions=False)


@pytest.fixture(autouse=True)
def _clear_store():
    """Clear the in-memory store before each test to prevent cross-test leakage."""
    from app.services import store
    store.clear_all()
    yield
    store.clear_all()


@pytest.fixture
def normal_flow():
    """A clearly normal network flow."""
    return {
        "flowId": "flow-normal-001",
        "timestamp": 1700000000000,
        "sourceIp": "192.168.1.100",
        "destinationIp": "93.184.216.34",
        "protocol": "TCP",
        "sourcePort": 54321,
        "destinationPort": 80,
        "flowDuration": 5.0,
        "totalPackets": 50,
        "packetsPerSecond": 10.0,
        "bytesPerSecond": 50000.0,
        "totalBytes": 250000,
        "classification": "Normal",
        "confidence": 0.0,
        "severity": "INFO",
        "sourceEntropy": 2.0,
        "destinationConcentration": 0.1,
        "packetLengthMean": 500.0,
        "packetLengthStd": 200.0,
        "isSuspicious": False,
    }


@pytest.fixture
def ddos_flow():
    """A clearly suspicious DDoS flow."""
    return {
        "flowId": "flow-ddos-001",
        "timestamp": 1700000001000,
        "sourceIp": "10.0.0.1",
        "destinationIp": "192.168.1.1",
        "protocol": "UDP",
        "sourcePort": 12345,
        "destinationPort": 53,
        "flowDuration": 0.1,
        "totalPackets": 500000,
        "packetsPerSecond": 5000000.0,
        "bytesPerSecond": 500000000.0,
        "totalBytes": 50000000,
        "classification": "Normal",
        "confidence": 0.0,
        "severity": "INFO",
        "sourceEntropy": 7.0,
        "destinationConcentration": 0.95,
        "packetLengthMean": 100.0,
        "packetLengthStd": 30.0,
        "isSuspicious": False,
        "scenario": "ddos",
    }


@pytest.fixture
def normal_flow_dict(normal_flow):
    """Normal flow as a plain dict (for direct JSON requests)."""
    return normal_flow


@pytest.fixture
def ddos_flow_dict(ddos_flow):
    """DDoS flow as a plain dict."""
    return ddos_flow


# ── Legacy fixtures (used by existing tests) ────────────────────

@pytest.fixture
def sample_flow():
    """A minimal flow dict for API tests (normal flow on port 80)."""
    return {
        "flowId": "FLOW-0000001",
        "timestamp": 1700000000000,
        "sourceIp": "192.168.1.100",
        "destinationIp": "93.184.216.34",
        "protocol": "TCP",
        "sourcePort": 54321,
        "destinationPort": 80,
        "flowDuration": 5.0,
        "totalPackets": 50,
        "packetsPerSecond": 10.0,
        "bytesPerSecond": 50000.0,
        "totalBytes": 250000,
        "classification": "Normal",
        "confidence": 0.0,
        "severity": "INFO",
        "sourceEntropy": 2.0,
        "destinationConcentration": 0.1,
        "packetLengthMean": 500.0,
        "packetLengthStd": 200.0,
        "isSuspicious": False,
    }


@pytest.fixture
def sample_alert():
    """A minimal alert dict for API tests."""
    return {
        "alertId": "ALT-TEST-001",
        "timestamp": 1700000001000,
        "flowId": "FLOW-0000001",
        "threatClass": "DDoS",
        "confidence": 0.95,
        "severity": "CRITICAL",
        "sourceIp": "10.0.0.1",
        "destinationIp": "192.168.1.1",
        "protocol": "UDP",
        "destinationPort": 53,
        "detector": "DDoS Baseline Detector",
        "detectionLatencyMs": 5,
        "supportingEvidence": {},
        "description": "Test alert",
        "status": "new",
    }
