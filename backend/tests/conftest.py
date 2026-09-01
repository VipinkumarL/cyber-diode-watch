"""Shared test fixtures for SIH26145 backend tests."""

import pytest
from fastapi.testclient import TestClient

from main import app
from app.services import store
from app.ml.model import load_model


@pytest.fixture(autouse=True)
def clear_store():
    """Clear all data stores before each test."""
    store.clear_all()
    store.reset_counters()
    yield
    store.clear_all()
    store.reset_counters()


@pytest.fixture(autouse=True, scope="session")
def load_ml_model():
    """Load the ML model once for all tests."""
    load_model()
    yield


@pytest.fixture
def client():
    """Provide a FastAPI TestClient."""
    return TestClient(app)


@pytest.fixture
def sample_flow():
    """Provide a minimal valid NetworkFlow dict."""
    return {
        "flowId": "FLOW-0000001",
        "timestamp": 1725120000000,
        "sourceIp": "192.168.1.100",
        "destinationIp": "10.0.1.1",
        "protocol": "TCP",
        "sourcePort": 54321,
        "destinationPort": 443,
        "flowDuration": 1.5,
        "totalPackets": 200,
        "packetsPerSecond": 133.3,
        "bytesPerSecond": 150000.0,
        "totalBytes": 225000,
        "classification": "Normal",
        "confidence": 0.0,
        "severity": "INFO",
        "isSuspicious": False,
        "scenario": "normal",
    }


@pytest.fixture
def sample_alert():
    """Provide a minimal valid Alert dict."""
    return {
        "alertId": "ALT-1725120000000-0001",
        "timestamp": 1725120000000,
        "flowId": "FLOW-0000001",
        "threatClass": "DDoS",
        "confidence": 0.95,
        "severity": "CRITICAL",
        "sourceIp": "192.168.1.100",
        "destinationIp": "10.0.1.1",
        "protocol": "UDP",
        "destinationPort": 80,
        "detector": "DDoS-RF-v1",
        "detectionLatencyMs": 84,
        "supportingEvidence": {"packets_per_second": 18420},
        "description": "DDoS attack detected: 18420 packets/sec",
        "status": "new",
    }
