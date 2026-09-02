"""Tests for the prediction endpoint."""

import pytest

from demo_predict import demo_flows


def test_predict_returns_flow(client, sample_flow):
    """POST /api/predict should return the flow."""
    payload = {"flow": sample_flow}
    resp = client.post("/api/predict", json=payload)
    assert resp.status_code == 200
    data = resp.json()
    assert data["updatedFlow"]["flowId"] == sample_flow["flowId"]
    assert "detectionTimeMs" in data
    # sample_flow may trigger non-DDoS detectors (C2 on port 443)
    # but the response structure is always valid


def test_predict_stores_flow(client, sample_flow):
    """POST /api/predict should store the flow in the data store."""
    payload = {"flow": sample_flow}
    client.post("/api/predict", json=payload)

    resp = client.get("/api/flows")
    data = resp.json()
    assert data["stats"]["totalFlows"] == 1


def test_predict_validation(client):
    """POST /api/predict should reject invalid payloads."""
    resp = client.post("/api/predict", json={"flow": {"bad": True}})
    assert resp.status_code == 422


def test_predict_empty_body(client):
    """POST /api/predict with no body should return 422."""
    resp = client.post("/api/predict")
    assert resp.status_code == 422


def test_predict_ddos_flow_has_alert(client):
    """POST /api/predict with a clear DDoS flow should return an alert."""
    ddos_flow = {
        "flowId": "FLOW-PRED-DDOS",
        "timestamp": 1725120000000,
        "sourceIp": "10.0.0.1",
        "destinationIp": "10.0.1.1",
        "protocol": "UDP",
        "sourcePort": 1234,
        "destinationPort": 80,
        "flowDuration": 0.3,
        "totalPackets": 50000,
        "packetsPerSecond": 15000.0,
        "bytesPerSecond": 7500000.0,
        "totalBytes": 2250000,
        "classification": "Normal",
        "confidence": 0.0,
        "severity": "INFO",
        "sourceEntropy": 7.5,
        "destinationConcentration": 0.95,
        "isSuspicious": False,
        "scenario": "ddos",
    }
    resp = client.post("/api/predict", json={"flow": ddos_flow})
    assert resp.status_code == 200
    data = resp.json()
    assert data["alert"] is not None
    assert data["alert"]["threatClass"] == "DDoS"


@pytest.mark.parametrize(
    "scenario",
    [
        "normal",
        "ddos",
        "recon",
        "c2",
        "dns",
        "encrypted_malware",
        "exfil",
    ],
)
def test_predict_demo_scenarios_return_valid_alert(client, scenario):
    """Safe synthetic demo metadata should exercise the full predict contract."""
    flow = demo_flows()[scenario]
    resp = client.post("/api/predict", json={"flow": flow})
    assert resp.status_code == 200

    data = resp.json()
    assert data["alert"] is not None
    assert isinstance(data["updatedFlow"], dict)
    assert isinstance(data["detectionTimeMs"], int)

    alert = data["alert"]
    for field in (
        "threatClass",
        "confidence",
        "severity",
        "detector",
        "supportingEvidence",
    ):
        assert field in alert

    assert alert["supportingEvidence"]
    assert data["updatedFlow"]["flowId"] == flow["flowId"]
