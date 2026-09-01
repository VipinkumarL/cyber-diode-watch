"""Tests for flow ingestion and retrieval endpoints."""

import pytest


def test_ingest_flow(client, sample_flow):
    """POST /api/flows should accept and store a flow."""
    resp = client.post("/api/flows", json=sample_flow)
    assert resp.status_code == 200
    data = resp.json()
    assert data["flowId"] == "FLOW-0000001"
    assert data["sourceIp"] == "192.168.1.100"


def test_list_flows_empty(client):
    """GET /api/flows with no data should return empty list."""
    resp = client.get("/api/flows")
    assert resp.status_code == 200
    data = resp.json()
    assert data["flows"] == []
    assert data["stats"]["totalFlows"] == 0


def test_list_flows_after_insert(client, sample_flow):
    """GET /api/flows should return inserted flows."""
    client.post("/api/flows", json=sample_flow)
    resp = client.get("/api/flows?limit=10")
    assert resp.status_code == 200
    data = resp.json()
    assert len(data["flows"]) == 1
    assert data["stats"]["totalFlows"] == 1


def test_list_flows_respects_limit(client, sample_flow):
    """GET /api/flows limit param should cap the number of returned flows."""
    for i in range(5):
        flow = {**sample_flow, "flowId": f"FLOW-{i+1:07d}"}
        client.post("/api/flows", json=flow)
    resp = client.get("/api/flows?limit=2")
    assert resp.status_code == 200
    data = resp.json()
    assert len(data["flows"]) == 2
    assert data["stats"]["totalFlows"] == 5


def test_ingest_flow_validation(client):
    """POST /api/flows should reject invalid payloads."""
    resp = client.post("/api/flows", json={"flowId": "BAD"})
    assert resp.status_code == 422


def test_flows_stats_compute_correctly(client):
    """Flow stats should reflect inserted data."""
    # Use a clearly normal flow that won't trigger any detector
    normal = {
        "flowId": "N-1",
        "timestamp": 1725120000000,
        "sourceIp": "10.0.0.1",
        "destinationIp": "10.0.1.1",
        "protocol": "TCP",
        "sourcePort": 54321,
        "destinationPort": 8888,  # Non-suspicious port
        "flowDuration": 10.0,
        "totalPackets": 500,
        "packetsPerSecond": 50.0,
        "bytesPerSecond": 50000.0,
        "totalBytes": 500000,
        "classification": "Normal",
        "confidence": 0.0,
        "severity": "INFO",
        "sourceEntropy": 2.0,
        "destinationConcentration": 0.8,  # Concentrated (not scan)
        "isSuspicious": False,
    }
    # Use a clearly DDoS flow
    threat = {
        "flowId": "T-1",
        "timestamp": 1725120000000,
        "sourceIp": "10.0.0.2",
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
    client.post("/api/flows", json=normal)
    client.post("/api/flows", json=threat)
    resp = client.get("/api/flows")
    stats = resp.json()["stats"]
    assert stats["totalFlows"] == 2
    assert stats["threatsDetected"] >= 1  # DDoS flow should be detected
