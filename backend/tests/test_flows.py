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
    assert resp.status_code == 422  # Pydantic validation error


def test_flows_stats_compute_correctly(client, sample_flow):
    """Flow stats should reflect inserted data."""
    normal = {**sample_flow, "flowId": "N-1", "classification": "Normal", "isSuspicious": False}
    threat = {
        **sample_flow,
        "flowId": "T-1",
        "classification": "DDoS",
        "isSuspicious": True,
        "confidence": 0.95,
    }
    client.post("/api/flows", json=normal)
    client.post("/api/flows", json=threat)
    resp = client.get("/api/flows")
    stats = resp.json()["stats"]
    assert stats["totalFlows"] == 2
    assert stats["normalFlows"] == 1
    assert stats["threatsDetected"] == 1
