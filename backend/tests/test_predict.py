"""Tests for the prediction endpoint."""

import pytest


def test_predict_returns_flow(client, sample_flow):
    """POST /api/predict should return the flow and no alert (no model loaded)."""
    payload = {"flow": sample_flow}
    resp = client.post("/api/predict", json=payload)
    assert resp.status_code == 200
    data = resp.json()
    assert data["updatedFlow"]["flowId"] == sample_flow["flowId"]
    assert data["alert"] is None
    assert "detectionTimeMs" in data


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
