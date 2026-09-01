"""Tests for the health endpoint."""

import pytest


def test_health_returns_ok(client):
    """GET /api/health should return status ok."""
    resp = client.get("/api/health")
    assert resp.status_code == 200
    data = resp.json()
    assert data["status"] == "ok"
    assert "model_loaded" in data
    assert "db_status" in data


def test_root_returns_service_info(client):
    """GET / should return service metadata."""
    resp = client.get("/")
    assert resp.status_code == 200
    data = resp.json()
    assert data["service"] == "SIH26145 Cyber-Diode-Watch"
    assert data["status"] == "passive_monitoring_active"
