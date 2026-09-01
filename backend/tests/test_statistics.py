"""Tests for statistics and incident endpoints."""

import pytest


def test_statistics_empty(client):
    """GET /api/statistics should return zeroed stats when empty."""
    resp = client.get("/api/statistics")
    assert resp.status_code == 200
    data = resp.json()
    assert data["flows"]["totalFlows"] == 0
    assert data["alerts"]["total"] == 0
    assert data["incidents"]["total"] == 0


def test_metrics(client):
    """GET /api/metrics should return a SystemMetrics snapshot."""
    resp = client.get("/api/metrics")
    assert resp.status_code == 200
    data = resp.json()
    assert "timestamp" in data
    assert "totalFlows" in data
    assert "riskScore" in data


def test_incidents_empty(client):
    """GET /api/incidents should return empty list initially."""
    resp = client.get("/api/incidents")
    assert resp.status_code == 200
    data = resp.json()
    assert data["incidents"] == []
    assert data["stats"]["total"] == 0


def test_incident_by_id_404(client):
    """GET /api/incidents/{id} for nonexistent incident should 404."""
    resp = client.get("/api/incidents/INC-nonexistent")
    assert resp.status_code == 404


def test_incident_by_id(client):
    """GET /api/incidents/{id} should return the incident."""
    from app.services.store import insert_incident
    from app.models.schemas import Incident, ThreatClass, Severity

    inc = Incident(
        incidentId="INC-TEST-001",
        timestamp=1725120000000,
        title="DDoS Attack",
        description="Test incident",
        threatClass=ThreatClass.DDoS,
        severity=Severity.CRITICAL,
        confidence=0.95,
        detector="DDoS-RF-v1",
        detectionLatencyMs=84,
        evidence={"packets_per_second": 18420},
        status="open",
    )
    insert_incident(inc)

    resp = client.get("/api/incidents/INC-TEST-001")
    assert resp.status_code == 200
    data = resp.json()
    assert data["incidentId"] == "INC-TEST-001"
    assert data["title"] == "DDoS Attack"
