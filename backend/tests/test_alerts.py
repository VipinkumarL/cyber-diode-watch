"""Tests for alert retrieval endpoints."""

import pytest


def test_list_alerts_empty(client):
    """GET /api/alerts with no data should return empty list."""
    resp = client.get("/api/alerts")
    assert resp.status_code == 200
    data = resp.json()
    assert data["alerts"] == []
    assert data["stats"]["total"] == 0


def test_alert_by_id_returns_404(client):
    """GET /api/alerts/{id} for nonexistent alert should 404."""
    resp = client.get("/api/alerts/ALT-nonexistent")
    assert resp.status_code == 404


def test_alert_by_id(client, sample_alert):
    """GET /api/alerts/{id} should return the alert."""
    # Insert via store since there is no POST /api/alerts endpoint yet
    from app.services.store import insert_alert
    from app.models.schemas import Alert, ThreatClass, Severity

    insert_alert(Alert(**sample_alert))
    resp = client.get(f"/api/alerts/{sample_alert['alertId']}")
    assert resp.status_code == 200
    data = resp.json()
    assert data["alertId"] == sample_alert["alertId"]
    assert data["threatClass"] == "DDoS"


def test_alerts_stats(client, sample_alert):
    """Alert stats should reflect inserted alerts."""
    resp = client.get("/api/alerts")
    stats = resp.json()["stats"]
    assert stats["total"] == 0  # No alerts stored yet via endpoints

    # Manually insert via store to test stats computation
    from app.services.store import insert_alert
    from app.models.schemas import Alert, ThreatClass, Severity

    insert_alert(Alert(
        alertId="ALT-TEST-001",
        timestamp=1725120000000,
        flowId="FLOW-0000001",
        threatClass=ThreatClass.DDoS,
        confidence=0.95,
        severity=Severity.CRITICAL,
        sourceIp="1.2.3.4",
        destinationIp="10.0.1.1",
        protocol="UDP",
        destinationPort=80,
        detector="DDoS-RF-v1",
        detectionLatencyMs=84,
        supportingEvidence={},
        description="DDoS detected",
        status="new",
    ))

    resp = client.get("/api/alerts")
    stats = resp.json()["stats"]
    assert stats["total"] == 1
    assert stats["byThreatClass"]["DDoS"] == 1
    assert stats["bySeverity"]["CRITICAL"] == 1
