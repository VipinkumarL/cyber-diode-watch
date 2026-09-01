"""Tests for detector status endpoint."""

import pytest


def test_list_detectors(client):
    """GET /api/detectors should return all 6 detector categories."""
    resp = client.get("/api/detectors")
    assert resp.status_code == 200
    data = resp.json()
    assert len(data) == 6

    threat_classes = {d["threatClass"] for d in data}
    expected = {
        "DDoS",
        "C2_Beaconing",
        "DGA_DNS_Tunneling",
        "Encrypted_Malware",
        "Reconnaissance",
        "Data_Exfiltration",
    }
    assert threat_classes == expected


def test_detectors_not_implemented(client):
    """All detectors should be marked NOT_IMPLEMENTED (no ML model loaded)."""
    resp = client.get("/api/detectors")
    data = resp.json()
    for d in data:
        assert d["status"] == "NOT_IMPLEMENTED"
