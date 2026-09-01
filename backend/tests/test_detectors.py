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


def test_all_detectors_are_active(client):
    """All 6 detectors should now be ACTIVE (working baselines)."""
    resp = client.get("/api/detectors")
    data = resp.json()
    for d in data:
        assert d["status"] == "ACTIVE", f"{d['name']} is not ACTIVE"


def test_ddos_detector_method(client):
    """DDoS detector should use statistical/baseline method."""
    resp = client.get("/api/detectors")
    data = resp.json()
    ddos = next(d for d in data if d["threatClass"] == "DDoS")
    assert "Baseline" in ddos["method"] or "Statistical" in ddos["method"]


def test_detectors_have_descriptions(client):
    """Each detector should have a non-empty description."""
    resp = client.get("/api/detectors")
    data = resp.json()
    for d in data:
        assert len(d["description"]) > 10, f"{d['name']} has no description"
