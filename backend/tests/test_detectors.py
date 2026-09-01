"""Tests for detector status endpoint."""

import pytest


def test_list_detectors(client):
    """GET /api/detectors should return all detectors (6 baseline + 1 ML)."""
    resp = client.get("/api/detectors")
    assert resp.status_code == 200
    data = resp.json()
    assert len(data) == 7  # 6 baseline + 1 ML

    threat_classes = {d["threatClass"] for d in data}
    expected = {
        "DDoS",
        "C2_Beaconing",
        "DGA_DNS_Tunneling",
        "Encrypted_Malware",
        "Reconnaissance",
        "Data_Exfiltration",
        "Normal",  # ML classifier
    }
    assert threat_classes == expected


def test_baseline_detectors_are_active(client):
    """All 6 baseline detectors should be ACTIVE."""
    resp = client.get("/api/detectors")
    data = resp.json()
    baseline = [d for d in data if d["name"] != "ML Random Forest Classifier"]
    assert len(baseline) == 6
    for d in baseline:
        assert d["status"] == "ACTIVE", f"{d['name']} is not ACTIVE"


def test_ml_detector_status(client):
    """ML detector should report ACTIVE when model is loaded."""
    resp = client.get("/api/detectors")
    data = resp.json()
    ml = next((d for d in data if "ML" in d["name"]), None)
    assert ml is not None
    assert ml["status"] == "ACTIVE"
    assert "Random Forest" in ml["method"]


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
