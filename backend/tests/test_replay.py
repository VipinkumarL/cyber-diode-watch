"""Tests for replay control endpoints."""

import pytest


def test_start_replay(client):
    """POST /api/replay/start should return running status."""
    resp = client.post("/api/replay/start", json={
        "scenario": "ddos",
        "speed": 100,
        "dataset": "synthetic",
    })
    assert resp.status_code == 200
    data = resp.json()
    assert data["status"] == "running"


def test_pause_replay(client):
    """POST /api/replay/pause should return paused status."""
    client.post("/api/replay/start", json={
        "scenario": "normal",
        "speed": 100,
        "dataset": "synthetic",
    })
    resp = client.post("/api/replay/pause")
    assert resp.status_code == 200
    assert resp.json()["status"] == "paused"


def test_stop_replay(client):
    """POST /api/replay/stop should return stopped status."""
    client.post("/api/replay/start", json={
        "scenario": "normal",
        "speed": 100,
        "dataset": "synthetic",
    })
    resp = client.post("/api/replay/stop")
    assert resp.status_code == 200
    assert resp.json()["status"] == "stopped"


def test_reset_replay(client):
    """POST /api/replay/reset should return idle status."""
    client.post("/api/replay/start", json={
        "scenario": "ddos",
        "speed": 100,
        "dataset": "synthetic",
    })
    resp = client.post("/api/replay/reset")
    assert resp.status_code == 200
    assert resp.json()["status"] == "idle"


def test_reset_clears_data(client, sample_flow):
    """POST /api/replay/reset should clear all stored data."""
    client.post("/api/flows", json=sample_flow)
    resp = client.get("/api/flows")
    assert resp.json()["stats"]["totalFlows"] == 1

    client.post("/api/replay/reset")

    resp = client.get("/api/flows")
    assert resp.json()["stats"]["totalFlows"] == 0
