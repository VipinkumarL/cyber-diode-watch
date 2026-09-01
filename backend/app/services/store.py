"""
SIH26145 In-Memory Data Store.

Thread-safe in-memory storage for flows, alerts, incidents, and metrics.
Replace with a proper database (PostgreSQL, SQLite) for production.
"""

from __future__ import annotations

import time
import threading
from collections import deque
from typing import Optional

from ..models.schemas import (
    Alert,
    AlertStats,
    FlowStats,
    Incident,
    IncidentStats,
    NetworkFlow,
    Severity,
    SystemMetrics,
    ThreatClass,
)

# Thread lock for safe concurrent access
_lock = threading.Lock()

# Bounded in-memory stores
_flows: deque[NetworkFlow] = deque(maxlen=2000)
_alerts: deque[Alert] = deque(maxlen=1000)
_incidents: deque[Incident] = deque(maxlen=500)
_metrics: deque[SystemMetrics] = deque(maxlen=300)

# Counters for IDs
_flow_counter: int = 0
_alert_counter: int = 0
_incident_counter: int = 0

# ── Flow Operations ───────────────────────────────────────────────


def insert_flow(flow: NetworkFlow) -> NetworkFlow:
    """Insert a flow record into the store."""
    with _lock:
        _flows.appendleft(flow)
    return flow


def get_flows(limit: int = 200) -> list[NetworkFlow]:
    """Return the most recent flows up to `limit`."""
    with _lock:
        return list(_flows)[:limit]


def get_flow(flow_id: str) -> Optional[NetworkFlow]:
    """Look up a single flow by its flowId."""
    with _lock:
        for f in _flows:
            if f.flowId == flow_id:
                return f
    return None


def get_flow_stats() -> FlowStats:
    """Compute aggregate statistics over all stored flows."""
    with _lock:
        flows = list(_flows)
        alerts_list = list(_alerts)

    total = len(flows)
    normal = sum(1 for f in flows if f.classification == ThreatClass.Normal)
    suspicious = sum(1 for f in flows if f.isSuspicious)
    threats = sum(
        1 for f in flows if f.classification != ThreatClass.Normal and f.isSuspicious
    )

    # Throughput: flows received in the last 1 second
    now_ms = int(time.time() * 1000)
    recent = sum(1 for f in flows if now_ms - f.timestamp < 1000)
    flows_per_sec = float(recent)

    # Average detection latency
    with_conf = [f for f in flows if f.confidence > 0]
    avg_latency = (
        round(sum(f.flowDuration * 100 or 84 for f in with_conf) / len(with_conf))
        if with_conf
        else 0
    )

    # Risk score
    critical = sum(1 for a in alerts_list if a.severity == Severity.CRITICAL)
    high = sum(1 for a in alerts_list if a.severity == Severity.HIGH)
    risk_score = min(100, critical * 15 + high * 8 + threats * 2)

    return FlowStats(
        totalFlows=total,
        normalFlows=normal,
        suspiciousFlows=suspicious,
        threatsDetected=threats,
        criticalAlerts=critical,
        flowsPerSecond=flows_per_sec,
        avgDetectionLatencyMs=float(avg_latency),
        riskScore=risk_score,
    )


def clear_flows() -> None:
    """Clear all stored flows."""
    with _lock:
        _flows.clear()


# ── Alert Operations ──────────────────────────────────────────────


def insert_alert(alert: Alert) -> Alert:
    """Insert an alert into the store."""
    with _lock:
        _alerts.appendleft(alert)
    return alert


def get_alerts(limit: int = 50) -> list[Alert]:
    """Return the most recent alerts up to `limit`."""
    with _lock:
        return list(_alerts)[:limit]


def get_alert(alert_id: str) -> Optional[Alert]:
    """Look up a single alert by its alertId."""
    with _lock:
        for a in _alerts:
            if a.alertId == alert_id:
                return a
    return None


def get_alert_stats() -> AlertStats:
    """Compute aggregate statistics over all stored alerts."""
    with _lock:
        alerts_list = list(_alerts)

    total = len(alerts_list)
    by_threat: dict[str, int] = {}
    by_severity: dict[str, int] = {}
    total_conf = 0.0
    total_lat = 0

    for a in alerts_list:
        by_threat[a.threatClass.value] = by_threat.get(a.threatClass.value, 0) + 1
        by_severity[a.severity.value] = by_severity.get(a.severity.value, 0) + 1
        total_conf += a.confidence
        total_lat += a.detectionLatencyMs

    return AlertStats(
        total=total,
        byThreatClass=by_threat,
        bySeverity=by_severity,
        avgConfidence=round(total_conf / total, 4) if total else 0.0,
        avgLatency=round(total_lat / total, 2) if total else 0.0,
    )


def clear_alerts() -> None:
    """Clear all stored alerts."""
    with _lock:
        _alerts.clear()


# ── Incident Operations ───────────────────────────────────────────


def insert_incident(incident: Incident) -> Incident:
    """Insert an incident into the store."""
    with _lock:
        _incidents.appendleft(incident)
    return incident


def get_incidents(limit: int = 50) -> list[Incident]:
    """Return the most recent incidents up to `limit`."""
    with _lock:
        return list(_incidents)[:limit]


def get_incident(incident_id: str) -> Optional[Incident]:
    """Look up a single incident by its incidentId."""
    with _lock:
        for i in _incidents:
            if i.incidentId == incident_id:
                return i
    return None


def get_incident_stats() -> IncidentStats:
    """Compute aggregate statistics over all stored incidents."""
    with _lock:
        incidents_list = list(_incidents)

    total = len(incidents_list)
    by_status: dict[str, int] = {}
    by_severity: dict[str, int] = {}

    for inc in incidents_list:
        by_status[inc.status] = by_status.get(inc.status, 0) + 1
        by_severity[inc.severity.value] = by_severity.get(inc.severity.value, 0) + 1

    return IncidentStats(
        total=total,
        byStatus=by_status,
        bySeverity=by_severity,
    )


def clear_incidents() -> None:
    """Clear all stored incidents."""
    with _lock:
        _incidents.clear()


# ── Metrics Operations ────────────────────────────────────────────


def record_metrics() -> SystemMetrics:
    """Snapshot current system state into metrics history."""
    flow_stats = get_flow_stats()
    alert_stats = get_alert_stats()

    metrics = SystemMetrics(
        timestamp=int(time.time() * 1000),
        totalFlows=flow_stats.totalFlows,
        normalFlows=flow_stats.normalFlows,
        suspiciousFlows=flow_stats.suspiciousFlows,
        threatsDetected=flow_stats.threatsDetected,
        criticalAlerts=flow_stats.criticalAlerts,
        flowsPerSecond=flow_stats.flowsPerSecond,
        avgDetectionLatencyMs=flow_stats.avgDetectionLatencyMs,
        riskScore=flow_stats.riskScore,
        totalAlerts=alert_stats.total,
        totalIncidents=len(_incidents),
    )

    with _lock:
        _metrics.appendleft(metrics)

    return metrics


def get_latest_metrics() -> Optional[SystemMetrics]:
    """Return the most recent metrics snapshot."""
    with _lock:
        return _metrics[0] if _metrics else None


# ── Global Clear ──────────────────────────────────────────────────


def clear_all() -> None:
    """Clear all data stores (used by replay reset)."""
    with _lock:
        _flows.clear()
        _alerts.clear()
        _incidents.clear()
        _metrics.clear()


# ── ID Generation ─────────────────────────────────────────────────


def next_flow_id() -> str:
    """Generate the next flow ID."""
    global _flow_counter
    with _lock:
        _flow_counter += 1
        return f"FLOW-{_flow_counter:07d}"


def next_alert_id() -> str:
    """Generate the next alert ID."""
    global _alert_counter
    with _lock:
        _alert_counter += 1
        ts = int(time.time() * 1000)
        return f"ALT-{ts}-{_alert_counter:04d}"


def next_incident_id() -> str:
    """Generate the next incident ID."""
    global _incident_counter
    with _lock:
        _incident_counter += 1
        ts = int(time.time() * 1000)
        return f"INC-{ts}-{_incident_counter:04d}"


def reset_counters() -> None:
    """Reset all ID counters (used by replay reset)."""
    global _flow_counter, _alert_counter, _incident_counter
    with _lock:
        _flow_counter = 0
        _alert_counter = 0
        _incident_counter = 0
