"""
SIH26145 Pydantic Models — Backend ↔ Frontend contract.

These models mirror the TypeScript interfaces in src/lib/types.ts
and src/services/api.ts exactly, so the frontend can deserialize
responses without field-name mapping.
"""

from __future__ import annotations

import enum
from typing import Any, Literal, Optional, Union

from pydantic import BaseModel, Field


# ── Enums ─────────────────────────────────────────────────────────

class ThreatClass(str, enum.Enum):
    DDoS = "DDoS"
    C2_Beaconing = "C2_Beaconing"
    DGA_DNS_Tunneling = "DGA_DNS_Tunneling"
    Encrypted_Malware = "Encrypted_Malware"
    Reconnaissance = "Reconnaissance"
    Data_Exfiltration = "Data_Exfiltration"
    Normal = "Normal"


class Severity(str, enum.Enum):
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"


class DetectorStatus(str, enum.Enum):
    ACTIVE = "ACTIVE"
    DEMO = "DEMO"
    NOT_TRAINED = "NOT_TRAINED"
    NOT_IMPLEMENTED = "NOT_IMPLEMENTED"
    DISABLED = "DISABLED"


# ── Core Data Models ──────────────────────────────────────────────

class NetworkFlow(BaseModel):
    """Network flow record — mirrors src/lib/types.ts NetworkFlow."""
    flowId: str
    timestamp: int  # epoch milliseconds
    sourceIp: str
    destinationIp: str
    protocol: str
    sourcePort: int
    destinationPort: int
    flowDuration: float
    totalPackets: int
    packetsPerSecond: float
    bytesPerSecond: float
    totalBytes: int
    classification: ThreatClass = ThreatClass.Normal
    confidence: float = 0.0
    severity: Severity = Severity.INFO
    sourceEntropy: Optional[float] = None
    destinationConcentration: Optional[float] = None
    packetLengthMean: Optional[float] = None
    packetLengthStd: Optional[float] = None
    isSuspicious: bool = False
    scenario: Optional[str] = None


class Alert(BaseModel):
    """Threat alert — mirrors src/lib/types.ts Alert."""
    alertId: str
    timestamp: int
    flowId: str
    threatClass: ThreatClass
    confidence: float
    severity: Severity
    sourceIp: str
    destinationIp: str
    protocol: str
    destinationPort: int
    detector: str
    detectionLatencyMs: int
    supportingEvidence: dict[str, Any] = Field(default_factory=dict)
    description: str
    status: str = "new"
    scenario: Optional[str] = None


class Incident(BaseModel):
    """Incident record — mirrors src/lib/types.ts Incident."""
    incidentId: str
    timestamp: int
    title: str
    description: str
    threatClass: ThreatClass
    severity: Severity
    confidence: float
    alertCount: int = 1
    sourceIps: list[str] = Field(default_factory=list)
    destinationIps: list[str] = Field(default_factory=list)
    status: str = "open"
    evidence: dict[str, Any] = Field(default_factory=dict)
    detector: str = ""
    detectionLatencyMs: int = 0
    scenario: Optional[str] = None


class DetectorInfo(BaseModel):
    """Detector metadata — mirrors src/lib/types.ts DetectorInfo."""
    name: str
    threatClass: ThreatClass
    status: DetectorStatus
    method: str
    description: str


class FeatureVector(BaseModel):
    """Extracted features for ML detection."""
    flowDuration: float = 0.0
    packetsPerSecond: float = 0.0
    bytesPerSecond: float = 0.0
    totalPackets: int = 0
    totalBytes: int = 0
    sourcePort: int = 0
    destinationPort: int = 0
    sourceEntropy: float = 0.0
    destinationConcentration: float = 0.0
    packetLengthMean: float = 0.0
    packetLengthStd: float = 0.0


# ── Statistics / Metrics ──────────────────────────────────────────

class FlowStats(BaseModel):
    totalFlows: int = 0
    normalFlows: int = 0
    suspiciousFlows: int = 0
    threatsDetected: int = 0
    criticalAlerts: int = 0
    flowsPerSecond: float = 0.0
    avgDetectionLatencyMs: float = 0.0
    riskScore: int = 0


class AlertStats(BaseModel):
    total: int = 0
    byThreatClass: dict[str, int] = Field(default_factory=dict)
    bySeverity: dict[str, int] = Field(default_factory=dict)
    avgConfidence: float = 0.0
    avgLatency: float = 0.0


class IncidentStats(BaseModel):
    total: int = 0
    byStatus: dict[str, int] = Field(default_factory=dict)
    bySeverity: dict[str, int] = Field(default_factory=dict)


class SystemMetrics(BaseModel):
    """System-wide metrics snapshot."""
    timestamp: int = 0
    totalFlows: int = 0
    normalFlows: int = 0
    suspiciousFlows: int = 0
    threatsDetected: int = 0
    criticalAlerts: int = 0
    flowsPerSecond: float = 0.0
    avgDetectionLatencyMs: float = 0.0
    riskScore: int = 0
    totalAlerts: int = 0
    totalIncidents: int = 0


# ── API Response Models ───────────────────────────────────────────

class HealthResponse(BaseModel):
    status: Literal["ok", "degraded", "error"] = "ok"
    model_loaded: bool = False
    model_source: str = ""  # "CICIDS2017" or "synthetic" or ""
    db_status: str = "in_memory"


class FlowsResponse(BaseModel):
    flows: list[NetworkFlow] = Field(default_factory=list)
    stats: FlowStats = Field(default_factory=FlowStats)


class AlertsResponse(BaseModel):
    alerts: list[Alert] = Field(default_factory=list)
    stats: AlertStats = Field(default_factory=AlertStats)


class IncidentsResponse(BaseModel):
    incidents: list[Incident] = Field(default_factory=list)
    stats: IncidentStats = Field(default_factory=IncidentStats)


class StatisticsResponse(BaseModel):
    flows: FlowStats = Field(default_factory=FlowStats)
    alerts: AlertStats = Field(default_factory=AlertStats)
    incidents: IncidentStats = Field(default_factory=IncidentStats)


class PredictRequest(BaseModel):
    flow: NetworkFlow


class PredictResponse(BaseModel):
    alert: Optional[Alert] = None
    updatedFlow: NetworkFlow
    detectionTimeMs: int


class ReplayStartRequest(BaseModel):
    scenario: str = "normal"
    speed: int = 100
    dataset: str = "synthetic"


class ReplayStatusResponse(BaseModel):
    status: str
