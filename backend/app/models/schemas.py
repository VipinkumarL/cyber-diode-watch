"""
SIH26145 Pydantic Models — Backend ↔ Frontend contract.

These models mirror the TypeScript interfaces in src/lib/types.ts
and src/services/api.ts exactly, so the frontend can deserialize
responses without field-name mapping.
"""

from __future__ import annotations

import enum
from typing import Any, Literal, Optional, Union

from pydantic import BaseModel, ConfigDict, Field


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
    model_config = ConfigDict(
        json_schema_extra={
            "examples": [
                {
                    "flowId": "DEMO-NORMAL-001",
                    "timestamp": 1725120000000,
                    "sourceIp": "10.10.1.25",
                    "destinationIp": "93.184.216.34",
                    "protocol": "TCP",
                    "sourcePort": 52144,
                    "destinationPort": 443,
                    "flowDuration": 12.4,
                    "totalPackets": 96,
                    "packetsPerSecond": 7.74,
                    "bytesPerSecond": 38240.0,
                    "totalBytes": 474176,
                    "classification": "Normal",
                    "confidence": 0.0,
                    "severity": "INFO",
                    "sourceEntropy": 2.1,
                    "destinationConcentration": 0.18,
                    "packetLengthMean": 512.0,
                    "packetLengthStd": 84.5,
                    "isSuspicious": False,
                    "scenario": "normal",
                }
            ]
        }
    )

    flowId: str = Field(..., examples=["DEMO-NORMAL-001"])
    timestamp: int = Field(..., description="Epoch timestamp in milliseconds")
    sourceIp: str = Field(..., examples=["10.10.1.25"])
    destinationIp: str = Field(..., examples=["93.184.216.34"])
    protocol: str = Field(..., examples=["TCP"])
    sourcePort: int = Field(..., ge=0, le=65535)
    destinationPort: int = Field(..., ge=0, le=65535)
    flowDuration: float = Field(..., ge=0.0, description="Flow duration in seconds")
    totalPackets: int = Field(..., ge=0)
    packetsPerSecond: float = Field(..., ge=0.0)
    bytesPerSecond: float = Field(..., ge=0.0)
    totalBytes: int = Field(..., ge=0)
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
    model_config = ConfigDict(
        json_schema_extra={
            "examples": [
                {
                    "flow": {
                        "flowId": "DEMO-DDOS-METADATA-001",
                        "timestamp": 1725120000000,
                        "sourceIp": "10.10.4.18",
                        "destinationIp": "10.10.8.20",
                        "protocol": "UDP",
                        "sourcePort": 49152,
                        "destinationPort": 443,
                        "flowDuration": 0.35,
                        "totalPackets": 52000,
                        "packetsPerSecond": 148571.43,
                        "bytesPerSecond": 11800000.0,
                        "totalBytes": 4130000,
                        "classification": "Normal",
                        "confidence": 0.0,
                        "severity": "INFO",
                        "sourceEntropy": 7.2,
                        "destinationConcentration": 0.94,
                        "packetLengthMean": 79.4,
                        "packetLengthStd": 18.6,
                        "isSuspicious": False,
                        "scenario": "ddos",
                    }
                }
            ]
        }
    )

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
