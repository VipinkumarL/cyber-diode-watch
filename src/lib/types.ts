// SIH26145 Types — AI-Based Cyber Threat Detection

export type ThreatClass =
  | "DDoS"
  | "C2_Beaconing"
  | "DGA_DNS_Tunneling"
  | "Encrypted_Malware"
  | "Reconnaissance"
  | "Data_Exfiltration"
  | "Normal";

export type Severity = "CRITICAL" | "HIGH" | "MEDIUM" | "LOW" | "INFO";

export type DetectorStatus = "ACTIVE" | "DEMO" | "NOT_TRAINED" | "DISABLED";

export interface NetworkFlow {
  flowId: string;
  timestamp: number;
  sourceIp: string;
  destinationIp: string;
  protocol: string;
  sourcePort: number;
  destinationPort: number;
  flowDuration: number;
  totalPackets: number;
  packetsPerSecond: number;
  bytesPerSecond: number;
  totalBytes: number;
  classification: ThreatClass;
  confidence: number;
  severity: Severity;
  sourceEntropy?: number;
  destinationConcentration?: number;
  packetLengthMean?: number;
  packetLengthStd?: number;
  isSuspicious: boolean;
  scenario?: string;
}

export interface Alert {
  alertId: string;
  timestamp: number;
  flowId: string;
  threatClass: ThreatClass;
  confidence: number;
  severity: Severity;
  sourceIp: string;
  destinationIp: string;
  protocol: string;
  destinationPort: number;
  detector: string;
  detectionLatencyMs: number;
  supportingEvidence: Record<string, number | string>;
  description: string;
  status: string;
  scenario?: string;
}

export interface Incident {
  incidentId: string;
  timestamp: number;
  title: string;
  description: string;
  threatClass: ThreatClass;
  severity: Severity;
  confidence: number;
  alertCount: number;
  sourceIps: string[];
  destinationIps: string[];
  status: string;
  evidence: Record<string, number | string>;
  detector: string;
  detectionLatencyMs: number;
  scenario?: string;
}

export interface SystemMetrics {
  timestamp: number;
  totalFlows: number;
  normalFlows: number;
  suspiciousFlows: number;
  threatsDetected: number;
  criticalAlerts: number;
  flowsPerSecond: number;
  avgDetectionLatencyMs: number;
  riskScore: number;
  totalAlerts: number;
  totalIncidents: number;
}

export interface ReplayState {
  sessionId: string;
  status: "idle" | "running" | "paused" | "stopped";
  speed: number;
  flowsPerSecond: number;
  measuredFlowsPerSecond: number;
  dataset: string;
  scenario: string;
  totalFlows: number;
  processedFlows: number;
  startedAt?: number;
  mode: "LIVE" | "REPLAY" | "MOCK";
}

export interface DetectorInfo {
  name: string;
  threatClass: ThreatClass;
  status: DetectorStatus;
  method: string;
  description: string;
}

export interface FeatureVector {
  flowDuration: number;
  packetsPerSecond: number;
  bytesPerSecond: number;
  totalPackets: number;
  totalBytes: number;
  sourcePort: number;
  destinationPort: number;
  sourceEntropy: number;
  destinationConcentration: number;
  packetLengthMean: number;
  packetLengthStd: number;
}

export const NAV_ITEMS = [
  { label: "Overview", icon: "LayoutDashboard", path: "/dashboard/overview" },
  { label: "Live Traffic", icon: "Activity", path: "/dashboard/traffic" },
  { label: "Threats", icon: "ShieldAlert", path: "/dashboard/threats" },
  { label: "Incidents", icon: "AlertTriangle", path: "/dashboard/incidents" },
  { label: "Analytics", icon: "BarChart3", path: "/dashboard/analytics" },
  { label: "Replay Lab", icon: "FlaskConical", path: "/dashboard/replay" },
  { label: "System Health", icon: "HeartPulse", path: "/dashboard/health" },
] as const;

export const THREAT_COLORS: Record<ThreatClass, string> = {
  DDoS: "#e94560",
  C2_Beaconing: "#f5a623",
  DGA_DNS_Tunneling: "#0f9b8e",
  Encrypted_Malware: "#533483",
  Reconnaissance: "#48b9a7",
  Data_Exfiltration: "#ff6b6b",
  Normal: "#6c7a89",
};

export const SEVERITY_COLORS: Record<Severity, string> = {
  CRITICAL: "#e94560",
  HIGH: "#f5a623",
  MEDIUM: "#0f9b8e",
  LOW: "#48b9a7",
  INFO: "#6c7a89",
};
