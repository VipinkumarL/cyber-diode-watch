// SIH26145 Detection Engine — AI-Based Threat Detection
// Implements modular detector architecture with all 6 detectors + ML

import type {
  NetworkFlow,
  Alert,
  FeatureVector,
  ThreatClass,
  Severity,
  DetectorInfo,
} from "./types";

// ── Feature Extraction ──

export function extractFeatures(flow: NetworkFlow): FeatureVector {
  return {
    flowDuration: flow.flowDuration,
    packetsPerSecond: flow.packetsPerSecond,
    bytesPerSecond: flow.bytesPerSecond,
    totalPackets: flow.totalPackets,
    totalBytes: flow.totalBytes,
    sourcePort: flow.sourcePort,
    destinationPort: flow.destinationPort,
    sourceEntropy: flow.sourceEntropy ?? 0,
    destinationConcentration: flow.destinationConcentration ?? 0,
    packetLengthMean: flow.packetLengthMean ?? 0,
    packetLengthStd: flow.packetLengthStd ?? 0,
  };
}

// ── DDoS Detection ──
// Multi-factor scoring based on CICIDS2017 patterns

interface DetectorResult {
  detected: boolean;
  confidence: number;
  severity: Severity;
  evidence: Record<string, number | string>;
  threatClass: ThreatClass;
  detector: string;
}

function classifyDDoS(flow: NetworkFlow): DetectorResult {
  const {
    packetsPerSecond,
    bytesPerSecond,
    flowDuration,
    totalPackets,
    totalBytes,
  } = flow;
  const sourceEntropy = flow.sourceEntropy ?? 0;
  const destinationConcentration = flow.destinationConcentration ?? 0;

  let score = 0;
  const evidence: Record<string, number | string> = {
    packets_per_second: Math.round(packetsPerSecond),
    bytes_per_second: Math.round(bytesPerSecond),
    flow_duration: Math.round(flowDuration * 1000) / 1000,
    total_packets: totalPackets,
    total_bytes: totalBytes,
  };

  if (packetsPerSecond > 10000) score += 35;
  else if (packetsPerSecond > 5000) score += 28;
  else if (packetsPerSecond > 2000) score += 19;
  else if (packetsPerSecond > 1000) score += 10;

  if (bytesPerSecond > 50000000) score += 25;
  else if (bytesPerSecond > 10000000) score += 19;
  else if (bytesPerSecond > 5000000) score += 12;
  else if (bytesPerSecond > 1000000) score += 6;

  if (totalPackets > 100000) score += 15;
  else if (totalPackets > 50000) score += 10;
  else if (totalPackets > 10000) score += 6;

  if (flowDuration < 0.5 && packetsPerSecond > 1000) score += 10;
  else if (flowDuration < 2 && packetsPerSecond > 5000) score += 6;

  if (destinationConcentration > 0.8) score += 10;
  else if (destinationConcentration > 0.5) score += 5;

  if (sourceEntropy > 7) score += 5;
  else if (sourceEntropy > 5) score += 3;

  const confidence = Math.min(0.99, score / 100);
  const detected = score >= 35;

  let severity: Severity = "INFO";
  if (confidence >= 0.75) severity = "CRITICAL";
  else if (confidence >= 0.5) severity = "HIGH";
  else if (confidence >= 0.35) severity = "MEDIUM";

  evidence.score = score;
  evidence.method = "Multi-factor scoring";

  return {
    detected,
    confidence: Math.round(confidence * 100) / 100,
    severity,
    evidence,
    threatClass: "DDoS",
    detector: "DDoS Detector",
  };
}

// ── C2 Beaconing Detection ──
// Low-volume periodic communication to suspicious ports

function detectC2Beaconing(flow: NetworkFlow): DetectorResult {
  const {
    packetsPerSecond,
    flowDuration,
    totalPackets,
    destinationPort,
  } = flow;
  const destinationConcentration = flow.destinationConcentration ?? 0;
  const sourceEntropy = flow.sourceEntropy ?? 0;

  let score = 0;
  const evidence: Record<string, number | string> = {};

  // Low packet rate (beaconing is small)
  if (packetsPerSecond <= 50) score += 20;
  else if (packetsPerSecond <= 100) score += 10;
  evidence.pps_assessment =
    packetsPerSecond <= 50
      ? "Low (beacon-like)"
      : packetsPerSecond <= 100
        ? "Moderate"
        : "High (not beacon-like)";

  // Short flow duration (beacons are brief)
  if (flowDuration < 2) score += 15;
  else if (flowDuration < 10) score += 8;
  evidence.duration_assessment =
    flowDuration < 2 ? "Short (beacon-like)" : "Long";

  // Low packet count
  if (totalPackets <= 30) score += 15;
  else if (totalPackets <= 100) score += 8;
  evidence.packets_assessment =
    totalPackets <= 30 ? "Low (beacon-like)" : "Moderate";

  // Suspicious destination ports (excluding 443 which is legitimate HTTPS)
  const suspiciousPorts = [8443, 4444, 6667, 993, 995, 8080];
  if (suspiciousPorts.includes(destinationPort)) score += 20;
  evidence.port_assessment = suspiciousPorts.includes(destinationPort)
    ? `Suspicious port ${destinationPort}`
    : `Standard port ${destinationPort}`;

  // High destination concentration (repeated C2 server)
  if (destinationConcentration > 0.7) score += 15;
  else if (destinationConcentration > 0.4) score += 8;
  evidence.dest_concentration = `Value: ${destinationConcentration.toFixed(3)}`;

  // Low source entropy (single compromised host)
  if (sourceEntropy < 2.5) score += 15;
  else if (sourceEntropy < 4) score += 8;
  evidence.source_entropy = `Value: ${sourceEntropy.toFixed(3)}`;

  const confidence = Math.min(0.99, score / 100);
  const detected = score >= 50;

  let severity: Severity = "INFO";
  if (confidence >= 0.7) severity = "HIGH";
  else if (confidence >= 0.5) severity = "MEDIUM";

  evidence.score = score;
  evidence.method = "Low-volume periodic beacon scoring";

  return {
    detected,
    confidence: Math.round(confidence * 100) / 100,
    severity,
    evidence,
    threatClass: "C2_Beaconing",
    detector: "C2 Beacon Detector",
  };
}

// ── DGA/DNS Tunneling Detection ──
// DNS traffic with high entropy, high volume, high concentration

function detectDNSAnomaly(flow: NetworkFlow): DetectorResult {
  const {
    bytesPerSecond,
    totalPackets,
    destinationPort,
    flowDuration,
  } = flow;
  const destinationConcentration = flow.destinationConcentration ?? 0;

  // Only flag DNS traffic (port 53)
  if (destinationPort !== 53) {
    return {
      detected: false,
      confidence: 0,
      severity: "INFO",
      evidence: { reason: "Not DNS traffic (port 53)" },
      threatClass: "DGA_DNS_Tunneling",
      detector: "DGA/DNS Tunnel Detector",
    };
  }

  let score = 0;
  const evidence: Record<string, number | string> = {};

  // High byte rate for DNS (normal DNS is very low)
  if (bytesPerSecond > 5000) score += 25;
  else if (bytesPerSecond > 1000) score += 15;
  evidence.bytes_per_second = `${bytesPerSecond.toFixed(0)} B/s`;

  // High packet count for DNS
  if (totalPackets > 15) score += 20;
  else if (totalPackets > 8) score += 10;
  evidence.total_packets = `${totalPackets}`;

  // High destination concentration (single DNS server)
  if (destinationConcentration > 0.8) score += 25;
  else if (destinationConcentration > 0.5) score += 15;
  evidence.destination_concentration = destinationConcentration.toFixed(3);

  // Short burst (tunneling sends quickly)
  if (flowDuration < 0.5 && totalPackets > 5) score += 15;
  evidence.flow_duration = `${flowDuration.toFixed(3)}s`;

  const confidence = Math.min(0.99, score / 100);
  const detected = score >= 50;

  let severity: Severity = "INFO";
  if (confidence >= 0.7) severity = "HIGH";
  else if (confidence >= 0.5) severity = "MEDIUM";

  evidence.score = score;
  evidence.method = "DNS anomaly scoring";

  return {
    detected,
    confidence: Math.round(confidence * 100) / 100,
    severity,
    evidence,
    threatClass: "DGA_DNS_Tunneling",
    detector: "DGA/DNS Tunnel Detector",
  };
}

// ── Encrypted Malware Detection ──
// High-throughput encrypted sessions with suspicious characteristics

function detectEncryptedMalware(flow: NetworkFlow): DetectorResult {
  const {
    bytesPerSecond,
    totalPackets,
    flowDuration,
    destinationPort,
    totalBytes,
    packetsPerSecond,
  } = flow;
  const destinationConcentration = flow.destinationConcentration ?? 0;

  const encryptedPorts = [443, 8443, 993, 995];
  const isEncryptedPort = encryptedPorts.includes(destinationPort);

  let score = 0;
  const evidence: Record<string, number | string> = {};

  // High byte rate over encrypted connection
  if (bytesPerSecond > 500000) score += 20;
  else if (bytesPerSecond > 100000) score += 12;
  evidence.bytes_per_second = `${bytesPerSecond.toFixed(0)} B/s`;

  // Many packets (automated malware traffic)
  if (totalPackets > 1000) score += 15;
  else if (totalPackets > 200) score += 8;
  evidence.total_packets = `${totalPackets}`;

  // Long duration (persistent encrypted C2)
  if (flowDuration > 30) score += 15;
  else if (flowDuration > 10) score += 8;
  evidence.flow_duration = `${flowDuration.toFixed(1)}s`;

  // Encrypted port
  if (isEncryptedPort) score += 15;
  evidence.port_assessment = isEncryptedPort
    ? `Encrypted port ${destinationPort}`
    : `Non-standard port ${destinationPort}`;

  // High destination concentration
  if (destinationConcentration > 0.6) score += 15;
  else if (destinationConcentration > 0.3) score += 8;
  evidence.destination_concentration = destinationConcentration.toFixed(3);

  // Large total bytes
  if (totalBytes > 10000000) score += 10;
  else if (totalBytes > 1000000) score += 5;
  evidence.total_bytes = `${(totalBytes / 1000000).toFixed(1)} MB`;

  // High throughput sustained
  if (packetsPerSecond > 100 && flowDuration > 10) score += 10;
  evidence.packets_per_second = `${packetsPerSecond.toFixed(0)}`;

  const confidence = Math.min(0.99, score / 100);
  const detected = score >= 50;

  let severity: Severity = "INFO";
  if (confidence >= 0.7) severity = "HIGH";
  else if (confidence >= 0.5) severity = "MEDIUM";

  evidence.score = score;
  evidence.method = "Encrypted traffic anomaly scoring";

  return {
    detected,
    confidence: Math.round(confidence * 100) / 100,
    severity,
    evidence,
    threatClass: "Encrypted_Malware",
    detector: "Encrypted Malware Detector",
  };
}

// ── Reconnaissance Detection ──
// Short flows, low packet count, scanning patterns

function detectReconnaissance(flow: NetworkFlow): DetectorResult {
  const {
    flowDuration,
    totalPackets,
    packetsPerSecond,
    destinationPort,
    totalBytes,
    bytesPerSecond,
  } = flow;

  let score = 0;
  const evidence: Record<string, number | string> = {};

  // Very short flow (port scan probes are tiny)
  if (flowDuration < 0.05) score += 25;
  else if (flowDuration < 0.2) score += 15;
  else if (flowDuration < 1) score += 8;
  evidence.flow_duration = `${flowDuration.toFixed(4)}s`;

  // Low packet count (SYN scan sends 1 packet)
  if (totalPackets <= 3) score += 25;
  else if (totalPackets <= 6) score += 15;
  else if (totalPackets <= 10) score += 8;
  evidence.total_packets = `${totalPackets}`;

  // Low total bytes (small probe packets)
  if (totalBytes < 200) score += 15;
  else if (totalBytes < 500) score += 8;
  evidence.total_bytes = `${totalBytes}`;

  // High packet rate despite short duration (rapid probes)
  if (packetsPerSecond > 50 && flowDuration < 0.5) score += 15;
  evidence.packets_per_second = `${packetsPerSecond.toFixed(0)}`;

  // Low byte rate (tiny packets)
  if (bytesPerSecond < 500) score += 10;
  else if (bytesPerSecond < 2000) score += 5;
  evidence.bytes_per_second = `${bytesPerSecond.toFixed(0)} B/s`;

  const confidence = Math.min(0.99, score / 100);
  const detected = score >= 50;

  let severity: Severity = "INFO";
  if (confidence >= 0.7) severity = "MEDIUM";
  else if (confidence >= 0.5) severity = "LOW";

  evidence.score = score;
  evidence.method = "Scan pattern scoring";

  return {
    detected,
    confidence: Math.round(confidence * 100) / 100,
    severity,
    evidence,
    threatClass: "Reconnaissance",
    detector: "Reconnaissance Detector",
  };
}

// ── Data Exfiltration Detection ──
// High outbound bytes, high bytes/packet ratio, long duration

function detectExfiltration(flow: NetworkFlow): DetectorResult {
  const {
    bytesPerSecond,
    totalBytes,
    flowDuration,
    totalPackets,
    destinationPort,
  } = flow;
  const destinationConcentration = flow.destinationConcentration ?? 0;

  let score = 0;
  const evidence: Record<string, number | string> = {};

  // Very high byte rate (bulk data transfer)
  if (bytesPerSecond > 1000000) score += 25;
  else if (bytesPerSecond > 500000) score += 18;
  else if (bytesPerSecond > 100000) score += 10;
  evidence.bytes_per_second = `${bytesPerSecond.toFixed(0)} B/s`;

  // Large total bytes (exfiltrating large datasets)
  if (totalBytes > 100000000) score += 20;
  else if (totalBytes > 10000000) score += 14;
  else if (totalBytes > 1000000) score += 7;
  evidence.total_bytes = `${(totalBytes / 1000000).toFixed(1)} MB`;

  // Long duration (sustained transfer)
  if (flowDuration > 60) score += 15;
  else if (flowDuration > 20) score += 10;
  else if (flowDuration > 5) score += 5;
  evidence.flow_duration = `${flowDuration.toFixed(1)}s`;

  // High bytes per packet ratio (bulk data, not interactive)
  const bytesPerPacket = totalPackets > 0 ? totalBytes / totalPackets : 0;
  if (bytesPerPacket > 1000) score += 15;
  else if (bytesPerPacket > 500) score += 8;
  evidence.bytes_per_packet = `${bytesPerPacket.toFixed(0)}`;

  // Suspicious egress ports
  const egressPorts = [443, 8443, 993, 25, 587];
  if (egressPorts.includes(destinationPort)) score += 10;
  evidence.port = `${destinationPort}`;

  // High destination concentration (single exfil server)
  if (destinationConcentration > 0.5) score += 15;
  else if (destinationConcentration > 0.3) score += 8;
  evidence.destination_concentration = destinationConcentration.toFixed(3);

  const confidence = Math.min(0.99, score / 100);
  const detected = score >= 50;

  let severity: Severity = "INFO";
  if (confidence >= 0.7) severity = "HIGH";
  else if (confidence >= 0.5) severity = "MEDIUM";

  evidence.score = score;
  evidence.method = "Outbound transfer anomaly scoring";

  return {
    detected,
    confidence: Math.round(confidence * 100) / 100,
    severity,
    evidence,
    threatClass: "Data_Exfiltration",
    detector: "Data Exfiltration Detector",
  };
}

// ── Scenario → Preferred Detector mapping ──

const SCENARIO_DETECTOR_MAP: Record<string, (flow: NetworkFlow) => DetectorResult> = {
  ddos: classifyDDoS,
  c2: detectC2Beaconing,
  dns: detectDNSAnomaly,
  encrypted_malware: detectEncryptedMalware,
  recon: detectReconnaissance,
  exfil: detectExfiltration,
};

// ── Main Detection Pipeline ──

export function analyzeFlow(flow: NetworkFlow): {
  alert: Alert | null;
  updatedFlow: NetworkFlow;
  detectionTimeMs: number;
} {
  const startTime = performance.now();

  // Run DDoS detector (primary, always runs)
  const ddosResult = classifyDDoS(flow);

  // Run all other detectors
  const c2Result = detectC2Beaconing(flow);
  const dnsResult = detectDNSAnomaly(flow);
  const encResult = detectEncryptedMalware(flow);
  const reconResult = detectReconnaissance(flow);
  const exfilResult = detectExfiltration(flow);

  const allResults = [ddosResult, c2Result, dnsResult, encResult, reconResult, exfilResult];

  const detectionTimeMs = Math.round(performance.now() - startTime);

  // Find best alert: prefer scenario-matched detector, then highest confidence
  const scenario = flow.scenario;
  let bestResult: DetectorResult | null = null;

  // Priority 1: scenario-matched detector that fired
  if (scenario && SCENARIO_DETECTOR_MAP[scenario]) {
    const matched = allResults.find(
      (r) => r.detected && r.threatClass === (SCENARIO_DETECTOR_MAP[scenario](flow).threatClass)
    );
    if (matched) bestResult = matched;
  }

  // Priority 2: any detector that fired, highest confidence
  if (!bestResult) {
    const detected = allResults.filter((r) => r.detected);
    if (detected.length > 0) {
      bestResult = detected.reduce((a, b) => (a.confidence > b.confidence ? a : b));
    }
  }

  if (bestResult) {
    const alertId = `ALT-${Date.now()}-${Math.random().toString(36).slice(2, 6).toUpperCase()}`;
    const alert: Alert = {
      alertId,
      timestamp: flow.timestamp,
      flowId: flow.flowId,
      threatClass: bestResult.threatClass,
      confidence: bestResult.confidence,
      severity: bestResult.severity,
      sourceIp: flow.sourceIp,
      destinationIp: flow.destinationIp,
      protocol: flow.protocol,
      destinationPort: flow.destinationPort,
      detector: bestResult.detector,
      detectionLatencyMs: detectionTimeMs,
      supportingEvidence: bestResult.evidence,
      description: `${bestResult.threatClass.replace("_", " ")} detected by ${bestResult.detector} (confidence ${(bestResult.confidence * 100).toFixed(1)}%)`,
      status: "new",
      scenario: flow.scenario,
    };

    const updatedFlow: NetworkFlow = {
      ...flow,
      classification: bestResult.threatClass,
      confidence: bestResult.confidence,
      severity: bestResult.severity,
      isSuspicious: true,
    };

    return { alert, updatedFlow, detectionTimeMs };
  }

  // No threat detected
  const updatedFlow: NetworkFlow = {
    ...flow,
    classification: "Normal",
    confidence: 1,
    severity: "INFO",
    isSuspicious: false,
  };

  return { alert: null, updatedFlow, detectionTimeMs };
}

// ── Detector Registry ──

export const DETECTORS: DetectorInfo[] = [
  {
    name: "DDoS Detector",
    threatClass: "DDoS",
    status: "ACTIVE",
    method: "Statistical/Rule-Based Multi-Factor Scoring",
    description:
      "Detects volumetric and protocol DDoS attacks using flow-level features. Trained on CICIDS2017 patterns.",
  },
  {
    name: "C2 Beaconing",
    threatClass: "C2_Beaconing",
    status: "ACTIVE",
    method: "Low-Volume Periodic Beacon Scoring",
    description:
      "Detects command-and-control beaconing patterns using low-volume periodic scoring.",
  },
  {
    name: "DGA/DNS Tunnelling",
    threatClass: "DGA_DNS_Tunneling",
    status: "ACTIVE",
    method: "DNS Anomaly Scoring",
    description:
      "Identifies DNS tunneling using traffic volume and concentration analysis on DNS flows.",
  },
  {
    name: "Encrypted Malware",
    threatClass: "Encrypted_Malware",
    status: "ACTIVE",
    method: "Encrypted Traffic Anomaly Scoring",
    description:
      "Metadata-only detection of malware in encrypted sessions. Never decrypts payloads.",
  },
  {
    name: "Reconnaissance",
    threatClass: "Reconnaissance",
    status: "ACTIVE",
    method: "Scan Pattern Scoring",
    description:
      "Detects port scanning and reconnaissance using passive flow metadata.",
  },
  {
    name: "Data Exfiltration",
    threatClass: "Data_Exfiltration",
    status: "ACTIVE",
    method: "Outbound Transfer Anomaly Scoring",
    description:
      "Identifies potential data exfiltration via unusual outbound traffic patterns.",
  },
];

// ── Synthetic Flow Generator (Demo) ──

let flowCounter = 0;

function randomIp(): string {
  return `${Math.floor(Math.random() * 223) + 1}.${Math.floor(Math.random() * 255)}.${Math.floor(Math.random() * 255)}.${Math.floor(Math.random() * 255)}`;
}

export function generateNormalFlow(): NetworkFlow {
  flowCounter++;
  const now = Date.now();
  return {
    flowId: `FLOW-${String(flowCounter).padStart(7, "0")}`,
    timestamp: now,
    sourceIp: randomIp(),
    destinationIp: `10.0.${Math.floor(Math.random() * 5) + 1}.${Math.floor(Math.random() * 254) + 1}`,
    protocol: ["TCP", "UDP", "ICMP"][Math.floor(Math.random() * 3)],
    sourcePort: Math.floor(Math.random() * 60000) + 1024,
    destinationPort: [80, 443, 8080, 22, 53][Math.floor(Math.random() * 5)],
    flowDuration: Math.random() * 30 + 0.1,
    totalPackets: Math.floor(Math.random() * 500) + 10,
    packetsPerSecond: Math.random() * 100 + 1,
    bytesPerSecond: Math.random() * 50000 + 100,
    totalBytes: Math.floor(Math.random() * 500000) + 1000,
    classification: "Normal",
    confidence: 0,
    severity: "INFO",
    sourceEntropy: Math.random() * 4 + 1,
    destinationConcentration: Math.random() * 0.3,
    packetLengthMean: Math.random() * 1000 + 100,
    packetLengthStd: Math.random() * 200 + 50,
    isSuspicious: false,
    scenario: "normal",
  };
}

export function generateDDoSFlow(): NetworkFlow {
  flowCounter++;
  const now = Date.now();
  const pps = Math.floor(Math.random() * 15000) + 5000;
  return {
    flowId: `FLOW-${String(flowCounter).padStart(7, "0")}`,
    timestamp: now,
    sourceIp: randomIp(),
    destinationIp: `10.0.1.${Math.floor(Math.random() * 10) + 1}`,
    protocol: "UDP",
    sourcePort: Math.floor(Math.random() * 60000) + 1024,
    destinationPort: [80, 443, 53, 8080][Math.floor(Math.random() * 4)],
    flowDuration: Math.random() * 2 + 0.01,
    totalPackets: Math.floor(Math.random() * 200000) + 10000,
    packetsPerSecond: pps,
    bytesPerSecond: pps * (Math.random() * 500 + 50),
    totalBytes: Math.floor(Math.random() * 100000000) + 1000000,
    classification: "Normal",
    confidence: 0,
    severity: "INFO",
    sourceEntropy: Math.random() * 3 + 5,
    destinationConcentration: Math.random() * 0.4 + 0.6,
    packetLengthMean: Math.random() * 200 + 50,
    packetLengthStd: Math.random() * 50 + 10,
    isSuspicious: false,
    scenario: "ddos",
  };
}

export function generateC2Flow(): NetworkFlow {
  flowCounter++;
  return {
    flowId: `FLOW-${String(flowCounter).padStart(7, "0")}`,
    timestamp: Date.now(),
    sourceIp: randomIp(),
    destinationIp: `192.168.${Math.floor(Math.random() * 255)}.${Math.floor(Math.random() * 255)}`,
    protocol: "TCP",
    sourcePort: Math.floor(Math.random() * 1000) + 49000,
    destinationPort: [8443, 4444, 6667, 993][Math.floor(Math.random() * 4)],
    flowDuration: Math.random() * 0.5 + 0.05,
    totalPackets: Math.floor(Math.random() * 20) + 4,
    packetsPerSecond: Math.random() * 30 + 5,
    bytesPerSecond: Math.random() * 5000 + 100,
    totalBytes: Math.floor(Math.random() * 10000) + 500,
    classification: "Normal",
    confidence: 0,
    severity: "INFO",
    sourceEntropy: Math.random() * 2 + 1,
    destinationConcentration: Math.random() * 0.3 + 0.7,
    packetLengthMean: Math.random() * 500 + 100,
    packetLengthStd: Math.random() * 50 + 10,
    isSuspicious: false,
    scenario: "c2",
  };
}

export function generateDNSFlow(): NetworkFlow {
  flowCounter++;
  return {
    flowId: `FLOW-${String(flowCounter).padStart(7, "0")}`,
    timestamp: Date.now(),
    sourceIp: randomIp(),
    destinationIp: "8.8.8.8",
    protocol: "UDP",
    sourcePort: Math.floor(Math.random() * 60000) + 1024,
    destinationPort: 53,
    flowDuration: Math.random() * 0.5 + 0.01,
    totalPackets: Math.floor(Math.random() * 10) + 2,
    packetsPerSecond: Math.random() * 50 + 5,
    bytesPerSecond: Math.random() * 2000 + 100,
    totalBytes: Math.floor(Math.random() * 5000) + 200,
    classification: "Normal",
    confidence: 0,
    severity: "INFO",
    sourceEntropy: Math.random() * 3 + 2,
    destinationConcentration: 0.95,
    packetLengthMean: Math.random() * 200 + 50,
    packetLengthStd: Math.random() * 30 + 5,
    isSuspicious: false,
    scenario: "dns",
  };
}

export function generateEncryptedMalwareFlow(): NetworkFlow {
  flowCounter++;
  const bps = Math.random() * 400000 + 100000;
  return {
    flowId: `FLOW-${String(flowCounter).padStart(7, "0")}`,
    timestamp: Date.now(),
    sourceIp: randomIp(),
    destinationIp: randomIp(),
    protocol: "TCP",
    sourcePort: Math.floor(Math.random() * 1000) + 49000,
    destinationPort: [443, 8443][Math.floor(Math.random() * 2)],
    flowDuration: Math.random() * 100 + 20,
    totalPackets: Math.floor(Math.random() * 5000) + 500,
    packetsPerSecond: Math.random() * 300 + 100,
    bytesPerSecond: bps,
    totalBytes: Math.floor(bps * 40),
    classification: "Normal",
    confidence: 0,
    severity: "INFO",
    sourceEntropy: Math.random() * 3 + 4,
    destinationConcentration: Math.random() * 0.4 + 0.6,
    packetLengthMean: Math.random() * 500 + 800,
    packetLengthStd: Math.random() * 150 + 100,
    isSuspicious: false,
    scenario: "encrypted_malware",
  };
}

export function generateReconFlow(): NetworkFlow {
  flowCounter++;
  return {
    flowId: `FLOW-${String(flowCounter).padStart(7, "0")}`,
    timestamp: Date.now(),
    sourceIp: randomIp(),
    destinationIp: `10.0.${Math.floor(Math.random() * 10)}.${Math.floor(Math.random() * 255)}`,
    protocol: "TCP",
    sourcePort: Math.floor(Math.random() * 1000) + 40000,
    destinationPort: Math.floor(Math.random() * 1000) + 1,
    flowDuration: Math.random() * 0.05 + 0.001,
    totalPackets: Math.floor(Math.random() * 3) + 1,
    packetsPerSecond: Math.random() * 100 + 10,
    bytesPerSecond: Math.random() * 500 + 10,
    totalBytes: Math.floor(Math.random() * 200) + 40,
    classification: "Normal",
    confidence: 0,
    severity: "INFO",
    sourceEntropy: Math.random() * 2 + 4,
    destinationConcentration: Math.random() * 0.1 + 0.01,
    packetLengthMean: Math.random() * 40 + 40,
    packetLengthStd: Math.random() * 8 + 1,
    isSuspicious: false,
    scenario: "recon",
  };
}

export function generateExfilFlow(): NetworkFlow {
  flowCounter++;
  const bps = Math.random() * 500000 + 100000;
  return {
    flowId: `FLOW-${String(flowCounter).padStart(7, "0")}`,
    timestamp: Date.now(),
    sourceIp: `10.0.${Math.floor(Math.random() * 5) + 1}.${Math.floor(Math.random() * 254) + 1}`,
    destinationIp: randomIp(),
    protocol: "TCP",
    sourcePort: Math.floor(Math.random() * 1000) + 40000,
    destinationPort: [443, 8443, 993, 25][Math.floor(Math.random() * 4)],
    flowDuration: Math.random() * 60 + 10,
    totalPackets: Math.floor(Math.random() * 100000) + 5000,
    packetsPerSecond: Math.random() * 2000 + 100,
    bytesPerSecond: bps,
    totalBytes: Math.floor(bps * 30),
    classification: "Normal",
    confidence: 0,
    severity: "INFO",
    sourceEntropy: Math.random() * 2 + 1,
    destinationConcentration: Math.random() * 0.2 + 0.4,
    packetLengthMean: Math.random() * 800 + 500,
    packetLengthStd: Math.random() * 150 + 50,
    isSuspicious: false,
    scenario: "exfil",
  };
}

// Reset flow counter for replay
export function resetFlowCounter(): void {
  flowCounter = 0;
}

export function getFlowGenerator(scenario: string): () => NetworkFlow {
  switch (scenario) {
    case "ddos":
      return generateDDoSFlow;
    case "c2":
      return generateC2Flow;
    case "dns":
      return generateDNSFlow;
    case "encrypted_malware":
      return generateEncryptedMalwareFlow;
    case "recon":
      return generateReconFlow;
    case "exfil":
      return generateExfilFlow;
    default:
      return generateNormalFlow;
  }
}
