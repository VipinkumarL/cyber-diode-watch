// SIH26145 Frontend Service Layer
// In-memory mock data store replacing Convex backend
// Designed for later swap to FastAPI backend

import { useState, useEffect, useCallback, useRef } from "react";
import type {
  NetworkFlow,
  Alert,
  Incident,
  SystemMetrics,
  ThreatClass,
  Severity,
} from "@/lib/types";

// ── In-Memory Stores ──

const flowsStore: NetworkFlow[] = [];
const alertsStore: Alert[] = [];
const incidentsStore: Incident[] = [];
const metricsHistory: SystemMetrics[] = [];

let nextFlowId = 1;
let nextAlertId = 1;
let nextIncidentId = 1;

// ── Flow Operations ──

export function insertFlow(flow: NetworkFlow): NetworkFlow {
  flowsStore.unshift(flow);
  if (flowsStore.length > 2000) flowsStore.length = 2000;
  return flow;
}

export function getRecentFlows(limit = 200): NetworkFlow[] {
  return flowsStore.slice(0, limit);
}

export function getFlowStats() {
  const total = flowsStore.length;
  const normal = flowsStore.filter((f) => f.classification === "Normal").length;
  const suspicious = flowsStore.filter((f) => f.isSuspicious).length;
  const threats = flowsStore.filter(
    (f) => f.classification !== "Normal" && f.isSuspicious,
  ).length;

  // Calculate flows/sec from last second
  const now = Date.now();
  const recentFlows = flowsStore.filter((f) => now - f.timestamp < 1000);
  const flowsPerSecond = recentFlows.length;

  // Average detection latency
  const withLatency = flowsStore.filter((f) => f.confidence > 0);
  const avgLatency =
    withLatency.length > 0
      ? Math.round(
          withLatency.reduce((sum, f) => sum + (f.flowDuration * 100 || 84), 0) /
            withLatency.length,
        )
      : 0;

  // Risk score
  const criticalCount = alertsStore.filter(
    (a) => a.severity === "CRITICAL",
  ).length;
  const highCount = alertsStore.filter((a) => a.severity === "HIGH").length;
  const riskScore = Math.min(
    100,
    Math.round(criticalCount * 15 + highCount * 8 + threats * 2),
  );

  return {
    totalFlows: total,
    normalFlows: normal,
    suspiciousFlows: suspicious,
    threatsDetected: threats,
    criticalAlerts: criticalCount,
    flowsPerSecond,
    avgDetectionLatencyMs: avgLatency,
    riskScore,
  };
}

export function getFlowTimeseries(windowMs = 300000): Array<{
  time: string;
  total: number;
  threats: number;
  normal: number;
}> {
  const now = Date.now();
  const buckets: Record<string, { total: number; threats: number; normal: number }> = {};

  for (const flow of flowsStore) {
    if (now - flow.timestamp > windowMs) continue;
    const key = new Date(flow.timestamp).toLocaleTimeString("en-US", {
      hour12: false,
      minute: "2-digit",
      second: "2-digit",
    });
    if (!buckets[key]) buckets[key] = { total: 0, threats: 0, normal: 0 };
    buckets[key].total++;
    if (flow.classification !== "Normal" && flow.isSuspicious) {
      buckets[key].threats++;
    } else {
      buckets[key].normal++;
    }
  }

  return Object.entries(buckets)
    .map(([time, data]) => ({ time, ...data }))
    .sort((a, b) => a.time.localeCompare(b.time));
}

export function clearFlows(): void {
  flowsStore.length = 0;
}

// ── Alert Operations ──

export function insertAlert(alert: Alert): Alert {
  alertsStore.unshift(alert);
  if (alertsStore.length > 1000) alertsStore.length = 1000;
  return alert;
}

export function getRecentAlerts(limit = 50): Alert[] {
  return alertsStore.slice(0, limit);
}

export function getAlertStats() {
  const total = alertsStore.length;
  const byThreatClass: Record<string, number> = {};
  const bySeverity: Record<string, number> = {};
  let totalConfidence = 0;
  let totalLatency = 0;

  for (const alert of alertsStore) {
    byThreatClass[alert.threatClass] =
      (byThreatClass[alert.threatClass] ?? 0) + 1;
    bySeverity[alert.severity] = (bySeverity[alert.severity] ?? 0) + 1;
    totalConfidence += alert.confidence;
    totalLatency += alert.detectionLatencyMs;
  }

  return {
    total,
    byThreatClass,
    bySeverity,
    avgConfidence: total > 0 ? totalConfidence / total : 0,
    avgLatency: total > 0 ? totalLatency / total : 0,
  };
}

export function getAlertTimeline(windowMs = 300000): Array<{
  time: number;
  count: number;
}> {
  const now = Date.now();
  const buckets: Record<number, number> = {};

  for (const alert of alertsStore) {
    if (now - alert.timestamp > windowMs) continue;
    // Bucket by 10-second intervals
    const bucket = Math.floor(alert.timestamp / 10000) * 10000;
    buckets[bucket] = (buckets[bucket] ?? 0) + 1;
  }

  return Object.entries(buckets)
    .map(([time, count]) => ({ time: Number(time), count }))
    .sort((a, b) => a.time - b.time);
}

export function clearAlerts(): void {
  alertsStore.length = 0;
}

// ── Incident Operations ──

export function insertIncident(
  data: Omit<Incident, "incidentId"> & { incidentId?: string },
): Incident {
  const incident: Incident = {
    incidentId:
      data.incidentId ??
      `INC-${Date.now()}-${Math.random().toString(36).slice(2, 6).toUpperCase()}`,
    ...data,
  };
  incidentsStore.unshift(incident);
  if (incidentsStore.length > 500) incidentsStore.length = 500;
  return incident;
}

export function getIncidents(limit = 50): Incident[] {
  return incidentsStore.slice(0, limit);
}

export function getIncidentStats() {
  const total = incidentsStore.length;
  const byStatus: Record<string, number> = {};
  const bySeverity: Record<string, number> = {};

  for (const inc of incidentsStore) {
    byStatus[inc.status] = (byStatus[inc.status] ?? 0) + 1;
    bySeverity[inc.severity] = (bySeverity[inc.severity] ?? 0) + 1;
  }

  return { total, byStatus, bySeverity };
}

export function clearIncidents(): void {
  incidentsStore.length = 0;
}

// ── Metrics Operations ──

export function recordMetrics(): SystemMetrics {
  const stats = getFlowStats();
  const alertStats = getAlertStats();
  const metrics: SystemMetrics = {
    timestamp: Date.now(),
    ...stats,
    totalAlerts: alertStats.total,
    totalIncidents: incidentsStore.length,
  };
  metricsHistory.unshift(metrics);
  if (metricsHistory.length > 300) metricsHistory.length = 300;
  return metrics;
}

export function getLatestMetrics(): SystemMetrics | null {
  return metricsHistory[0] ?? null;
}

export function getMetricsTimeseries(windowMs = 300000): SystemMetrics[] {
  const now = Date.now();
  return metricsHistory.filter((m) => now - m.timestamp <= windowMs);
}

// ── React Hooks for Reactive Data ──

/**
 * Subscribe to reactive flow data. Polls every `intervalMs`.
 */
export function useFlowData(limit = 200, intervalMs = 1000) {
  const [flows, setFlows] = useState<NetworkFlow[]>([]);
  const [stats, setStats] = useState<ReturnType<typeof getFlowStats> | null>(null);

  useEffect(() => {
    const update = () => {
      setFlows(getRecentFlows(limit));
      setStats(getFlowStats());
    };
    update();
    const timer = setInterval(update, intervalMs);
    return () => clearInterval(timer);
  }, [limit, intervalMs]);

  return { flows, stats };
}

/**
 * Subscribe to reactive alert data.
 */
export function useAlertData(limit = 50, intervalMs = 1000) {
  const [alerts, setAlerts] = useState<Alert[]>([]);
  const [stats, setStats] = useState<ReturnType<typeof getAlertStats> | null>(null);

  useEffect(() => {
    const update = () => {
      setAlerts(getRecentAlerts(limit));
      setStats(getAlertStats());
    };
    update();
    const timer = setInterval(update, intervalMs);
    return () => clearInterval(timer);
  }, [limit, intervalMs]);

  return { alerts, stats };
}

/**
 * Subscribe to reactive incident data.
 */
export function useIncidentData(limit = 50, intervalMs = 1000) {
  const [incidents, setIncidents] = useState<Incident[]>([]);
  const [stats, setStats] = useState<ReturnType<typeof getIncidentStats> | null>(null);

  useEffect(() => {
    const update = () => {
      setIncidents(getIncidents(limit));
      setStats(getIncidentStats());
    };
    update();
    const timer = setInterval(update, intervalMs);
    return () => clearInterval(timer);
  }, [limit, intervalMs]);

  return { incidents, stats };
}

/**
 * Subscribe to flow timeseries data.
 */
export function useFlowTimeseries(windowMs = 300000, intervalMs = 2000) {
  const [data, setData] = useState<ReturnType<typeof getFlowTimeseries>>([]);

  useEffect(() => {
    const update = () => setData(getFlowTimeseries(windowMs));
    update();
    const timer = setInterval(update, intervalMs);
    return () => clearInterval(timer);
  }, [windowMs, intervalMs]);

  return data;
}

/**
 * Subscribe to alert timeline data.
 */
export function useAlertTimeline(windowMs = 300000, intervalMs = 2000) {
  const [data, setData] = useState<ReturnType<typeof getAlertTimeline>>([]);

  useEffect(() => {
    const update = () => setData(getAlertTimeline(windowMs));
    update();
    const timer = setInterval(update, intervalMs);
    return () => clearInterval(timer);
  }, [windowMs, intervalMs]);

  return data;
}

/**
 * Subscribe to latest metrics.
 */
export function useMetrics(intervalMs = 2000) {
  const [metrics, setMetrics] = useState<SystemMetrics | null>(null);

  useEffect(() => {
    const update = () => setMetrics(getLatestMetrics());
    update();
    const timer = setInterval(update, intervalMs);
    return () => clearInterval(timer);
  }, [intervalMs]);

  return metrics;
}

/**
 * Force-clear all data stores (for reset).
 */
export function clearAllData(): void {
  clearFlows();
  clearAlerts();
  clearIncidents();
  metricsHistory.length = 0;
  nextFlowId = 1;
  nextAlertId = 1;
  nextIncidentId = 1;
}

/**
 * Get total counts for the header/nav.
 */
export function useDataCounts(intervalMs = 1000) {
  const [counts, setCounts] = useState({
    totalFlows: 0,
    totalAlerts: 0,
    totalIncidents: 0,
  });

  useEffect(() => {
    const update = () => {
      setCounts({
        totalFlows: flowsStore.length,
        totalAlerts: alertsStore.length,
        totalIncidents: incidentsStore.length,
      });
    };
    update();
    const timer = setInterval(update, intervalMs);
    return () => clearInterval(timer);
  }, [intervalMs]);

  return counts;
}
