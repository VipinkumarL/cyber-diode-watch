// ═══════════════════════════════════════════════════════════════════
// SIH26145 — Service Layer
// Frontend ↔ FastAPI Backend Abstraction
//
// Architecture:
//   1. Configuration     — reads VITE_API_BASE_URL from env
//   2. REST Client       — typed fetch wrappers for FastAPI endpoints
//   3. WebSocket Client  — live detection event stream
//   4. Mock Data Store   — in-memory fallback when no backend
//   5. Data Access       — unified layer: API-first, mock fallback
//   6. React Hooks       — reactive subscriptions for components
//
// When VITE_API_BASE_URL is set, all reads attempt the FastAPI
// backend first and silently fall back to the in-memory mock
// store if the backend is unavailable. Writes always persist
// locally and fire-and-forget to the backend when available.
// ═══════════════════════════════════════════════════════════════════

import { useState, useEffect, useCallback, useRef } from "react";
import type {
  NetworkFlow,
  Alert,
  Incident,
  SystemMetrics,
  ThreatClass,
  Severity,
  DetectorInfo,
} from "@/lib/types";

// ─────────────────────────────────────────────────────────────────
// 1. CONFIGURATION
// ─────────────────────────────────────────────────────────────────

/**
 * FastAPI backend base URL. Set via VITE_API_BASE_URL env var.
 * Defaults to the local FastAPI backend. Set to "" to run in mock-only mode.
 * Example: VITE_API_BASE_URL=http://127.0.0.1:8000
 */
const API_BASE_URL: string = import.meta.env.VITE_API_BASE_URL ?? "http://127.0.0.1:8000";

/**
 * WebSocket URL. Auto-derived from API_BASE_URL if not explicitly set.
 * Example: ws://127.0.0.1:8000/ws/traffic
 */
const WS_URL: string =
  import.meta.env.VITE_WS_URL ??
  (API_BASE_URL.length > 0
    ? API_BASE_URL.replace(/^http/, "ws") + "/ws/traffic"
    : "");

/** Whether a live backend is configured */
export const USE_BACKEND = API_BASE_URL.length > 0;

/** Exported for health/status display */
export const API_BASE = API_BASE_URL;

// ─────────────────────────────────────────────────────────────────
// 2. REST CLIENT — FastAPI endpoints
// ─────────────────────────────────────────────────────────────────

/**
 * Standard error from the backend API.
 */
export class ApiError extends Error {
  status: number;
  constructor(message: string, status: number) {
    super(message);
    this.name = "ApiError";
    this.status = status;
  }
}

/**
 * Generic typed GET request to the FastAPI backend.
 * Returns parsed JSON of type T.
 */
async function apiGet<T>(path: string, params?: Record<string, string>): Promise<T> {
  const url = new URL(path, API_BASE_URL);
  if (params) {
    for (const [k, v] of Object.entries(params)) {
      url.searchParams.set(k, v);
    }
  }
  const res = await fetch(url.toString());
  if (!res.ok) {
    const body = await res.text().catch(() => "");
    throw new ApiError(`GET ${path} failed (${res.status}): ${body}`, res.status);
  }
  return res.json() as Promise<T>;
}

/**
 * Generic typed POST request to the FastAPI backend.
 */
async function apiPost<T>(path: string, body?: unknown): Promise<T> {
  const res = await fetch(`${API_BASE_URL}${path}`, {
    method: "POST",
    headers: body != null ? { "Content-Type": "application/json" } : undefined,
    body: body != null ? JSON.stringify(body) : undefined,
  });
  if (!res.ok) {
    const text = await res.text().catch(() => "");
    throw new ApiError(`POST ${path} failed (${res.status}): ${text}`, res.status);
  }
  return res.json() as Promise<T>;
}

// ─── FastAPI endpoint contracts ──────────────────────────────────
//
// GET  /api/health           → { status, model_loaded, db_status }
// GET  /api/flows?limit=N    → { flows: NetworkFlow[], stats: FlowStats }
// GET  /api/alerts?limit=N   → { alerts: Alert[], stats: AlertStats }
// GET  /api/alerts/:id       → Alert
// GET  /api/incidents?limit=N → { incidents: Incident[], stats: IncidentStats }
// GET  /api/incidents/:id    → Incident
// GET  /api/statistics       → { flows: FlowStats, alerts: AlertStats, incidents: IncidentStats }
// GET  /api/metrics          → SystemMetrics
// GET  /api/detectors        → DetectorInfo[]
// POST /api/replay/start     → { status: "running" }
// POST /api/replay/stop      → { status: "stopped" }
// POST /api/replay/pause     → { status: "paused" }
// POST /api/replay/reset     → { status: "idle" }
// POST /api/predict          → { alert: Alert | null, updatedFlow: NetworkFlow, detectionTimeMs: number }
// WS   /ws/traffic           → stream of WebSocketMessage events
//
// ─────────────────────────────────────────────────────────────────

export interface FlowStats {
  totalFlows: number;
  normalFlows: number;
  suspiciousFlows: number;
  threatsDetected: number;
  criticalAlerts: number;
  flowsPerSecond: number;
  avgDetectionLatencyMs: number;
  riskScore: number;
}

export interface AlertStats {
  total: number;
  byThreatClass: Record<string, number>;
  bySeverity: Record<string, number>;
  avgConfidence: number;
  avgLatency: number;
}

export interface IncidentStats {
  total: number;
  byStatus: Record<string, number>;
  bySeverity: Record<string, number>;
}

export interface FlowsResponse {
  flows: NetworkFlow[];
  stats: FlowStats;
}

export interface AlertsResponse {
  alerts: Alert[];
  stats: AlertStats;
}

export interface IncidentsResponse {
  incidents: Incident[];
  stats: IncidentStats;
}

export interface StatisticsResponse {
  flows: FlowStats;
  alerts: AlertStats;
  incidents: IncidentStats;
}

export interface HealthResponse {
  status: "ok" | "degraded" | "error";
  model_loaded: boolean;
  db_status: string;
}

export interface ReplayStartRequest {
  scenario: string;
  speed: number;
  dataset: string;
}

export interface PredictRequest {
  flow: NetworkFlow;
}

export interface PredictResponse {
  alert: Alert | null;
  updatedFlow: NetworkFlow;
  detectionTimeMs: number;
}

/** WebSocket message types from /ws/traffic */
export type WebSocketMessage =
  | { type: "flow"; data: NetworkFlow }
  | { type: "alert"; data: Alert }
  | { type: "incident"; data: Incident }
  | { type: "metrics"; data: SystemMetrics }
  | { type: "replay_status"; data: { status: string } };

// ── Client functions (used when USE_BACKEND = true) ──────────────

export async function fetchHealth(): Promise<HealthResponse> {
  return apiGet<HealthResponse>("/api/health");
}

export async function fetchFlowsApi(limit = 200): Promise<FlowsResponse> {
  return apiGet<FlowsResponse>("/api/flows", { limit: String(limit) });
}

export async function fetchAlertsApi(limit = 50): Promise<AlertsResponse> {
  return apiGet<AlertsResponse>("/api/alerts", { limit: String(limit) });
}

export async function fetchAlertApi(alertId: string): Promise<Alert> {
  return apiGet<Alert>(`/api/alerts/${encodeURIComponent(alertId)}`);
}

export async function fetchIncidentsApi(limit = 50): Promise<IncidentsResponse> {
  return apiGet<IncidentsResponse>("/api/incidents", { limit: String(limit) });
}

export async function fetchIncidentApi(incidentId: string): Promise<Incident> {
  return apiGet<Incident>(`/api/incidents/${encodeURIComponent(incidentId)}`);
}

export async function fetchStatisticsApi(): Promise<StatisticsResponse> {
  return apiGet<StatisticsResponse>("/api/statistics");
}

export async function fetchMetricsApi(): Promise<SystemMetrics> {
  return apiGet<SystemMetrics>("/api/metrics");
}

export async function fetchDetectorsApi(): Promise<DetectorInfo[]> {
  return apiGet<DetectorInfo[]>("/api/detectors");
}

export async function startReplayApi(req: ReplayStartRequest): Promise<{ status: string }> {
  return apiPost<{ status: string }>("/api/replay/start", req);
}

export async function stopReplayApi(): Promise<{ status: string }> {
  return apiPost<{ status: string }>("/api/replay/stop");
}

export async function pauseReplayApi(): Promise<{ status: string }> {
  return apiPost<{ status: string }>("/api/replay/pause");
}

export async function resetReplayApi(): Promise<{ status: string }> {
  return apiPost<{ status: string }>("/api/replay/reset");
}

export async function predictApi(req: PredictRequest): Promise<PredictResponse> {
  return apiPost<PredictResponse>("/api/predict", req);
}

// ─────────────────────────────────────────────────────────────────
// 3. WEBSOCKET CLIENT — Live detection event stream
// ─────────────────────────────────────────────────────────────────

type WsStatus = "connecting" | "connected" | "disconnected";

let wsInstance: WebSocket | null = null;
let wsStatus: WsStatus = "disconnected";
const wsListeners = new Set<(msg: WebSocketMessage) => void>();
const wsStatusListeners = new Set<(status: WsStatus) => void>();

function setWsStatus(s: WsStatus) {
  wsStatus = s;
  for (const fn of wsStatusListeners) fn(s);
}

/**
 * Connect to the FastAPI WebSocket at /ws/traffic.
 * Idempotent — returns existing connection if already open.
 * Only active when USE_BACKEND is true.
 */
export function connectWebSocket(): void {
  if (!USE_BACKEND || !WS_URL) return;
  if (
    wsInstance &&
    (wsInstance.readyState === WebSocket.OPEN ||
      wsInstance.readyState === WebSocket.CONNECTING)
  ) {
    return;
  }
  setWsStatus("connecting");
  const ws = new WebSocket(WS_URL);
  wsInstance = ws;

  ws.onopen = () => setWsStatus("connected");

  ws.onmessage = (event) => {
    try {
      const msg: WebSocketMessage = JSON.parse(event.data as string);
      for (const fn of wsListeners) fn(msg);
    } catch {
      // Ignore malformed messages
    }
  };

  ws.onclose = () => {
    setWsStatus("disconnected");
    wsInstance = null;
    // Auto-reconnect after 3 seconds
    if (USE_BACKEND) {
      setTimeout(connectWebSocket, 3000);
    }
  };

  ws.onerror = () => {
    ws.close();
  };
}

/**
 * Disconnect the WebSocket cleanly.
 */
export function disconnectWebSocket(): void {
  if (wsInstance) {
    wsInstance.close();
    wsInstance = null;
  }
  setWsStatus("disconnected");
}

/**
 * Subscribe to WebSocket messages. Returns an unsubscribe function.
 */
export function onWebSocketMessage(
  cb: (msg: WebSocketMessage) => void,
): () => void {
  wsListeners.add(cb);
  return () => {
    wsListeners.delete(cb);
  };
}

/**
 * Subscribe to WebSocket connection status changes.
 */
export function onWebSocketStatus(
  cb: (status: WsStatus) => void,
): () => void {
  wsStatusListeners.add(cb);
  return () => {
    wsStatusListeners.delete(cb);
  };
}

/**
 * Get current WebSocket connection status.
 */
export function getWebSocketStatus(): WsStatus {
  return wsStatus;
}

// ─────────────────────────────────────────────────────────────────
// 4. MOCK DATA STORE — In-memory fallback
// ─────────────────────────────────────────────────────────────────

const flowsStore: NetworkFlow[] = [];
const alertsStore: Alert[] = [];
const incidentsStore: Incident[] = [];
const metricsHistory: SystemMetrics[] = [];

let nextFlowId = 1;
let nextAlertId = 1;
let nextIncidentId = 1;

// ── Flow Operations (Mock) ──

function mockInsertFlow(flow: NetworkFlow): NetworkFlow {
  flowsStore.unshift(flow);
  if (flowsStore.length > 2000) flowsStore.length = 2000;
  return flow;
}

function mockGetRecentFlows(limit = 200): NetworkFlow[] {
  return flowsStore.slice(0, limit);
}

function mockGetFlowStats(): FlowStats {
  const total = flowsStore.length;
  const normal = flowsStore.filter((f) => f.classification === "Normal").length;
  const suspicious = flowsStore.filter((f) => f.isSuspicious).length;
  const threats = flowsStore.filter(
    (f) => f.classification !== "Normal" && f.isSuspicious,
  ).length;

  const now = Date.now();
  const recentFlows = flowsStore.filter((f) => now - f.timestamp < 1000);
  const flowsPerSecond = recentFlows.length;

  const withLatency = flowsStore.filter((f) => f.confidence > 0);
  const avgLatency =
    withLatency.length > 0
      ? Math.round(
          withLatency.reduce((sum, f) => sum + (f.flowDuration * 100 || 84), 0) /
            withLatency.length,
        )
      : 0;

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

function mockGetFlowTimeseries(windowMs = 300000): Array<{
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

// ── Alert Operations (Mock) ──

function mockInsertAlert(alert: Alert): Alert {
  alertsStore.unshift(alert);
  if (alertsStore.length > 1000) alertsStore.length = 1000;
  return alert;
}

function mockGetRecentAlerts(limit = 50): Alert[] {
  return alertsStore.slice(0, limit);
}

function mockGetAlertStats(): AlertStats {
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

function mockGetAlertTimeline(windowMs = 300000): Array<{
  time: number;
  count: number;
}> {
  const now = Date.now();
  const buckets: Record<number, number> = {};

  for (const alert of alertsStore) {
    if (now - alert.timestamp > windowMs) continue;
    const bucket = Math.floor(alert.timestamp / 10000) * 10000;
    buckets[bucket] = (buckets[bucket] ?? 0) + 1;
  }

  return Object.entries(buckets)
    .map(([time, count]) => ({ time: Number(time), count }))
    .sort((a, b) => a.time - b.time);
}

// ── Incident Operations (Mock) ──

function mockInsertIncident(
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

function mockGetIncidents(limit = 50): Incident[] {
  return incidentsStore.slice(0, limit);
}

function mockGetIncidentStats(): IncidentStats {
  const total = incidentsStore.length;
  const byStatus: Record<string, number> = {};
  const bySeverity: Record<string, number> = {};

  for (const inc of incidentsStore) {
    byStatus[inc.status] = (byStatus[inc.status] ?? 0) + 1;
    bySeverity[inc.severity] = (bySeverity[inc.severity] ?? 0) + 1;
  }

  return { total, byStatus, bySeverity };
}

// ── Metrics Operations (Mock) ──

function mockRecordMetrics(): SystemMetrics {
  const stats = mockGetFlowStats();
  const alertStats = mockGetAlertStats();
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

function mockGetLatestMetrics(): SystemMetrics | null {
  return metricsHistory[0] ?? null;
}

// ─────────────────────────────────────────────────────────────────
// 5. DATA ACCESS LAYER — Unified API / Mock routing
// ─────────────────────────────────────────────────────────────────
//
// Write functions: always persist to local mock store, AND
// fire-and-forget to the FastAPI backend when available.
//
// Read functions: defined in section 6 (React hooks) as async
// operations that try the API first, then fall back to mock store.
// ─────────────────────────────────────────────────────────────────

// ── Write Operations (local + backend) ──

export function insertFlow(flow: NetworkFlow): NetworkFlow {
  mockInsertFlow(flow);
  // Fire-and-forget to backend
  if (USE_BACKEND) {
    apiPost("/api/flows", flow).catch(() => {});
  }
  return flow;
}

export function insertAlert(alert: Alert): Alert {
  mockInsertAlert(alert);
  // Backend stores alerts via predict endpoint or alert creation; no standalone POST
  return alert;
}

export function insertIncident(
  data: Omit<Incident, "incidentId"> & { incidentId?: string },
): Incident {
  const incident = mockInsertIncident(data);
  // Backend stores incidents via alert creation; no standalone POST
  return incident;
}

export function clearAllData(): void {
  flowsStore.length = 0;
  alertsStore.length = 0;
  incidentsStore.length = 0;
  metricsHistory.length = 0;
  nextFlowId = 1;
  nextAlertId = 1;
  nextIncidentId = 1;
  // Also reset backend
  if (USE_BACKEND) {
    apiPost("/api/replay/reset").catch(() => {});
  }
}

// ── Read Operations (exposed for non-hook consumers) ──

/**
 * Get flows from mock store (synchronous fallback).
 * Prefer the useFlowData hook which tries the API first.
 */
export function getRecentFlows(limit = 200): NetworkFlow[] {
  return mockGetRecentFlows(limit);
}

export function getFlowStats(): FlowStats {
  return mockGetFlowStats();
}

export function getFlowTimeseries(windowMs = 300000): Array<{
  time: string;
  total: number;
  threats: number;
  normal: number;
}> {
  return mockGetFlowTimeseries(windowMs);
}

export function getRecentAlerts(limit = 50): Alert[] {
  return mockGetRecentAlerts(limit);
}

export function getAlertStats(): AlertStats {
  return mockGetAlertStats();
}

export function getAlertTimeline(windowMs = 300000): Array<{
  time: number;
  count: number;
}> {
  return mockGetAlertTimeline(windowMs);
}

export function getIncidents(limit = 50): Incident[] {
  return mockGetIncidents(limit);
}

export function getIncidentStats(): IncidentStats {
  return mockGetIncidentStats();
}

export function getLatestMetrics(): SystemMetrics | null {
  return mockGetLatestMetrics();
}

// ─────────────────────────────────────────────────────────────────
// 6. REACT HOOKS — Reactive subscriptions for components
// ─────────────────────────────────────────────────────────────────
//
// Strategy:
//   - Try fetching from FastAPI backend (async)
//   - On success: update state with backend data
//   - On failure: fall back to mock store (sync)
//   - This provides real backend data when available,
//     and graceful degradation when backend is offline.
// ─────────────────────────────────────────────────────────────────

/**
 * Compute flow timeseries from an array of flows.
 * Used by both mock fallback and API-fetched data.
 */
function computeFlowTimeseries(
  flows: NetworkFlow[],
  windowMs = 300000,
): Array<{ time: string; total: number; threats: number; normal: number }> {
  const now = Date.now();
  const buckets: Record<string, { total: number; threats: number; normal: number }> = {};

  for (const flow of flows) {
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

/**
 * Compute alert timeline from an array of alerts.
 */
function computeAlertTimeline(
  alerts: Alert[],
  windowMs = 300000,
): Array<{ time: number; count: number }> {
  const now = Date.now();
  const buckets: Record<number, number> = {};

  for (const alert of alerts) {
    if (now - alert.timestamp > windowMs) continue;
    const bucket = Math.floor(alert.timestamp / 10000) * 10000;
    buckets[bucket] = (buckets[bucket] ?? 0) + 1;
  }

  return Object.entries(buckets)
    .map(([time, count]) => ({ time: Number(time), count }))
    .sort((a, b) => a.time - b.time);
}

/**
 * Subscribe to reactive flow data.
 * Tries FastAPI backend first, falls back to mock store.
 */
export function useFlowData(limit = 200, intervalMs = 1000) {
  const [flows, setFlows] = useState<NetworkFlow[]>([]);
  const [stats, setStats] = useState<FlowStats | null>(null);
  const flowsRef = useRef(flows);

  useEffect(() => {
    let cancelled = false;

    const update = async () => {
      if (USE_BACKEND) {
        try {
          const res = await fetchFlowsApi(limit);
          if (!cancelled) {
            setFlows(res.flows);
            setStats(res.stats);
            flowsRef.current = res.flows;
            return;
          }
        } catch {
          // Backend unavailable — fall through to mock
        }
      }
      // Mock fallback
      const mockFlows = mockGetRecentFlows(limit);
      const mockStats = mockGetFlowStats();
      if (!cancelled) {
        setFlows(mockFlows);
        setStats(mockStats);
        flowsRef.current = mockFlows;
      }
    };

    update();
    const timer = setInterval(update, intervalMs);
    return () => {
      cancelled = true;
      clearInterval(timer);
    };
  }, [limit, intervalMs]);

  return { flows, stats, flowsRef };
}

/**
 * Subscribe to reactive alert data.
 * Tries FastAPI backend first, falls back to mock store.
 */
export function useAlertData(limit = 50, intervalMs = 1000) {
  const [alerts, setAlerts] = useState<Alert[]>([]);
  const [stats, setStats] = useState<AlertStats | null>(null);

  useEffect(() => {
    let cancelled = false;

    const update = async () => {
      if (USE_BACKEND) {
        try {
          const res = await fetchAlertsApi(limit);
          if (!cancelled) {
            setAlerts(res.alerts);
            setStats(res.stats);
            return;
          }
        } catch {
          // Fall through to mock
        }
      }
      // Mock fallback
      const mockAlerts = mockGetRecentAlerts(limit);
      const mockStats = mockGetAlertStats();
      if (!cancelled) {
        setAlerts(mockAlerts);
        setStats(mockStats);
      }
    };

    update();
    const timer = setInterval(update, intervalMs);
    return () => {
      cancelled = true;
      clearInterval(timer);
    };
  }, [limit, intervalMs]);

  return { alerts, stats };
}

/**
 * Subscribe to reactive incident data.
 * Tries FastAPI backend first, falls back to mock store.
 */
export function useIncidentData(limit = 50, intervalMs = 1000) {
  const [incidents, setIncidents] = useState<Incident[]>([]);
  const [stats, setStats] = useState<IncidentStats | null>(null);

  useEffect(() => {
    let cancelled = false;

    const update = async () => {
      if (USE_BACKEND) {
        try {
          const res = await fetchIncidentsApi(limit);
          if (!cancelled) {
            setIncidents(res.incidents);
            setStats(res.stats);
            return;
          }
        } catch {
          // Fall through to mock
        }
      }
      // Mock fallback
      const mockIncidents = mockGetIncidents(limit);
      const mockStats = mockGetIncidentStats();
      if (!cancelled) {
        setIncidents(mockIncidents);
        setStats(mockStats);
      }
    };

    update();
    const timer = setInterval(update, intervalMs);
    return () => {
      cancelled = true;
      clearInterval(timer);
    };
  }, [limit, intervalMs]);

  return { incidents, stats };
}

/**
 * Subscribe to flow timeseries data for charts.
 * Tries FastAPI backend first (computes timeseries from fetched flows),
 * falls back to mock store.
 */
export function useFlowTimeseries(windowMs = 300000, intervalMs = 2000) {
  const [data, setData] = useState<Array<{
    time: string;
    total: number;
    threats: number;
    normal: number;
  }>>([]);

  useEffect(() => {
    let cancelled = false;

    const update = async () => {
      if (USE_BACKEND) {
        try {
          const res = await fetchFlowsApi(2000);
          if (!cancelled) {
            setData(computeFlowTimeseries(res.flows, windowMs));
            return;
          }
        } catch {
          // Fall through to mock
        }
      }
      // Mock fallback
      if (!cancelled) {
        setData(mockGetFlowTimeseries(windowMs));
      }
    };

    update();
    const timer = setInterval(update, intervalMs);
    return () => {
      cancelled = true;
      clearInterval(timer);
    };
  }, [windowMs, intervalMs]);

  return data;
}

/**
 * Subscribe to alert timeline data for charts.
 * Tries FastAPI backend first, falls back to mock store.
 */
export function useAlertTimeline(windowMs = 300000, intervalMs = 2000) {
  const [data, setData] = useState<Array<{ time: number; count: number }>>([]);

  useEffect(() => {
    let cancelled = false;

    const update = async () => {
      if (USE_BACKEND) {
        try {
          const res = await fetchAlertsApi(500);
          if (!cancelled) {
            setData(computeAlertTimeline(res.alerts, windowMs));
            return;
          }
        } catch {
          // Fall through to mock
        }
      }
      // Mock fallback
      if (!cancelled) {
        setData(mockGetAlertTimeline(windowMs));
      }
    };

    update();
    const timer = setInterval(update, intervalMs);
    return () => {
      cancelled = true;
      clearInterval(timer);
    };
  }, [windowMs, intervalMs]);

  return data;
}

/**
 * Subscribe to latest system metrics.
 * Tries FastAPI backend first, falls back to mock store.
 */
export function useMetrics(intervalMs = 2000) {
  const [metrics, setMetrics] = useState<SystemMetrics | null>(null);

  useEffect(() => {
    let cancelled = false;

    const update = async () => {
      if (USE_BACKEND) {
        try {
          const res = await fetchMetricsApi();
          if (!cancelled) {
            setMetrics(res);
            return;
          }
        } catch {
          // Fall through to mock
        }
      }
      // Mock fallback
      if (!cancelled) {
        setMetrics(mockGetLatestMetrics());
      }
    };

    update();
    const timer = setInterval(update, intervalMs);
    return () => {
      cancelled = true;
      clearInterval(timer);
    };
  }, [intervalMs]);

  return metrics;
}

/**
 * Subscribe to data counts for the top nav.
 * Tries FastAPI backend first, falls back to local counts.
 */
export function useDataCounts(intervalMs = 1000) {
  const [counts, setCounts] = useState({
    totalFlows: 0,
    totalAlerts: 0,
    totalIncidents: 0,
  });

  useEffect(() => {
    let cancelled = false;

    const update = async () => {
      if (USE_BACKEND) {
        try {
          const res = await fetchStatisticsApi();
          if (!cancelled) {
            setCounts({
              totalFlows: res.flows.totalFlows,
              totalAlerts: res.alerts.total,
              totalIncidents: res.incidents.total,
            });
            return;
          }
        } catch {
          // Fall through to mock
        }
      }
      // Mock fallback
      if (!cancelled) {
        setCounts({
          totalFlows: flowsStore.length,
          totalAlerts: alertsStore.length,
          totalIncidents: incidentsStore.length,
        });
      }
    };

    update();
    const timer = setInterval(update, intervalMs);
    return () => {
      cancelled = true;
      clearInterval(timer);
    };
  }, [intervalMs]);

  return counts;
}

/**
 * Subscribe to WebSocket connection status.
 */
export function useWebSocketStatus(): WsStatus {
  const [status, setStatus] = useState<WsStatus>(getWebSocketStatus());

  useEffect(() => {
    if (USE_BACKEND) connectWebSocket();
    return onWebSocketStatus(setStatus);
  }, []);

  return status;
}
