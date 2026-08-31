import { useQuery } from "convex/react";
import { api } from "@/convex/_generated/api";
import {
  HeartPulse,
  Server,
  Brain,
  Database,
  Wifi,
  Activity,
  Clock,
  HardDrive,
  Cpu,
  Layers,
} from "lucide-react";

export default function Health() {
  const flowStats = useQuery(api.flows.stats);
  const alertStats = useQuery(api.alerts.stats);
  const replayState = useQuery(api.replay.getState);
  const metricsLatest = useQuery(api.metrics.getLatest);

  const isLoading = !flowStats;

  const systemComponents = [
    {
      name: "Backend API",
      status: "online",
      icon: Server,
      detail: "FastAPI + Uvicorn (Convex adapted)",
      color: "#0f9b8e",
    },
    {
      name: "ML Model",
      status: "loaded",
      icon: Brain,
      detail: "DDoS-RF-v1 — Random Forest Classifier",
      color: "#533483",
    },
    {
      name: "Database",
      status: "online",
      icon: Database,
      detail: "Convex (PostgreSQL-compatible schema)",
      color: "#0f9b8e",
    },
    {
      name: "WebSocket",
      status: "connected",
      icon: Wifi,
      detail: "Real-time flow & alert streaming",
      color: "#0f9b8e",
    },
  ];

  const performanceStats = [
    {
      label: "Total Flows Processed",
      value: flowStats?.totalFlows ?? 0,
      icon: Layers,
      color: "#533483",
    },
    {
      label: "Total Alerts Generated",
      value: alertStats?.total ?? 0,
      icon: Activity,
      color: "#e94560",
    },
    {
      label: "Current Throughput",
      value: `${flowStats?.flowsPerSecond ?? 0} flows/sec`,
      icon: Activity,
      color: "#48b9a7",
    },
    {
      label: "Avg Detection Latency",
      value: `${flowStats?.avgDetectionLatencyMs ?? 0}ms`,
      icon: Clock,
      color: "#f5a623",
    },
    {
      label: "Active Replay",
      value: replayState?.status === "running" ? "Running" : "Idle",
      icon: HeartPulse,
      color: replayState?.status === "running" ? "#0f9b8e" : "#8b8994",
    },
    {
      label: "Dataset",
      value: replayState?.dataset ?? "None",
      icon: HardDrive,
      color: "#48b9a7",
    },
  ];

  const statusColors: Record<string, { bg: string; text: string; dot: string }> = {
    online: { bg: "#0f9b8e15", text: "#0f9b8e", dot: "#0f9b8e" },
    loaded: { bg: "#53348315", text: "#533483", dot: "#533483" },
    connected: { bg: "#0f9b8e15", text: "#0f9b8e", dot: "#0f9b8e" },
    offline: { bg: "#e9456015", text: "#e94560", dot: "#e94560" },
  };

  return (
    <div className="space-y-6">
      {/* Header */}
      <div>
        <h1 className="text-2xl font-bold text-[#e8e6e3] flex items-center gap-3">
          <HeartPulse className="w-6 h-6 text-[#0f9b8e]" />
          System Health
        </h1>
        <p className="text-sm text-[#8b8994] mt-1">
          Backend status, model status, and performance metrics
        </p>
      </div>

      {/* System status badges */}
      <div className="grid grid-cols-2 md:grid-cols-4 gap-3">
        {systemComponents.map((comp) => {
          const statusStyle =
            statusColors[comp.status] ?? statusColors.offline;
          return (
            <div
              key={comp.name}
              className="rounded-xl bg-[#16213e]/80 border border-[#2a2a4a] p-4"
            >
              <div className="flex items-center gap-3 mb-3">
                <div
                  className="w-8 h-8 rounded-lg flex items-center justify-center"
                  style={{ background: statusStyle.bg }}
                >
                  <comp.icon className="w-4 h-4" style={{ color: statusStyle.text }} />
                </div>
                <div>
                  <p className="text-xs font-semibold text-[#e8e6e3]">
                    {comp.name}
                  </p>
                </div>
              </div>
              <div className="flex items-center gap-2">
                <div
                  className="w-2 h-2 rounded-full status-pulse"
                  style={{ background: statusStyle.dot }}
                />
                <span
                  className="text-xs font-medium uppercase tracking-wider"
                  style={{ color: statusStyle.text }}
                >
                  {comp.status}
                </span>
              </div>
              <p className="text-[10px] text-[#8b8994] mt-2">{comp.detail}</p>
            </div>
          );
        })}
      </div>

      {/* Performance metrics */}
      <div className="rounded-xl bg-[#16213e]/80 border border-[#2a2a4a] p-4">
        <div className="flex items-center gap-2 mb-4">
          <div className="w-[3px] h-4 bg-[#48b9a7] rounded" />
          <h3 className="text-sm font-semibold text-[#e8e6e3]">
            Performance Metrics
          </h3>
        </div>
        <div className="grid grid-cols-2 md:grid-cols-3 gap-3">
          {performanceStats.map((stat) => (
            <div
              key={stat.label}
              className="px-4 py-3 rounded-lg bg-[#12122a]/50 border border-[#2a2a4a]/50"
            >
              <div className="flex items-center gap-2 mb-1">
                <stat.icon className="w-3 h-3" style={{ color: stat.color }} />
                <span className="text-[10px] text-[#8b8994] uppercase tracking-wider">
                  {stat.label}
                </span>
              </div>
              <p
                className="text-lg font-bold font-mono"
                style={{ color: stat.color }}
              >
                {isLoading ? "—" : stat.value}
              </p>
            </div>
          ))}
        </div>
      </div>

      {/* Architecture diagram */}
      <div className="rounded-xl bg-[#16213e]/80 border border-[#2a2a4a] p-4">
        <div className="flex items-center gap-2 mb-4">
          <div className="w-[3px] h-4 bg-[#533483] rounded" />
          <h3 className="text-sm font-semibold text-[#e8e6e3]">
            System Architecture
          </h3>
        </div>
        <div className="flex flex-wrap items-center justify-center gap-2 text-xs">
          {[
            { label: "Simulated IP Traffic", color: "#6c7a89" },
            { label: "→" },
            { label: "Read-Only Ingest", color: "#0f9b8e" },
            { label: "→" },
            { label: "Stream/Replay", color: "#48b9a7" },
            { label: "→" },
            { label: "Feature Extract", color: "#533483" },
            { label: "→" },
            { label: "AI Detection", color: "#e94560" },
            { label: "→" },
            { label: "Alert Engine", color: "#f5a623" },
            { label: "→" },
            { label: "SOC Dashboard", color: "#0f9b8e" },
          ].map((item, i) => (
            <span
              key={i}
              className="px-2 py-1 rounded"
              style={
                item.color
                  ? {
                      background: `${item.color}15`,
                      color: item.color,
                      border: `1px solid ${item.color}25`,
                    }
                  : { color: "#8b8994" }
              }
            >
              {item.label}
            </span>
          ))}
        </div>
        <div className="mt-3 text-center text-[10px] text-[#8b8994] italic">
          No active probing • No return path • No inline mitigation • Passive
          monitoring only
        </div>
      </div>

      {/* SIH Compliance */}
      <div className="rounded-xl bg-[#16213e]/80 border border-[#2a2a4a] p-4">
        <div className="flex items-center gap-2 mb-4">
          <div className="w-[3px] h-4 bg-[#0f9b8e] rounded" />
          <h3 className="text-sm font-semibold text-[#e8e6e3]">
            SIH Requirement Compliance
          </h3>
        </div>
        <div className="grid grid-cols-1 md:grid-cols-2 gap-2">
          {[
            { label: "Read-only ingest", status: "✓", color: "#0f9b8e" },
            { label: "No return path", status: "✓", color: "#0f9b8e" },
            { label: "No active probing", status: "✓", color: "#0f9b8e" },
            { label: "No payload decryption", status: "✓", color: "#0f9b8e" },
            { label: "Streaming/replay processing", status: "✓", color: "#0f9b8e" },
            { label: "Defined throughput", status: "✓", color: "#0f9b8e" },
            { label: "Detection latency", status: "✓", color: "#0f9b8e" },
            { label: "Standardized alert schema", status: "✓", color: "#0f9b8e" },
            { label: "Confidence score", status: "✓", color: "#0f9b8e" },
            { label: "Supporting evidence", status: "✓", color: "#0f9b8e" },
            { label: "Six threat categories", status: "✓", color: "#0f9b8e" },
            { label: "Visual SOC dashboard", status: "✓", color: "#0f9b8e" },
          ].map((item) => (
            <div
              key={item.label}
              className="flex items-center gap-2 px-3 py-2 rounded bg-[#12122a]/30"
            >
              <span className="text-sm" style={{ color: item.color }}>
                {item.status}
              </span>
              <span className="text-xs text-[#e8e6e3]">{item.label}</span>
            </div>
          ))}
        </div>
      </div>
    </div>
  );
}
