import { useQuery } from "convex/react";
import { api } from "@/convex/_generated/api";
import {
  Activity,
  ShieldAlert,
  AlertTriangle,
  TrendingUp,
  Clock,
  Gauge,
  Zap,
  ShieldCheck,
} from "lucide-react";
import {
  LineChart,
  Line,
  AreaChart,
  Area,
  PieChart,
  Pie,
  Cell,
  XAxis,
  YAxis,
  CartesianGrid,
  Tooltip,
  ResponsiveContainer,
  Legend,
} from "recharts";

const SEVERITY_DATA = [
  { name: "Critical", value: 0, color: "#e94560" },
  { name: "High", value: 0, color: "#f5a623" },
  { name: "Medium", value: 0, color: "#0f9b8e" },
  { name: "Low", value: 0, color: "#48b9a7" },
  { name: "Info", value: 0, color: "#6c7a89" },
];

export default function Overview() {
  const stats = useQuery(api.flows.stats);
  const alertStats = useQuery(api.alerts.stats);
  const recentAlerts = useQuery(api.alerts.list, { limit: 10 });
  const flowTimeseries = useQuery(api.flows.getFlowTimeseries, {
    windowMs: 300000,
  });
  const metricsTimeseries = useQuery(api.metrics.getTimeseries, {
    windowMs: 300000,
  });

  const isLoading = !stats;

  const totalFlows = stats?.totalFlows ?? 0;
  const normalFlows = stats?.normalFlows ?? 0;
  const suspiciousFlows = stats?.suspiciousFlows ?? 0;
  const threatsDetected = stats?.threatsDetected ?? 0;
  const criticalAlerts = stats?.criticalAlerts ?? 0;
  const flowsPerSecond = stats?.flowsPerSecond ?? 0;
  const avgLatency = stats?.avgDetectionLatencyMs ?? 0;
  const riskScore = stats?.riskScore ?? 0;

  // Threat distribution from alert stats
  const threatDistribution = alertStats
    ? Object.entries(alertStats.byThreatClass).map(([name, value]) => ({
        name: name.replace("_", " "),
        value,
      }))
    : [];

  const severityData = alertStats
    ? SEVERITY_DATA.map((s) => ({
        ...s,
        value: alertStats.bySeverity[s.name.toUpperCase()] ?? 0,
      }))
    : SEVERITY_DATA;

  const metricCards = [
    {
      label: "Total Flows",
      value: totalFlows.toLocaleString(),
      icon: Activity,
      color: "#533483",
      bgColor: "#53348315",
    },
    {
      label: "Normal",
      value: normalFlows.toLocaleString(),
      icon: ShieldCheck,
      color: "#0f9b8e",
      bgColor: "#0f9b8e15",
    },
    {
      label: "Suspicious",
      value: suspiciousFlows.toLocaleString(),
      icon: AlertTriangle,
      color: "#f5a623",
      bgColor: "#f5a62315",
    },
    {
      label: "Threats Detected",
      value: threatsDetected.toLocaleString(),
      icon: ShieldAlert,
      color: "#e94560",
      bgColor: "#e9456015",
    },
    {
      label: "Critical Alerts",
      value: criticalAlerts.toLocaleString(),
      icon: Zap,
      color: "#e94560",
      bgColor: "#e9456020",
    },
    {
      label: "Flows/sec",
      value: flowsPerSecond.toFixed(1),
      icon: TrendingUp,
      color: "#48b9a7",
      bgColor: "#48b9a715",
    },
    {
      label: "Avg Detection Latency",
      value: `${avgLatency}ms`,
      icon: Clock,
      color: "#f5a623",
      bgColor: "#f5a62315",
    },
    {
      label: "Risk Score",
      value: `${riskScore}/100`,
      icon: Gauge,
      color: riskScore > 70 ? "#e94560" : riskScore > 40 ? "#f5a623" : "#0f9b8e",
      bgColor:
        riskScore > 70 ? "#e9456015" : riskScore > 40 ? "#f5a62315" : "#0f9b8e15",
    },
  ];

  // Chart data from timeseries
  const chartData = (flowTimeseries ?? []).map((d) => ({
    time: d.time,
    flows: d.total,
    threats: d.threats,
    normal: d.normal,
  }));

  return (
    <div className="space-y-6">
      {/* Page header */}
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-bold text-[#e8e6e3]">
            SOC Overview
          </h1>
          <p className="text-sm text-[#8b8994] mt-1">
            Security Operations Center — Executive Dashboard
          </p>
        </div>
        <div className="flex items-center gap-3">
          <div className="flex items-center gap-2 px-4 py-2 rounded-lg bg-[#0f9b8e]/10 border border-[#0f9b8e]/30">
            <div className="w-3 h-3 rounded-full bg-[#0f9b8e] status-pulse" />
            <span className="text-sm font-semibold text-[#0f9b8e] uppercase tracking-wider">
              Passive Monitoring Active
            </span>
          </div>
        </div>
      </div>

      {/* Notebook annotation */}
      <div className="flex items-center gap-2 text-[#f5a623] italic text-xs">
        <span>§</span>
        <span>Read-Only • No Return Path • No Active Probing • No Inline Mitigation</span>
      </div>

      {/* Metric cards grid */}
      <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
        {metricCards.map((card) => (
          <div
            key={card.label}
            className="notebook-card rounded-xl p-4 bg-[#16213e]/80 border border-[#2a2a4a] relative overflow-hidden group hover:border-[#533483]/40 transition-colors"
          >
            <div
              className="absolute top-0 left-0 right-0 h-[3px]"
              style={{ background: card.color }}
            />
            <div className="flex items-start justify-between">
              <div>
                <p className="text-[11px] text-[#8b8994] uppercase tracking-wider font-medium">
                  {card.label}
                </p>
                <p
                  className="text-2xl font-bold mt-1 font-mono"
                  style={{ color: card.color }}
                >
                  {isLoading ? "—" : card.value}
                </p>
              </div>
              <div
                className="w-8 h-8 rounded-lg flex items-center justify-center"
                style={{ background: card.bgColor }}
              >
                <card.icon className="w-4 h-4" style={{ color: card.color }} />
              </div>
            </div>
          </div>
        ))}
      </div>

      {/* Charts row */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-4">
        {/* Traffic rate chart */}
        <div className="lg:col-span-2 rounded-xl bg-[#16213e]/80 border border-[#2a2a4a] p-4">
          <div className="flex items-center gap-2 mb-4">
            <div className="w-[3px] h-4 bg-[#533483] rounded" />
            <h3 className="text-sm font-semibold text-[#e8e6e3]">
              Traffic Rate
            </h3>
            <span className="text-[10px] text-[#8b8994] ml-auto">
              Last 5 minutes
            </span>
          </div>
          <ResponsiveContainer width="100%" height={220}>
            <AreaChart data={chartData}>
              <defs>
                <linearGradient id="gradFlows" x1="0" y1="0" x2="0" y2="1">
                  <stop offset="5%" stopColor="#533483" stopOpacity={0.3} />
                  <stop offset="95%" stopColor="#533483" stopOpacity={0} />
                </linearGradient>
              </defs>
              <CartesianGrid strokeDasharray="3 3" stroke="#2a2a4a" />
              <XAxis
                dataKey="time"
                stroke="#8b8994"
                fontSize={10}
                tickLine={false}
              />
              <YAxis stroke="#8b8994" fontSize={10} tickLine={false} />
              <Tooltip
                contentStyle={{
                  background: "#16213e",
                  border: "1px solid #2a2a4a",
                  borderRadius: "8px",
                  fontSize: "12px",
                  color: "#e8e6e3",
                }}
              />
              <Area
                type="monotone"
                dataKey="flows"
                stroke="#533483"
                fill="url(#gradFlows)"
                strokeWidth={2}
              />
            </AreaChart>
          </ResponsiveContainer>
        </div>

        {/* Severity distribution */}
        <div className="rounded-xl bg-[#16213e]/80 border border-[#2a2a4a] p-4">
          <div className="flex items-center gap-2 mb-4">
            <div className="w-[3px] h-4 bg-[#e94560] rounded" />
            <h3 className="text-sm font-semibold text-[#e8e6e3]">
              Severity Distribution
            </h3>
          </div>
          <ResponsiveContainer width="100%" height={220}>
            <PieChart>
              <Pie
                data={severityData}
                cx="50%"
                cy="50%"
                innerRadius={50}
                outerRadius={80}
                paddingAngle={3}
                dataKey="value"
              >
                {severityData.map((entry, index) => (
                  <Cell key={index} fill={entry.color} />
                ))}
              </Pie>
              <Tooltip
                contentStyle={{
                  background: "#16213e",
                  border: "1px solid #2a2a4a",
                  borderRadius: "8px",
                  fontSize: "12px",
                  color: "#e8e6e3",
                }}
              />
              <Legend
                wrapperStyle={{ fontSize: "11px", color: "#8b8994" }}
              />
            </PieChart>
          </ResponsiveContainer>
        </div>
      </div>

      {/* Threats over time + Threat distribution */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
        {/* Threats over time */}
        <div className="rounded-xl bg-[#16213e]/80 border border-[#2a2a4a] p-4">
          <div className="flex items-center gap-2 mb-4">
            <div className="w-[3px] h-4 bg-[#e94560] rounded" />
            <h3 className="text-sm font-semibold text-[#e8e6e3]">
              Threats Over Time
            </h3>
          </div>
          <ResponsiveContainer width="100%" height={200}>
            <LineChart data={chartData}>
              <CartesianGrid strokeDasharray="3 3" stroke="#2a2a4a" />
              <XAxis
                dataKey="time"
                stroke="#8b8994"
                fontSize={10}
                tickLine={false}
              />
              <YAxis stroke="#8b8994" fontSize={10} tickLine={false} />
              <Tooltip
                contentStyle={{
                  background: "#16213e",
                  border: "1px solid #2a2a4a",
                  borderRadius: "8px",
                  fontSize: "12px",
                  color: "#e8e6e3",
                }}
              />
              <Line
                type="monotone"
                dataKey="threats"
                stroke="#e94560"
                strokeWidth={2}
                dot={false}
              />
              <Line
                type="monotone"
                dataKey="normal"
                stroke="#0f9b8e"
                strokeWidth={1}
                dot={false}
                strokeDasharray="5 5"
              />
            </LineChart>
          </ResponsiveContainer>
        </div>

        {/* Threat distribution */}
        <div className="rounded-xl bg-[#16213e]/80 border border-[#2a2a4a] p-4">
          <div className="flex items-center gap-2 mb-4">
            <div className="w-[3px] h-4 bg-[#f5a623] rounded" />
            <h3 className="text-sm font-semibold text-[#e8e6e3]">
              Threat Distribution
            </h3>
          </div>
          {threatDistribution.length > 0 ? (
            <ResponsiveContainer width="100%" height={200}>
              <PieChart>
                <Pie
                  data={threatDistribution}
                  cx="50%"
                  cy="50%"
                  outerRadius={80}
                  dataKey="value"
                  label={({ name, percent }) =>
                    `${name} ${(percent * 100).toFixed(0)}%`
                  }
                >
                  {threatDistribution.map((entry, index) => (
                    <Cell
                      key={index}
                      fill={
                        [
                          "#e94560",
                          "#f5a623",
                          "#0f9b8e",
                          "#533483",
                          "#48b9a7",
                          "#ff6b6b",
                        ][index % 6]
                      }
                    />
                  ))}
                </Pie>
                <Tooltip
                  contentStyle={{
                    background: "#16213e",
                    border: "1px solid #2a2a4a",
                    borderRadius: "8px",
                    fontSize: "12px",
                    color: "#e8e6e3",
                  }}
                />
              </PieChart>
            </ResponsiveContainer>
          ) : (
            <div className="flex items-center justify-center h-[200px] text-sm text-[#8b8994]">
              No threats detected yet. Start a replay to generate data.
            </div>
          )}
        </div>
      </div>

      {/* Recent alerts table */}
      <div className="rounded-xl bg-[#16213e]/80 border border-[#2a2a4a] p-4">
        <div className="flex items-center gap-2 mb-4">
          <div className="w-[3px] h-4 bg-[#e94560] rounded" />
          <h3 className="text-sm font-semibold text-[#e8e6e3]">
            Recent Alerts
          </h3>
          <span className="text-[10px] text-[#8b8994] ml-auto font-mono">
            {alertStats?.total ?? 0} total
          </span>
        </div>
        {recentAlerts && recentAlerts.length > 0 ? (
          <div className="overflow-x-auto">
            <table className="w-full text-sm">
              <thead>
                <tr className="border-b border-[#2a2a4a]">
                  <th className="text-left py-2 px-3 text-[10px] text-[#8b8994] uppercase tracking-wider font-medium">
                    Time
                  </th>
                  <th className="text-left py-2 px-3 text-[10px] text-[#8b8994] uppercase tracking-wider font-medium">
                    Threat
                  </th>
                  <th className="text-left py-2 px-3 text-[10px] text-[#8b8994] uppercase tracking-wider font-medium">
                    Severity
                  </th>
                  <th className="text-left py-2 px-3 text-[10px] text-[#8b8994] uppercase tracking-wider font-medium">
                    Confidence
                  </th>
                  <th className="text-left py-2 px-3 text-[10px] text-[#8b8994] uppercase tracking-wider font-medium">
                    Source → Dest
                  </th>
                  <th className="text-left py-2 px-3 text-[10px] text-[#8b8994] uppercase tracking-wider font-medium">
                    Detector
                  </th>
                </tr>
              </thead>
              <tbody>
                {recentAlerts.map((alert) => (
                  <tr
                    key={alert._id}
                    className="border-b border-[#2a2a4a]/50 hover:bg-[#1a1a3e]/50"
                  >
                    <td className="py-2.5 px-3 text-xs text-[#c4c1bb] font-mono">
                      {new Date(alert.timestamp).toLocaleTimeString("en-US", {
                        hour12: false,
                      })}
                    </td>
                    <td className="py-2.5 px-3">
                      <span className="text-xs font-medium text-[#e8e6e3]">
                        {alert.threatClass.replace("_", " ")}
                      </span>
                    </td>
                    <td className="py-2.5 px-3">
                      <span
                        className="inline-flex items-center px-2 py-0.5 rounded text-[10px] font-bold uppercase tracking-wider"
                        style={{
                          background:
                            alert.severity === "CRITICAL"
                              ? "#e9456020"
                              : alert.severity === "HIGH"
                                ? "#f5a62320"
                                : "#0f9b8e20",
                          color:
                            alert.severity === "CRITICAL"
                              ? "#e94560"
                              : alert.severity === "HIGH"
                                ? "#f5a623"
                                : "#0f9b8e",
                        }}
                      >
                        {alert.severity}
                      </span>
                    </td>
                    <td className="py-2.5 px-3 text-xs font-mono text-[#c4c1bb]">
                      {(alert.confidence * 100).toFixed(1)}%
                    </td>
                    <td className="py-2.5 px-3 text-xs text-[#8b8994] font-mono">
                      {alert.sourceIp} → {alert.destinationIp}:{alert.destinationPort}
                    </td>
                    <td className="py-2.5 px-3 text-xs text-[#8b8994]">
                      {alert.detector}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        ) : (
          <div className="text-center py-8 text-sm text-[#8b8994]">
            No alerts yet. Start a replay from the Replay Lab to generate detections.
          </div>
        )}
      </div>
    </div>
  );
}
