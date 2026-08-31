import { BarChart3 } from "lucide-react";
import {
  AreaChart,
  Area,
  BarChart,
  Bar,
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
import {
  useFlowData,
  useAlertData,
  useFlowTimeseries,
  useAlertTimeline,
} from "@/services/api";

const COLORS = ["#e94560", "#f5a623", "#0f9b8e", "#533483", "#48b9a7", "#ff6b6b"];

export default function Analytics() {
  const { stats: flowStats, flows } = useFlowData(100, 1000);
  const { stats: alertStats } = useAlertData(0, 1000);
  const flowTimeseries = useFlowTimeseries(300000, 2000);
  const alertTimeline = useAlertTimeline(300000, 2000);

  const isLoading = !flowStats;

  // Threat distribution
  const threatDistribution = alertStats
    ? Object.entries(alertStats.byThreatClass)
        .map(([name, value]) => ({ name: name.replace("_", " "), value }))
        .sort((a, b) => b.value - a.value)
    : [];

  // Severity distribution
  const severityDistribution = alertStats
    ? ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"].map((s) => ({
        name: s,
        value: alertStats.bySeverity[s] ?? 0,
        color:
          s === "CRITICAL"
            ? "#e94560"
            : s === "HIGH"
              ? "#f5a623"
              : s === "MEDIUM"
                ? "#0f9b8e"
                : s === "LOW"
                  ? "#48b9a7"
                  : "#6c7a89",
      }))
    : [];

  // Confidence distribution (from flows)
  const confidenceBuckets = [
    { range: "0-20%", count: 0 },
    { range: "20-40%", count: 0 },
    { range: "40-60%", count: 0 },
    { range: "60-80%", count: 0 },
    { range: "80-100%", count: 0 },
  ];

  if (flows) {
    for (const flow of flows) {
      if (flow.confidence > 0) {
        const bucket = Math.min(4, Math.floor(flow.confidence * 5));
        confidenceBuckets[bucket].count++;
      }
    }
  }

  // Port distribution
  const portCounts: Record<number, number> = {};
  if (flows) {
    for (const flow of flows) {
      portCounts[flow.destinationPort] =
        (portCounts[flow.destinationPort] ?? 0) + 1;
    }
  }
  const portDistribution = Object.entries(portCounts)
    .map(([port, count]) => ({ port: `:${port}`, count }))
    .sort((a, b) => b.count - a.count)
    .slice(0, 10);

  // Protocol distribution
  const protoCounts: Record<string, number> = {};
  if (flows) {
    for (const flow of flows) {
      protoCounts[flow.protocol] = (protoCounts[flow.protocol] ?? 0) + 1;
    }
  }
  const protoDistribution = Object.entries(protoCounts).map(
    ([name, value]) => ({ name, value }),
  );

  // Flow timeseries
  const chartData = flowTimeseries.map((d) => ({
    time: d.time,
    flows: d.total,
    threats: d.threats,
    normal: d.normal,
  }));

  // Alert timeseries
  const alertChartData = alertTimeline.map((d) => ({
    ...d,
    timeLabel: new Date(d.time).toLocaleTimeString("en-US", { hour12: false }),
  }));

  return (
    <div className="space-y-6">
      {/* Header */}
      <div>
        <h1 className="text-2xl font-bold text-[#e8e6e3] flex items-center gap-3">
          <BarChart3 className="w-6 h-6 text-[#48b9a7]" />
          Analytics
        </h1>
        <p className="text-sm text-[#8b8994] mt-1">
          Traffic analysis, threat statistics, and detection performance
        </p>
      </div>

      {/* Summary stats */}
      <div className="grid grid-cols-2 md:grid-cols-4 gap-3">
        {[
          { label: "Total Flows", value: flowStats?.totalFlows ?? 0, color: "#533483" },
          { label: "Total Alerts", value: alertStats?.total ?? 0, color: "#e94560" },
          {
            label: "Avg Confidence",
            value: `${((alertStats?.avgConfidence ?? 0) * 100).toFixed(1)}%`,
            color: "#f5a623",
          },
          {
            label: "Avg Latency",
            value: `${(alertStats?.avgLatency ?? 0).toFixed(0)}ms`,
            color: "#0f9b8e",
          },
        ].map((stat) => (
          <div
            key={stat.label}
            className="rounded-xl bg-[#16213e]/80 border border-[#2a2a4a] p-4"
          >
            <p className="text-[10px] text-[#8b8994] uppercase tracking-wider">
              {stat.label}
            </p>
            <p
              className="text-xl font-bold font-mono mt-1"
              style={{ color: stat.color }}
            >
              {isLoading ? "—" : stat.value}
            </p>
          </div>
        ))}
      </div>

      {/* Charts grid */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
        {/* Flows over time */}
        <div className="rounded-xl bg-[#16213e]/80 border border-[#2a2a4a] p-4">
          <div className="flex items-center gap-2 mb-4">
            <div className="w-[3px] h-4 bg-[#533483] rounded" />
            <h3 className="text-sm font-semibold text-[#e8e6e3]">
              Flows Over Time
            </h3>
          </div>
          <ResponsiveContainer width="100%" height={250}>
            <AreaChart data={chartData}>
              <defs>
                <linearGradient id="gradNormal" x1="0" y1="0" x2="0" y2="1">
                  <stop offset="5%" stopColor="#0f9b8e" stopOpacity={0.3} />
                  <stop offset="95%" stopColor="#0f9b8e" stopOpacity={0} />
                </linearGradient>
                <linearGradient id="gradThreats" x1="0" y1="0" x2="0" y2="1">
                  <stop offset="5%" stopColor="#e94560" stopOpacity={0.3} />
                  <stop offset="95%" stopColor="#e94560" stopOpacity={0} />
                </linearGradient>
              </defs>
              <CartesianGrid strokeDasharray="3 3" stroke="#2a2a4a" />
              <XAxis dataKey="time" stroke="#8b8994" fontSize={10} tickLine={false} />
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
              <Area type="monotone" dataKey="normal" stroke="#0f9b8e" fill="url(#gradNormal)" strokeWidth={1.5} />
              <Area type="monotone" dataKey="threats" stroke="#e94560" fill="url(#gradThreats)" strokeWidth={1.5} />
              <Legend wrapperStyle={{ fontSize: "11px", color: "#8b8994" }} />
            </AreaChart>
          </ResponsiveContainer>
        </div>

        {/* Threat distribution */}
        <div className="rounded-xl bg-[#16213e]/80 border border-[#2a2a4a] p-4">
          <div className="flex items-center gap-2 mb-4">
            <div className="w-[3px] h-4 bg-[#e94560] rounded" />
            <h3 className="text-sm font-semibold text-[#e8e6e3]">
              Threat Distribution
            </h3>
          </div>
          {threatDistribution.length > 0 ? (
            <ResponsiveContainer width="100%" height={250}>
              <BarChart data={threatDistribution} layout="vertical">
                <CartesianGrid strokeDasharray="3 3" stroke="#2a2a4a" />
                <XAxis type="number" stroke="#8b8994" fontSize={10} />
                <YAxis
                  dataKey="name"
                  type="category"
                  stroke="#8b8994"
                  fontSize={10}
                  width={100}
                />
                <Tooltip
                  contentStyle={{
                    background: "#16213e",
                    border: "1px solid #2a2a4a",
                    borderRadius: "8px",
                    fontSize: "12px",
                    color: "#e8e6e3",
                  }}
                />
                <Bar dataKey="value" radius={[0, 4, 4, 0]}>
                  {threatDistribution.map((_, index) => (
                    <Cell key={index} fill={COLORS[index % COLORS.length]} />
                  ))}
                </Bar>
              </BarChart>
            </ResponsiveContainer>
          ) : (
            <div className="flex items-center justify-center h-[250px] text-sm text-[#8b8994]">
              No threat data yet
            </div>
          )}
        </div>

        {/* Severity distribution */}
        <div className="rounded-xl bg-[#16213e]/80 border border-[#2a2a4a] p-4">
          <div className="flex items-center gap-2 mb-4">
            <div className="w-[3px] h-4 bg-[#f5a623] rounded" />
            <h3 className="text-sm font-semibold text-[#e8e6e3]">
              Severity Distribution
            </h3>
          </div>
          <ResponsiveContainer width="100%" height={250}>
            <PieChart>
              <Pie
                data={severityDistribution}
                cx="50%"
                cy="50%"
                innerRadius={50}
                outerRadius={90}
                paddingAngle={3}
                dataKey="value"
              >
                {severityDistribution.map((entry, index) => (
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
              <Legend wrapperStyle={{ fontSize: "11px", color: "#8b8994" }} />
            </PieChart>
          </ResponsiveContainer>
        </div>

        {/* Confidence distribution */}
        <div className="rounded-xl bg-[#16213e]/80 border border-[#2a2a4a] p-4">
          <div className="flex items-center gap-2 mb-4">
            <div className="w-[3px] h-4 bg-[#48b9a7] rounded" />
            <h3 className="text-sm font-semibold text-[#e8e6e3]">
              Confidence Distribution
            </h3>
          </div>
          <ResponsiveContainer width="100%" height={250}>
            <BarChart data={confidenceBuckets}>
              <CartesianGrid strokeDasharray="3 3" stroke="#2a2a4a" />
              <XAxis dataKey="range" stroke="#8b8994" fontSize={10} />
              <YAxis stroke="#8b8994" fontSize={10} />
              <Tooltip
                contentStyle={{
                  background: "#16213e",
                  border: "1px solid #2a2a4a",
                  borderRadius: "8px",
                  fontSize: "12px",
                  color: "#e8e6e3",
                }}
              />
              <Bar dataKey="count" fill="#48b9a7" radius={[4, 4, 0, 0]} />
            </BarChart>
          </ResponsiveContainer>
        </div>

        {/* Port distribution */}
        <div className="rounded-xl bg-[#16213e]/80 border border-[#2a2a4a] p-4">
          <div className="flex items-center gap-2 mb-4">
            <div className="w-[3px] h-4 bg-[#533483] rounded" />
            <h3 className="text-sm font-semibold text-[#e8e6e3]">
              Top Destination Ports
            </h3>
          </div>
          <ResponsiveContainer width="100%" height={250}>
            <BarChart data={portDistribution}>
              <CartesianGrid strokeDasharray="3 3" stroke="#2a2a4a" />
              <XAxis dataKey="port" stroke="#8b8994" fontSize={10} />
              <YAxis stroke="#8b8994" fontSize={10} />
              <Tooltip
                contentStyle={{
                  background: "#16213e",
                  border: "1px solid #2a2a4a",
                  borderRadius: "8px",
                  fontSize: "12px",
                  color: "#e8e6e3",
                }}
              />
              <Bar dataKey="count" fill="#533483" radius={[4, 4, 0, 0]} />
            </BarChart>
          </ResponsiveContainer>
        </div>

        {/* Protocol distribution */}
        <div className="rounded-xl bg-[#16213e]/80 border border-[#2a2a4a] p-4">
          <div className="flex items-center gap-2 mb-4">
            <div className="w-[3px] h-4 bg-[#0f9b8e] rounded" />
            <h3 className="text-sm font-semibold text-[#e8e6e3]">
              Protocol Distribution
            </h3>
          </div>
          {protoDistribution.length > 0 ? (
            <ResponsiveContainer width="100%" height={250}>
              <PieChart>
                <Pie
                  data={protoDistribution}
                  cx="50%"
                  cy="50%"
                  outerRadius={90}
                  dataKey="value"
                  label={({ name, percent }) =>
                    `${name} ${(percent * 100).toFixed(0)}%`
                  }
                >
                  {protoDistribution.map((_, index) => (
                    <Cell key={index} fill={COLORS[index % COLORS.length]} />
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
            <div className="flex items-center justify-center h-[250px] text-sm text-[#8b8994]">
              No protocol data yet
            </div>
          )}
        </div>
      </div>
    </div>
  );
}
