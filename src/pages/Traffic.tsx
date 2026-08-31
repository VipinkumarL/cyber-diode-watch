import { useState, useMemo } from "react";
import {
  Activity,
  Search,
  Pause,
  Play,
  Filter,
} from "lucide-react";
import { cn } from "@/lib/utils";
import { useReplayStore } from "@/lib/store";
import { useFlowData } from "@/services/api";

export default function Traffic() {
  const { flows } = useFlowData(200, 1000);
  const [searchQuery, setSearchQuery] = useState("");
  const [filterSeverity, setFilterSeverity] = useState<string>("all");
  const [paused, setPaused] = useState(false);
  const replayState = useReplayStore();

  const isReplay = replayState.status === "running" || replayState.status === "paused";

  const filteredFlows = useMemo(() => {
    if (!flows) return [];
    return flows.filter((flow) => {
      const matchesSearch =
        !searchQuery ||
        flow.flowId.toLowerCase().includes(searchQuery.toLowerCase()) ||
        flow.sourceIp.includes(searchQuery) ||
        flow.destinationIp.includes(searchQuery);
      const matchesSeverity =
        filterSeverity === "all" || flow.severity === filterSeverity;
      return matchesSearch && matchesSeverity;
    });
  }, [flows, searchQuery, filterSeverity]);

  const displayFlows = paused ? filteredFlows : filteredFlows;

  return (
    <div className="space-y-4">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-bold text-[#e8e6e3] flex items-center gap-3">
            <Activity className="w-6 h-6 text-[#533483]" />
            Live Traffic
          </h1>
          <p className="text-sm text-[#8b8994] mt-1">
            Real-time network flow monitoring
          </p>
        </div>
        <div className="flex items-center gap-3">
          {isReplay && (
            <div className="flex items-center gap-2 px-3 py-1.5 rounded-md bg-[#f5a623]/10 border border-[#f5a623]/30">
              <div className="w-2 h-2 rounded-full bg-[#f5a623] animate-pulse" />
              <span className="text-xs font-medium text-[#f5a623] uppercase tracking-wider">
                Replay Mode
              </span>
            </div>
          )}
        </div>
      </div>

      {/* Controls */}
      <div className="flex items-center gap-3 flex-wrap">
        {/* Search */}
        <div className="relative flex-1 max-w-sm">
          <Search className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-[#8b8994]" />
          <input
            type="text"
            placeholder="Search by flow ID, IP..."
            value={searchQuery}
            onChange={(e) => setSearchQuery(e.target.value)}
            className="w-full pl-9 pr-4 py-2 rounded-lg bg-[#16213e] border border-[#2a2a4a] text-sm text-[#e8e6e3] placeholder-[#8b8994] focus:outline-none focus:border-[#533483]"
          />
        </div>

        {/* Severity filter */}
        <div className="relative">
          <Filter className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-[#8b8994]" />
          <select
            value={filterSeverity}
            onChange={(e) => setFilterSeverity(e.target.value)}
            className="pl-9 pr-8 py-2 rounded-lg bg-[#16213e] border border-[#2a2a4a] text-sm text-[#e8e6e3] appearance-none focus:outline-none focus:border-[#533483]"
          >
            <option value="all">All Severity</option>
            <option value="CRITICAL">Critical</option>
            <option value="HIGH">High</option>
            <option value="MEDIUM">Medium</option>
            <option value="LOW">Low</option>
            <option value="INFO">Info</option>
          </select>
        </div>

        {/* Pause/Resume */}
        <button
          onClick={() => setPaused(!paused)}
          className={cn(
            "flex items-center gap-2 px-3 py-2 rounded-lg border text-sm transition-colors",
            paused
              ? "bg-[#0f9b8e]/10 border-[#0f9b8e]/30 text-[#0f9b8e]"
              : "bg-[#16213e] border-[#2a2a4a] text-[#8b8994] hover:text-[#e8e6e3]",
          )}
        >
          {paused ? (
            <Play className="w-3.5 h-3.5" />
          ) : (
            <Pause className="w-3.5 h-3.5" />
          )}
          {paused ? "Resume" : "Pause"}
        </button>

        {/* Flow count */}
        <div className="text-xs text-[#8b8994] font-mono ml-auto">
          {displayFlows.length} flows
        </div>
      </div>

      {/* Flow table */}
      <div className="rounded-xl bg-[#16213e]/80 border border-[#2a2a4a] overflow-hidden">
        <div className="overflow-x-auto">
          <table className="w-full text-sm">
            <thead>
              <tr className="border-b border-[#2a2a4a] bg-[#12122a]/50">
                {[
                  "Timestamp",
                  "Flow ID",
                  "Source IP",
                  "Dest IP",
                  "Proto",
                  "Src Port",
                  "Dst Port",
                  "Duration",
                  "Packets/s",
                  "Bytes/s",
                  "Classification",
                  "Confidence",
                  "Severity",
                ].map((h) => (
                  <th
                    key={h}
                    className="text-left py-2.5 px-3 text-[10px] text-[#8b8994] uppercase tracking-wider font-medium whitespace-nowrap"
                  >
                    {h}
                  </th>
                ))}
              </tr>
            </thead>
            <tbody>
              {displayFlows.length === 0 ? (
                <tr>
                  <td
                    colSpan={13}
                    className="py-12 text-center text-sm text-[#8b8994]"
                  >
                    No traffic data. Start a replay from the Replay Lab to see
                    live traffic.
                  </td>
                </tr>
              ) : (
                displayFlows.map((flow) => (
                  <tr
                    key={flow.flowId}
                    className={cn(
                      "border-b border-[#2a2a4a]/30 transition-colors hover:bg-[#1a1a3e]/50",
                      flow.severity === "CRITICAL" && "bg-[#e94560]/5",
                      flow.severity === "HIGH" && "bg-[#f5a623]/5",
                    )}
                  >
                    <td className="py-2 px-3 text-xs text-[#c4c1bb] font-mono whitespace-nowrap">
                      {new Date(flow.timestamp).toLocaleTimeString("en-US", {
                        hour12: false,
                        hour: "2-digit",
                        minute: "2-digit",
                        second: "2-digit",
                      })}
                    </td>
                    <td className="py-2 px-3 text-xs text-[#8b8994] font-mono">
                      {flow.flowId.slice(-7)}
                    </td>
                    <td className="py-2 px-3 text-xs text-[#c4c1bb] font-mono">
                      {flow.sourceIp}
                    </td>
                    <td className="py-2 px-3 text-xs text-[#c4c1bb] font-mono">
                      {flow.destinationIp}
                    </td>
                    <td className="py-2 px-3">
                      <span className="text-[10px] px-1.5 py-0.5 rounded bg-[#533483]/20 text-[#533483] font-medium">
                        {flow.protocol}
                      </span>
                    </td>
                    <td className="py-2 px-3 text-xs text-[#8b8994] font-mono">
                      {flow.sourcePort}
                    </td>
                    <td className="py-2 px-3 text-xs text-[#8b8994] font-mono">
                      {flow.destinationPort}
                    </td>
                    <td className="py-2 px-3 text-xs text-[#c4c1bb] font-mono">
                      {flow.flowDuration.toFixed(3)}s
                    </td>
                    <td className="py-2 px-3 text-xs font-mono">
                      <span
                        style={{
                          color:
                            flow.packetsPerSecond > 5000
                              ? "#e94560"
                              : flow.packetsPerSecond > 1000
                                ? "#f5a623"
                                : "#c4c1bb",
                        }}
                      >
                        {flow.packetsPerSecond.toFixed(0)}
                      </span>
                    </td>
                    <td className="py-2 px-3 text-xs font-mono">
                      <span
                        style={{
                          color:
                            flow.bytesPerSecond > 10000000
                              ? "#e94560"
                              : flow.bytesPerSecond > 1000000
                                ? "#f5a623"
                                : "#c4c1bb",
                        }}
                      >
                        {flow.bytesPerSecond > 1000000
                          ? `${(flow.bytesPerSecond / 1000000).toFixed(1)}M`
                          : flow.bytesPerSecond > 1000
                            ? `${(flow.bytesPerSecond / 1000).toFixed(1)}K`
                            : flow.bytesPerSecond.toFixed(0)}
                      </span>
                    </td>
                    <td className="py-2 px-3">
                      <span className="text-xs font-medium">
                        {flow.classification}
                      </span>
                    </td>
                    <td className="py-2 px-3 text-xs font-mono text-[#c4c1bb]">
                      {flow.confidence > 0
                        ? `${(flow.confidence * 100).toFixed(1)}%`
                        : "—"}
                    </td>
                    <td className="py-2 px-3">
                      <span
                        className="inline-flex items-center px-2 py-0.5 rounded text-[10px] font-bold uppercase tracking-wider"
                        style={{
                          background:
                            flow.severity === "CRITICAL"
                              ? "#e9456020"
                              : flow.severity === "HIGH"
                                ? "#f5a62320"
                                : flow.severity === "MEDIUM"
                                  ? "#0f9b8e20"
                                  : "#6c7a8920",
                          color:
                            flow.severity === "CRITICAL"
                              ? "#e94560"
                              : flow.severity === "HIGH"
                                ? "#f5a623"
                                : flow.severity === "MEDIUM"
                                  ? "#0f9b8e"
                                  : "#6c7a89",
                        }}
                      >
                        {flow.severity}
                      </span>
                    </td>
                  </tr>
                ))
              )}
            </tbody>
          </table>
        </div>
      </div>
    </div>
  );
}
