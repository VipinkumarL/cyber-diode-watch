import { useState } from "react";
import {
  AlertTriangle,
  ChevronDown,
  ChevronRight,
  Clock,
  MapPin,
  Shield,
  Activity,
} from "lucide-react";
import { cn } from "@/lib/utils";
import { useIncidentData, useAlertData } from "@/services/api";

export default function Incidents() {
  const { incidents, stats: incidentStats } = useIncidentData(50, 1000);
  const { stats: alertStats } = useAlertData(0, 1000);
  const [expandedId, setExpandedId] = useState<string | null>(null);

  return (
    <div className="space-y-6">
      {/* Header */}
      <div>
        <h1 className="text-2xl font-bold text-[#e8e6e3] flex items-center gap-3">
          <AlertTriangle className="w-6 h-6 text-[#f5a623]" />
          Incidents
        </h1>
        <p className="text-sm text-[#8b8994] mt-1">
          Investigate detected threats with supporting evidence
        </p>
      </div>

      {/* Summary cards */}
      <div className="grid grid-cols-2 md:grid-cols-4 gap-3">
        {[
          {
            label: "Total Incidents",
            value: incidentStats?.total ?? 0,
            color: "#533483",
          },
          {
            label: "Open",
            value: incidentStats?.byStatus?.["open"] ?? 0,
            color: "#e94560",
          },
          {
            label: "Critical",
            value: incidentStats?.bySeverity?.["CRITICAL"] ?? 0,
            color: "#e94560",
          },
          {
            label: "Total Alerts",
            value: alertStats?.total ?? 0,
            color: "#f5a623",
          },
        ].map((card) => (
          <div
            key={card.label}
            className="rounded-xl bg-[#16213e]/80 border border-[#2a2a4a] p-4"
          >
            <p className="text-[10px] text-[#8b8994] uppercase tracking-wider">
              {card.label}
            </p>
            <p
              className="text-xl font-bold font-mono mt-1"
              style={{ color: card.color }}
            >
              {card.value}
            </p>
          </div>
        ))}
      </div>

      {/* Incidents list */}
      <div className="space-y-3">
        {incidents && incidents.length > 0 ? (
          incidents.map((incident) => {
            const isExpanded = expandedId === incident.incidentId;
            return (
              <div
                key={incident.incidentId}
                className={cn(
                  "rounded-xl bg-[#16213e]/80 border overflow-hidden transition-colors",
                  isExpanded
                    ? "border-[#533483]/40"
                    : "border-[#2a2a4a] hover:border-[#533483]/20",
                )}
              >
                {/* Incident header */}
                <button
                  onClick={() =>
                    setExpandedId(isExpanded ? null : incident.incidentId)
                  }
                  className="w-full flex items-center gap-4 p-4 text-left"
                >
                  <div className="flex-shrink-0">
                    {isExpanded ? (
                      <ChevronDown className="w-4 h-4 text-[#8b8994]" />
                    ) : (
                      <ChevronRight className="w-4 h-4 text-[#8b8994]" />
                    )}
                  </div>

                  <div
                    className="w-2 h-2 rounded-full flex-shrink-0"
                    style={{
                      background:
                        incident.severity === "CRITICAL"
                          ? "#e94560"
                          : incident.severity === "HIGH"
                            ? "#f5a623"
                            : "#0f9b8e",
                    }}
                  />

                  <div className="flex-1 min-w-0">
                    <div className="flex items-center gap-2">
                      <span className="text-sm font-semibold text-[#e8e6e3]">
                        {incident.title}
                      </span>
                      <span
                        className="px-1.5 py-0.5 rounded text-[9px] font-bold uppercase"
                        style={{
                          background:
                            incident.severity === "CRITICAL"
                              ? "#e9456020"
                              : incident.severity === "HIGH"
                                ? "#f5a62320"
                                : "#0f9b8e20",
                          color:
                            incident.severity === "CRITICAL"
                              ? "#e94560"
                              : incident.severity === "HIGH"
                                ? "#f5a623"
                                : "#0f9b8e",
                        }}
                      >
                        {incident.severity}
                      </span>
                    </div>
                    <p className="text-xs text-[#8b8994] mt-0.5 truncate">
                      {incident.description}
                    </p>
                  </div>

                  <div className="text-right flex-shrink-0">
                    <div className="text-xs font-mono text-[#c4c1bb]">
                      {(incident.confidence * 100).toFixed(1)}%
                    </div>
                    <div className="text-[10px] text-[#8b8994]">
                      {incident.alertCount} alerts
                    </div>
                  </div>

                  <div className="text-xs text-[#8b8994] font-mono flex-shrink-0">
                    {new Date(incident.timestamp).toLocaleTimeString("en-US", {
                      hour12: false,
                    })}
                  </div>
                </button>

                {/* Expanded details */}
                {isExpanded && (
                  <div className="border-t border-[#2a2a4a] p-4 space-y-4 bg-[#12122a]/30">
                    {/* Incident metadata */}
                    <div className="grid grid-cols-2 md:grid-cols-4 gap-3">
                      {[
                        {
                          icon: Shield,
                          label: "Threat Class",
                          value: incident.threatClass.replace("_", " "),
                        },
                        {
                          icon: Activity,
                          label: "Confidence",
                          value: `${(incident.confidence * 100).toFixed(1)}%`,
                        },
                        {
                          icon: Clock,
                          label: "Detection Latency",
                          value: `${incident.detectionLatencyMs}ms`,
                        },
                        {
                          icon: MapPin,
                          label: "Detector",
                          value: incident.detector,
                        },
                      ].map((item) => (
                        <div
                          key={item.label}
                          className="px-3 py-2 rounded-lg bg-[#16213e]/50"
                        >
                          <div className="flex items-center gap-1.5">
                            <item.icon className="w-3 h-3 text-[#8b8994]" />
                            <span className="text-[10px] text-[#8b8994] uppercase tracking-wider">
                              {item.label}
                            </span>
                          </div>
                          <p className="text-sm font-medium text-[#e8e6e3] mt-1">
                            {item.value}
                          </p>
                        </div>
                      ))}
                    </div>

                    {/* Source / Destination IPs */}
                    <div className="grid grid-cols-2 gap-3">
                      <div className="px-3 py-2 rounded-lg bg-[#16213e]/50">
                        <span className="text-[10px] text-[#8b8994] uppercase tracking-wider">
                          Source IPs
                        </span>
                        <div className="mt-1 space-y-0.5">
                          {incident.sourceIps.map((ip) => (
                            <span
                              key={ip}
                              className="block text-xs font-mono text-[#c4c1bb]"
                            >
                              {ip}
                            </span>
                          ))}
                        </div>
                      </div>
                      <div className="px-3 py-2 rounded-lg bg-[#16213e]/50">
                        <span className="text-[10px] text-[#8b8994] uppercase tracking-wider">
                          Destination IPs
                        </span>
                        <div className="mt-1 space-y-0.5">
                          {incident.destinationIps.map((ip) => (
                            <span
                              key={ip}
                              className="block text-xs font-mono text-[#c4c1bb]"
                            >
                              {ip}
                            </span>
                          ))}
                        </div>
                      </div>
                    </div>

                    {/* Supporting Evidence panel */}
                    <div className="rounded-lg bg-[#16213e]/60 border border-[#2a2a4a] p-4">
                      <div className="flex items-center gap-2 mb-3">
                        <div className="w-[3px] h-4 bg-[#f5a623] rounded" />
                        <h4 className="text-xs font-semibold text-[#e8e6e3] uppercase tracking-wider">
                          Supporting Evidence
                        </h4>
                        <span className="notebook-annotation ml-2">
                          Detection evidence — model output & feature analysis
                        </span>
                      </div>
                      <div className="grid grid-cols-2 md:grid-cols-3 gap-2">
                        {Object.entries(incident.evidence).map(
                          ([key, value]) => (
                            <div
                              key={key}
                              className="px-3 py-2 rounded bg-[#12122a]/50"
                            >
                              <p className="text-[10px] text-[#8b8994] uppercase tracking-wider">
                                {key.replace(/_/g, " ")}
                              </p>
                              <p className="text-xs font-mono text-[#e8e6e3] mt-0.5">
                                {typeof value === "number"
                                  ? value.toLocaleString()
                                  : String(value)}
                              </p>
                            </div>
                          ),
                        )}
                      </div>
                    </div>
                  </div>
                )}
              </div>
            );
          })
        ) : (
          <div className="rounded-xl bg-[#16213e]/80 border border-[#2a2a4a] p-12 text-center">
            <AlertTriangle className="w-12 h-12 text-[#8b8994]/30 mx-auto mb-4" />
            <p className="text-sm text-[#8b8994]">
              No incidents yet. Start a replay in the Replay Lab to generate
              threat detections and incidents.
            </p>
          </div>
        )}
      </div>
    </div>
  );
}
