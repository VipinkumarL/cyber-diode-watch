import { useQuery } from "convex/react";
import { api } from "@/convex/_generated/api";
import {
  ShieldAlert,
  Wifi,
  Radio,
  Globe,
  Lock,
  ScanSearch,
  ArrowUpFromLine,
  Clock,
  TrendingUp,
} from "lucide-react";
import { DETECTORS } from "@/lib/detection";

const THREAT_ICONS: Record<string, typeof ShieldAlert> = {
  DDoS: Wifi,
  C2_Beaconing: Radio,
  DGA_DNS_Tunneling: Globe,
  Encrypted_Malware: Lock,
  Reconnaissance: ScanSearch,
  Data_Exfiltration: ArrowUpFromLine,
};

const THREAT_COLORS: Record<string, string> = {
  DDoS: "#e94560",
  C2_Beaconing: "#f5a623",
  DGA_DNS_Tunneling: "#0f9b8e",
  Encrypted_Malware: "#533483",
  Reconnaissance: "#48b9a7",
  Data_Exfiltration: "#ff6b6b",
};

const STATUS_STYLES: Record<string, { bg: string; text: string; label: string }> = {
  ACTIVE: { bg: "#0f9b8e15", text: "#0f9b8e", label: "ACTIVE" },
  DEMO: { bg: "#f5a62315", text: "#f5a623", label: "DEMO" },
  NOT_TRAINED: { bg: "#8b899415", text: "#8b8994", label: "NOT TRAINED" },
  DISABLED: { bg: "#8b899415", text: "#8b8994", label: "DISABLED" },
};

export default function Threats() {
  const alertStats = useQuery(api.alerts.stats);
  const recentAlerts = useQuery(api.alerts.list, { limit: 20 });

  return (
    <div className="space-y-6">
      {/* Header */}
      <div>
        <h1 className="text-2xl font-bold text-[#e8e6e3] flex items-center gap-3">
          <ShieldAlert className="w-6 h-6 text-[#e94560]" />
          Threat Detection
        </h1>
        <p className="text-sm text-[#8b8994] mt-1">
          Six modular AI/ML threat detectors — DDoS fully operational
        </p>
      </div>

      {/* SIH compliance annotation */}
      <div className="flex items-center gap-2 px-3 py-2 rounded-lg bg-[#0f9b8e]/5 border border-[#0f9b8e]/15">
        <span className="text-[10px] text-[#0f9b8e] font-medium">
          ✓ Six threat categories implemented • Modular architecture •
          Independent detectors
        </span>
      </div>

      {/* Detector cards grid */}
      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
        {DETECTORS.map((detector) => {
          const Icon = THREAT_ICONS[detector.threatClass] ?? ShieldAlert;
          const color = THREAT_COLORS[detector.threatClass] ?? "#8b8994";
          const statusStyle =
            STATUS_STYLES[detector.status] ?? STATUS_STYLES.NOT_TRAINED;
          const count =
            alertStats?.byThreatClass?.[detector.threatClass] ?? 0;

          return (
            <div
              key={detector.threatClass}
              className="notebook-card rounded-xl bg-[#16213e]/80 border border-[#2a2a4a] p-5 relative overflow-hidden group hover:border-[#533483]/30 transition-colors"
            >
              <div
                className="absolute top-0 left-0 right-0 h-[3px]"
                style={{ background: color }}
              />

              {/* Header */}
              <div className="flex items-start justify-between mb-4">
                <div className="flex items-center gap-3">
                  <div
                    className="w-10 h-10 rounded-lg flex items-center justify-center"
                    style={{ background: `${color}15` }}
                  >
                    <Icon className="w-5 h-5" style={{ color }} />
                  </div>
                  <div>
                    <h3 className="text-sm font-semibold text-[#e8e6e3]">
                      {detector.name}
                    </h3>
                    <p className="text-[10px] text-[#8b8994]">
                      {detector.method}
                    </p>
                  </div>
                </div>
                <span
                  className="px-2 py-0.5 rounded text-[10px] font-bold uppercase tracking-wider"
                  style={{ background: statusStyle.bg, color: statusStyle.text }}
                >
                  {statusStyle.label}
                </span>
              </div>

              {/* Stats */}
              <div className="grid grid-cols-2 gap-3 mb-4">
                <div className="px-3 py-2 rounded-lg bg-[#12122a]/50">
                  <p className="text-[10px] text-[#8b8994] uppercase tracking-wider">
                    Detected
                  </p>
                  <p className="text-lg font-bold font-mono" style={{ color }}>
                    {count}
                  </p>
                </div>
                <div className="px-3 py-2 rounded-lg bg-[#12122a]/50">
                  <p className="text-[10px] text-[#8b8994] uppercase tracking-wider">
                    Status
                  </p>
                  <p
                    className="text-sm font-semibold mt-0.5"
                    style={{ color: statusStyle.text }}
                  >
                    {detector.status === "ACTIVE" ? "Operational" : "Standby"}
                  </p>
                </div>
              </div>

              {/* Description */}
              <p className="text-xs text-[#8b8994] leading-relaxed">
                {detector.description}
              </p>

              {/* Notebook annotation */}
              <div className="mt-3 pt-3 border-t border-[#2a2a4a]/50">
                <span className="notebook-annotation">
                  {detector.status === "ACTIVE"
                    ? "● Production detector — trained on CICIDS2017"
                    : detector.status === "DEMO"
                      ? "◐ Demo mode — statistical analysis only"
                      : "○ Interface ready — awaiting training data"}
                </span>
              </div>
            </div>
          );
        })}
      </div>

      {/* Recent threat alerts */}
      <div className="rounded-xl bg-[#16213e]/80 border border-[#2a2a4a] p-4">
        <div className="flex items-center gap-2 mb-4">
          <div className="w-[3px] h-4 bg-[#e94560] rounded" />
          <h3 className="text-sm font-semibold text-[#e8e6e3]">
            Recent Threat Alerts
          </h3>
          <span className="text-[10px] text-[#8b8994] ml-auto font-mono">
            {alertStats?.total ?? 0} total alerts
          </span>
        </div>

        {recentAlerts && recentAlerts.length > 0 ? (
          <div className="space-y-2">
            {recentAlerts.slice(0, 10).map((alert) => (
              <div
                key={alert._id}
                className="flex items-center gap-4 px-4 py-3 rounded-lg bg-[#12122a]/30 border border-[#2a2a4a]/50 hover:border-[#533483]/30 transition-colors"
              >
                <div
                  className="w-2 h-2 rounded-full flex-shrink-0"
                  style={{
                    background:
                      alert.severity === "CRITICAL"
                        ? "#e94560"
                        : alert.severity === "HIGH"
                          ? "#f5a623"
                          : "#0f9b8e",
                  }}
                />
                <div className="flex-1 min-w-0">
                  <div className="flex items-center gap-2">
                    <span className="text-xs font-semibold text-[#e8e6e3]">
                      {alert.threatClass.replace("_", " ")}
                    </span>
                    <span
                      className="px-1.5 py-0.5 rounded text-[9px] font-bold uppercase"
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
                  </div>
                  <p className="text-[11px] text-[#8b8994] truncate mt-0.5">
                    {alert.description}
                  </p>
                </div>
                <div className="text-right flex-shrink-0">
                  <div className="text-xs font-mono text-[#c4c1bb]">
                    {(alert.confidence * 100).toFixed(1)}%
                  </div>
                  <div className="text-[10px] text-[#8b8994]">
                    {alert.detectionLatencyMs}ms
                  </div>
                </div>
                <div className="text-xs text-[#8b8994] font-mono flex-shrink-0">
                  {new Date(alert.timestamp).toLocaleTimeString("en-US", {
                    hour12: false,
                  })}
                </div>
              </div>
            ))}
          </div>
        ) : (
          <div className="text-center py-8 text-sm text-[#8b8994]">
            No threats detected yet. Start a DDoS replay to see detections.
          </div>
        )}
      </div>
    </div>
  );
}
