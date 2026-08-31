import { motion } from "framer-motion";
import { useNavigate } from "react-router";
import {
  ShieldAlert,
  Radio,
  Lock,
  Eye,
  Zap,
  Activity,
  ArrowRight,
  Check,
  AlertTriangle,
  Brain,
  Database,
  Wifi,
  Server,
} from "lucide-react";

const FEATURES = [
  {
    icon: Eye,
    title: "Passive Monitoring",
    description:
      "Read-only ingest with zero return path. No active probing, no inline mitigation.",
    color: "#0f9b8e",
  },
  {
    icon: Brain,
    title: "AI/ML Detection",
    description:
      "Random Forest classifier trained on CICIDS2017 for real-time DDoS classification.",
    color: "#533483",
  },
  {
    icon: Zap,
    title: "Real-Time Alerts",
    description:
      "Standardized alert schema with confidence scores, severity, and supporting evidence.",
    color: "#e94560",
  },
  {
    icon: Database,
    title: "Streaming Pipeline",
    description:
      "Incremental flow processing with configurable replay rates up to 1000 flows/sec.",
    color: "#f5a623",
  },
  {
    icon: Activity,
    title: "SOC Dashboard",
    description:
      "Professional Security Operations Center interface with live metrics and analytics.",
    color: "#48b9a7",
  },
  {
    icon: ShieldAlert,
    title: "Six Threat Categories",
    description:
      "DDoS, C2 Beaconing, DNS Tunnelling, Encrypted Malware, Recon, and Data Exfiltration.",
    color: "#ff6b6b",
  },
];

const COMPLIANCE = [
  "Read-only ingest",
  "No return path",
  "No active probing",
  "No payload decryption",
  "Streaming/replay processing",
  "Defined throughput metrics",
  "Detection latency measurement",
  "Standardized alert schema",
  "Confidence scoring",
  "Supporting evidence",
  "Six threat categories",
  "Visual SOC dashboard",
];

export default function Landing() {
  const navigate = useNavigate();

  return (
    <div className="min-h-screen bg-[#1a1a2e] text-[#e8e6e3] overflow-x-hidden">
      {/* Hero Section */}
      <section className="relative min-h-screen flex items-center justify-center px-6">
        {/* Background pattern — notebook grain */}
        <div className="absolute inset-0 opacity-[0.03]"
          style={{
            backgroundImage: `url("data:image/svg+xml,%3Csvg viewBox='0 0 256 256' xmlns='http://www.w3.org/2000/svg'%3E%3Cfilter id='noise'%3E%3CfeTurbulence type='fractalNoise' baseFrequency='0.9' numOctaves='4' stitchTiles='stitch'/%3E%3C/filter%3E%3Crect width='100%25' height='100%25' filter='url(%23noise)'/%3E%3C/svg%3E")`,
          }}
        />

        {/* Ruled lines */}
        <div className="absolute inset-0 opacity-[0.03]"
          style={{
            backgroundImage: "repeating-linear-gradient(transparent, transparent 39px, #e8e6e3 39px, #e8e6e3 40px)",
          }}
        />

        {/* Margin line */}
        <div className="absolute left-[72px] top-0 bottom-0 w-[2px] bg-[#e94560]/10" />

        <div className="relative max-w-5xl mx-auto text-center">
          {/* Badge */}
          <motion.div
            initial={{ opacity: 0, y: 20 }}
            animate={{ opacity: 1, y: 0 }}
            transition={{ duration: 0.5 }}
            className="inline-flex items-center gap-2 px-4 py-2 rounded-full bg-[#e94560]/10 border border-[#e94560]/20 mb-8"
          >
            <div className="w-2 h-2 rounded-full bg-[#e94560] status-pulse" />
            <span className="text-xs font-medium text-[#e94560] uppercase tracking-wider">
              SIH26145 — Smart India Hackathon 2026
            </span>
          </motion.div>

          {/* Main heading */}
          <motion.h1
            initial={{ opacity: 0, y: 20 }}
            animate={{ opacity: 1, y: 0 }}
            transition={{ duration: 0.5, delay: 0.1 }}
            className="text-4xl md:text-6xl font-bold leading-tight mb-6"
          >
            AI-Based Detection of
            <br />
            <span className="text-[#e94560]">Cyber Threats</span> in
            <br />
            <span className="text-[#533483]">Unidirectional IP Traffic</span>
          </motion.h1>

          <motion.p
            initial={{ opacity: 0, y: 20 }}
            animate={{ opacity: 1, y: 0 }}
            transition={{ duration: 0.5, delay: 0.2 }}
            className="text-lg text-[#8b8994] max-w-2xl mx-auto mb-10 leading-relaxed"
          >
            A passive cybersecurity monitoring system powered by AI/ML that
            detects threats in one-directional IP traffic from a simulated data
            diode environment. Zero return path. Zero active probing.
          </motion.p>

          {/* Status badges */}
          <motion.div
            initial={{ opacity: 0, y: 20 }}
            animate={{ opacity: 1, y: 0 }}
            transition={{ duration: 0.5, delay: 0.3 }}
            className="flex flex-wrap items-center justify-center gap-3 mb-10"
          >
            {[
              { label: "PASSIVE MONITORING", icon: Radio, color: "#0f9b8e" },
              { label: "READ-ONLY INGEST", icon: Lock, color: "#533483" },
              { label: "NO RETURN PATH", icon: ShieldAlert, color: "#e94560" },
            ].map((badge) => (
              <div
                key={badge.label}
                className="flex items-center gap-2 px-3 py-1.5 rounded-md border"
                style={{
                  background: `${badge.color}08`,
                  borderColor: `${badge.color}25`,
                }}
              >
                <badge.icon className="w-3 h-3" style={{ color: badge.color }} />
                <span
                  className="text-[10px] font-bold uppercase tracking-wider"
                  style={{ color: badge.color }}
                >
                  {badge.label}
                </span>
              </div>
            ))}
          </motion.div>

          {/* CTA */}
          <motion.div
            initial={{ opacity: 0, y: 20 }}
            animate={{ opacity: 1, y: 0 }}
            transition={{ duration: 0.5, delay: 0.4 }}
            className="flex flex-wrap items-center justify-center gap-4"
          >
            <button
              onClick={() => navigate("/auth?returnTo=/dashboard/replay")}
              className="flex items-center gap-2 px-8 py-3.5 rounded-xl bg-[#e94560] text-[#1a1a2e] font-bold text-sm hover:bg-[#e94560]/85 transition-colors shadow-lg shadow-[#e94560]/20"
            >
              Launch SOC Dashboard
              <ArrowRight className="w-4 h-4" />
            </button>
            <button
              onClick={() => navigate("/auth?returnTo=/dashboard/overview")}
              className="flex items-center gap-2 px-8 py-3.5 rounded-xl bg-[#533483]/20 text-[#e8e6e3] font-semibold text-sm border border-[#533483]/30 hover:bg-[#533483]/30 transition-colors"
            >
              View Overview
            </button>
          </motion.div>

          {/* Scroll indicator */}
          <motion.div
            initial={{ opacity: 0 }}
            animate={{ opacity: 1 }}
            transition={{ duration: 0.5, delay: 0.8 }}
            className="mt-16"
          >
            <div className="animate-bounce">
              <div className="w-5 h-8 rounded-full border-2 border-[#8b8994]/30 mx-auto flex items-start justify-center pt-1.5">
                <div className="w-1 h-1.5 rounded-full bg-[#8b8994]/50" />
              </div>
            </div>
          </motion.div>
        </div>
      </section>

      {/* Features Section */}
      <section className="py-24 px-6">
        <div className="max-w-5xl mx-auto">
          <motion.div
            initial={{ opacity: 0, y: 20 }}
            whileInView={{ opacity: 1, y: 0 }}
            viewport={{ once: true }}
            transition={{ duration: 0.5 }}
            className="text-center mb-16"
          >
            <span className="notebook-annotation text-[#f5a623]">
              § System Capabilities
            </span>
            <h2 className="text-3xl font-bold mt-2 mb-4">
              Built for Passive Threat Detection
            </h2>
            <p className="text-[#8b8994] max-w-xl mx-auto">
              Modular AI/ML detector architecture with independent threat
              classifiers and transparent evidence generation.
            </p>
          </motion.div>

          <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
            {FEATURES.map((feature, i) => (
              <motion.div
                key={feature.title}
                initial={{ opacity: 0, y: 20 }}
                whileInView={{ opacity: 1, y: 0 }}
                viewport={{ once: true }}
                transition={{ duration: 0.4, delay: i * 0.1 }}
                className="notebook-card rounded-xl bg-[#16213e]/80 border border-[#2a2a4a] p-5 hover:border-[#533483]/30 transition-colors group"
              >
                <div
                  className="w-10 h-10 rounded-lg flex items-center justify-center mb-3"
                  style={{ background: `${feature.color}15` }}
                >
                  <feature.icon
                    className="w-5 h-5"
                    style={{ color: feature.color }}
                  />
                </div>
                <h3 className="text-sm font-semibold text-[#e8e6e3] mb-2">
                  {feature.title}
                </h3>
                <p className="text-xs text-[#8b8994] leading-relaxed">
                  {feature.description}
                </p>
              </motion.div>
            ))}
          </div>
        </div>
      </section>

      {/* Architecture Section */}
      <section className="py-24 px-6 bg-[#12122a]/50">
        <div className="max-w-5xl mx-auto">
          <motion.div
            initial={{ opacity: 0, y: 20 }}
            whileInView={{ opacity: 1, y: 0 }}
            viewport={{ once: true }}
            className="text-center mb-12"
          >
            <span className="notebook-annotation text-[#0f9b8e]">
              § System Architecture
            </span>
            <h2 className="text-3xl font-bold mt-2 mb-4">
              Detection Pipeline
            </h2>
          </motion.div>

          <motion.div
            initial={{ opacity: 0, y: 20 }}
            whileInView={{ opacity: 1, y: 0 }}
            viewport={{ once: true }}
            className="flex flex-wrap items-center justify-center gap-3"
          >
            {[
              { label: "Simulated Traffic", color: "#6c7a89" },
              { label: "Read-Only Ingest", color: "#0f9b8e" },
              { label: "Stream/Replay", color: "#48b9a7" },
              { label: "Feature Extraction", color: "#533483" },
              { label: "AI Detection", color: "#e94560" },
              { label: "Alert Engine", color: "#f5a623" },
              { label: "Standardized Alert", color: "#ff6b6b" },
              { label: "SOC Dashboard", color: "#0f9b8e" },
            ].map((step, i) => (
              <div key={step.label} className="flex items-center gap-2">
                <div
                  className="px-4 py-2.5 rounded-lg text-xs font-medium border"
                  style={{
                    background: `${step.color}10`,
                    borderColor: `${step.color}25`,
                    color: step.color,
                  }}
                >
                  {step.label}
                </div>
                {i < 7 && (
                  <span className="text-[#8b8994]/30 text-xs">→</span>
                )}
              </div>
            ))}
          </motion.div>
        </div>
      </section>

      {/* SIH Compliance Section */}
      <section className="py-24 px-6">
        <div className="max-w-5xl mx-auto">
          <motion.div
            initial={{ opacity: 0, y: 20 }}
            whileInView={{ opacity: 1, y: 0 }}
            viewport={{ once: true }}
            className="text-center mb-12"
          >
            <span className="notebook-annotation text-[#e94560]">
              § SIH Requirement Compliance
            </span>
            <h2 className="text-3xl font-bold mt-2 mb-4">
              Meeting Every Requirement
            </h2>
          </motion.div>

          <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-2">
            {COMPLIANCE.map((item, i) => (
              <motion.div
                key={item}
                initial={{ opacity: 0, x: -10 }}
                whileInView={{ opacity: 1, x: 0 }}
                viewport={{ once: true }}
                transition={{ duration: 0.3, delay: i * 0.05 }}
                className="flex items-center gap-2 px-4 py-2.5 rounded-lg bg-[#16213e]/50 border border-[#2a2a4a]/50"
              >
                <Check className="w-4 h-4 text-[#0f9b8e] flex-shrink-0" />
                <span className="text-sm text-[#e8e6e3]">{item}</span>
              </motion.div>
            ))}
          </div>
        </div>
      </section>

      {/* Footer */}
      <footer className="py-12 px-6 border-t border-[#2a2a4a]">
        <div className="max-w-5xl mx-auto text-center">
          <div className="flex items-center justify-center gap-3 mb-4">
            <ShieldAlert className="w-5 h-5 text-[#e94560]" />
            <span className="text-sm font-bold text-[#e8e6e3]">
              SIH26145 — AI-Based Cyber Threat Detection
            </span>
          </div>
          <p className="text-xs text-[#8b8994]">
            Passive monitoring system for unidirectional IP traffic.
            No offensive capabilities. No real attack generation.
            Built for Smart India Hackathon 2026.
          </p>
          <div className="flex items-center justify-center gap-2 mt-4">
            <div className="w-2 h-2 rounded-full bg-[#0f9b8e] status-pulse" />
            <span className="text-[10px] text-[#0f9b8e] uppercase tracking-wider font-medium">
              Passive Monitoring Active
            </span>
          </div>
        </div>
      </footer>
    </div>
  );
}
