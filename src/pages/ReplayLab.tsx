import { useState, useRef, useCallback, useEffect } from "react";
import {
  FlaskConical,
  Play,
  Pause,
  Square,
  RotateCcw,
  Zap,
  AlertTriangle,
  Wifi,
  Radio,
  Globe,
  Lock,
  ScanSearch,
  ArrowUpFromLine,
  ArrowDown,
} from "lucide-react";
import { cn } from "@/lib/utils";
import { useReplayActions } from "@/lib/store";
import {
  getFlowGenerator,
  resetFlowCounter,
  analyzeFlow,
} from "@/lib/detection";
import {
  insertFlow,
  insertAlert,
  insertIncident,
  clearAllData,
  startReplayApi,
  pauseReplayApi,
  stopReplayApi,
  resetReplayApi,
  USE_BACKEND,
} from "@/services/api";
import type { Alert, NetworkFlow } from "@/lib/types";

const SCENARIOS = [
  { id: "normal", label: "Normal", icon: ArrowDown, color: "#0f9b8e" },
  { id: "ddos", label: "DDoS", icon: Wifi, color: "#e94560" },
  { id: "c2", label: "C2 Beacon", icon: Radio, color: "#f5a623" },
  { id: "dns", label: "DNS Tunnel", icon: Globe, color: "#0f9b8e" },
  { id: "encrypted_malware", label: "Encrypted Malware", icon: Lock, color: "#9b59b6" },
  { id: "recon", label: "Recon", icon: ScanSearch, color: "#48b9a7" },
  { id: "exfil", label: "Exfil", icon: ArrowUpFromLine, color: "#ff6b6b" },
];

export default function ReplayLab() {
  const { state: replayState, setState: setReplayState, reset: resetReplay } = useReplayActions();

  const [selectedScenario, setSelectedScenario] = useState("normal");
  const [targetRate, setTargetRate] = useState(100);
  const [lastAlert, setLastAlert] = useState<Alert | null>(null);
  const [sessionStats, setSessionStats] = useState({
    totalFlows: 0,
    threatsDetected: 0,
    avgLatency: 0,
    totalLatency: 0,
    measuredFps: 0,
  });
  const intervalRef = useRef<ReturnType<typeof setInterval> | null>(null);
  const fpsTimerRef = useRef<ReturnType<typeof setInterval> | null>(null);
  const flowsThisSecond = useRef(0);
  const alertCountRef = useRef(0);
  const totalFlowsRef = useRef(0);
  const sourceIpsRef = useRef(new Set<string>());
  const destIpsRef = useRef(new Set<string>());
  const startTimeRef = useRef(0);

  // Cleanup on unmount
  useEffect(() => {
    return () => {
      if (intervalRef.current) clearInterval(intervalRef.current);
      if (fpsTimerRef.current) clearInterval(fpsTimerRef.current);
    };
  }, []);

  const processFlow = useCallback(
    (flow: NetworkFlow) => {
      const { alert, updatedFlow, detectionTimeMs } = analyzeFlow(flow);

      // Insert flow directly into service store (syncs to backend if available)
      insertFlow(updatedFlow);
      flowsThisSecond.current++;
      sourceIpsRef.current.add(flow.sourceIp);
      destIpsRef.current.add(flow.destinationIp);

      if (alert) {
        setLastAlert(alert);
        alertCountRef.current++;

        insertAlert(alert);

        // Create incident on first threat or periodically
        if (alertCountRef.current === 1 || alertCountRef.current % 5 === 0) {
          insertIncident({
            timestamp: alert.timestamp,
            title: `${alert.threatClass.replace("_", " ")} Attack Detected`,
            description: alert.description,
            threatClass: alert.threatClass,
            severity: alert.severity,
            confidence: alert.confidence,
            alertCount: 1,
            sourceIps: Array.from(sourceIpsRef.current).slice(-5),
            destinationIps: Array.from(destIpsRef.current).slice(-5),
            evidence: alert.supportingEvidence,
            detector: alert.detector,
            detectionLatencyMs: alert.detectionLatencyMs,
            status: "open",
            scenario: selectedScenario,
          });

          setReplayState({ totalIncidents: replayState.totalIncidents + 1 });
        }
      }

      totalFlowsRef.current++;
      const currentTotal = totalFlowsRef.current;

      setSessionStats((prev) => {
        const newThreats = alert ? prev.threatsDetected + 1 : prev.threatsDetected;
        const newTotalLatency = prev.totalLatency + detectionTimeMs;
        return {
          totalFlows: currentTotal,
          threatsDetected: newThreats,
          avgLatency: Math.round(newTotalLatency / currentTotal),
          totalLatency: newTotalLatency,
          measuredFps: 0,
        };
      });

      setReplayState({
        totalFlows: currentTotal,
        processedFlows: currentTotal,
      });
    },
    [selectedScenario, setReplayState, replayState.totalIncidents],
  );

  const startReplay = useCallback(() => {
    resetFlowCounter();
    flowsThisSecond.current = 0;
    alertCountRef.current = 0;
    totalFlowsRef.current = 0;
    sourceIpsRef.current = new Set();
    destIpsRef.current = new Set();
    startTimeRef.current = Date.now();

    setReplayState({
      status: "running",
      scenario: selectedScenario,
      dataset: "synthetic",
      mode: "REPLAY",
      speed: targetRate,
      flowsPerSecond: targetRate,
      totalFlows: 0,
      processedFlows: 0,
      totalAlerts: 0,
      totalIncidents: 0,
    });

    setSessionStats({
      totalFlows: 0,
      threatsDetected: 0,
      avgLatency: 0,
      totalLatency: 0,
      measuredFps: 0,
    });

    // Notify backend about replay start
    if (USE_BACKEND) {
      startReplayApi({
        scenario: selectedScenario,
        speed: targetRate,
        dataset: "synthetic",
      }).catch(() => {});
    }

    const generator = getFlowGenerator(selectedScenario);
    const intervalMs = Math.max(1, Math.floor(1000 / targetRate));

    if (intervalRef.current) clearInterval(intervalRef.current);
    intervalRef.current = setInterval(() => {
      const flow = generator();
      processFlow(flow);
    }, intervalMs);

    // Measure actual FPS
    if (fpsTimerRef.current) clearInterval(fpsTimerRef.current);
    flowsThisSecond.current = 0;
    fpsTimerRef.current = setInterval(() => {
      const measured = flowsThisSecond.current;
      flowsThisSecond.current = 0;
      setSessionStats((prev) => ({ ...prev, measuredFps: measured }));
      setReplayState({ measuredFlowsPerSecond: measured });
    }, 1000);
  }, [selectedScenario, targetRate, processFlow, setReplayState]);

  const pauseReplay = useCallback(() => {
    if (intervalRef.current) clearInterval(intervalRef.current);
    if (fpsTimerRef.current) clearInterval(fpsTimerRef.current);
    setReplayState({ status: "paused", measuredFlowsPerSecond: 0 });
    if (USE_BACKEND) {
      pauseReplayApi().catch(() => {});
    }
  }, [setReplayState]);

  const stopReplay = useCallback(() => {
    if (intervalRef.current) clearInterval(intervalRef.current);
    if (fpsTimerRef.current) clearInterval(fpsTimerRef.current);
    setReplayState({ status: "stopped", measuredFlowsPerSecond: 0 });
    if (USE_BACKEND) {
      stopReplayApi().catch(() => {});
    }
  }, [setReplayState]);

  const resumeReplay = useCallback(() => {
    const generator = getFlowGenerator(selectedScenario);
    const intervalMs = Math.max(1, Math.floor(1000 / targetRate));

    setReplayState({ status: "running" });

    // Notify backend
    if (USE_BACKEND) {
      startReplayApi({
        scenario: selectedScenario,
        speed: targetRate,
        dataset: "synthetic",
      }).catch(() => {});
    }

    flowsThisSecond.current = 0;
    intervalRef.current = setInterval(() => {
      const flow = generator();
      processFlow(flow);
    }, intervalMs);

    fpsTimerRef.current = setInterval(() => {
      const measured = flowsThisSecond.current;
      flowsThisSecond.current = 0;
      setSessionStats((prev) => ({ ...prev, measuredFps: measured }));
      setReplayState({ measuredFlowsPerSecond: measured });
    }, 1000);
  }, [selectedScenario, targetRate, processFlow, setReplayState]);

  const resetAll = useCallback(() => {
    if (intervalRef.current) clearInterval(intervalRef.current);
    if (fpsTimerRef.current) clearInterval(fpsTimerRef.current);
    resetFlowCounter();
    resetReplay();
    setLastAlert(null);
    alertCountRef.current = 0;
    totalFlowsRef.current = 0;
    sourceIpsRef.current = new Set();
    destIpsRef.current = new Set();
    setSessionStats({
      totalFlows: 0,
      threatsDetected: 0,
      avgLatency: 0,
      totalLatency: 0,
      measuredFps: 0,
    });
    clearAllData();
  }, [resetReplay]);

  const isRunning = replayState.status === "running";
  const isPaused = replayState.status === "paused";

  return (
    <div className="space-y-6">
      {/* Header */}
      <div>
        <h1 className="text-2xl font-bold text-[#e8e6e3] flex items-center gap-3">
          <FlaskConical className="w-6 h-6 text-[#533483]" />
          Replay Lab
        </h1>
        <p className="text-sm text-[#8b8994] mt-1">
          Replay recorded or synthetic traffic through the detection pipeline
        </p>
      </div>

      {/* Safety notice */}
      <div className="flex items-center gap-2 px-3 py-2 rounded-lg bg-[#e94560]/5 border border-[#e94560]/15">
        <AlertTriangle className="w-3.5 h-3.5 text-[#e94560] flex-shrink-0" />
        <span className="text-xs text-[#e94560]">
          This system replays recorded/synthetic data only. No real attacks are
          generated. No return path to monitored networks.
        </span>
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        {/* Controls panel */}
        <div className="space-y-4">
          {/* Data source */}
          <div className="rounded-xl bg-[#16213e]/80 border border-[#2a2a4a] p-4">
            <div className="flex items-center gap-2 mb-3">
              <div className="w-[3px] h-4 bg-[#533483] rounded" />
              <h3 className="text-xs font-semibold text-[#e8e6e3] uppercase tracking-wider">
                Data Source
              </h3>
            </div>
            <div className="px-3 py-2 rounded-lg bg-[#533483]/10 border border-[#533483]/20 text-center">
              <span className="text-sm font-medium text-[#533483]">
                DEMO SYNTHETIC DATA
              </span>
            </div>
            <p className="text-[10px] text-[#8b8994] mt-2 italic">
              Synthetic flow records for demonstration. CICIDS2017 data can be
              added to the data/ directory.
            </p>
          </div>

          {/* Mode */}
          <div className="rounded-xl bg-[#16213e]/80 border border-[#2a2a4a] p-4">
            <div className="flex items-center gap-2 mb-3">
              <div className="w-[3px] h-4 bg-[#0f9b8e] rounded" />
              <h3 className="text-xs font-semibold text-[#e8e6e3] uppercase tracking-wider">
                Mode
              </h3>
            </div>
            <div className="px-3 py-2 rounded-lg bg-[#0f9b8e]/10 border border-[#0f9b8e]/20 text-center">
              <span className="text-sm font-medium text-[#0f9b8e] uppercase tracking-wider">
                {replayState.mode}
              </span>
            </div>
          </div>

          {/* Throughput */}
          <div className="rounded-xl bg-[#16213e]/80 border border-[#2a2a4a] p-4">
            <div className="flex items-center gap-2 mb-3">
              <div className="w-[3px] h-4 bg-[#f5a623] rounded" />
              <h3 className="text-xs font-semibold text-[#e8e6e3] uppercase tracking-wider">
                Throughput
              </h3>
            </div>
            <div className="grid grid-cols-2 gap-2">
              <div className="px-3 py-2 rounded bg-[#12122a]/50 text-center">
                <p className="text-[10px] text-[#8b8994] uppercase">
                  Target
                </p>
                <p className="text-lg font-bold font-mono text-[#f5a623]">
                  {targetRate}
                </p>
                <p className="text-[9px] text-[#8b8994]">flows/sec</p>
              </div>
              <div className="px-3 py-2 rounded bg-[#12122a]/50 text-center">
                <p className="text-[10px] text-[#8b8994] uppercase">
                  Measured
                </p>
                <p className="text-lg font-bold font-mono text-[#0f9b8e]">
                  {sessionStats.measuredFps}
                </p>
                <p className="text-[9px] text-[#8b8994]">flows/sec</p>
              </div>
            </div>
          </div>

          {/* Rate selector */}
          <div className="rounded-xl bg-[#16213e]/80 border border-[#2a2a4a] p-4">
            <div className="flex items-center gap-2 mb-3">
              <div className="w-[3px] h-4 bg-[#48b9a7] rounded" />
              <h3 className="text-xs font-semibold text-[#e8e6e3] uppercase tracking-wider">
                Replay Rate
              </h3>
            </div>
            <div className="flex gap-2">
              {[50, 100, 200, 500, 1000].map((rate) => (
                <button
                  key={rate}
                  onClick={() => setTargetRate(rate)}
                  className={cn(
                    "px-2.5 py-1.5 rounded text-xs font-medium transition-colors",
                    targetRate === rate
                      ? "bg-[#48b9a7] text-[#1a1a2e]"
                      : "bg-[#12122a] text-[#8b8994] hover:text-[#e8e6e3] border border-[#2a2a4a]",
                  )}
                >
                  {rate}
                </button>
              ))}
            </div>
          </div>

          {/* Control buttons */}
          <div className="rounded-xl bg-[#16213e]/80 border border-[#2a2a4a] p-4">
            <div className="flex items-center gap-2 mb-3">
              <div className="w-[3px] h-4 bg-[#e94560] rounded" />
              <h3 className="text-xs font-semibold text-[#e8e6e3] uppercase tracking-wider">
                Controls
              </h3>
            </div>
            <div className="grid grid-cols-2 gap-2">
              {!isRunning ? (
                <button
                  onClick={isPaused ? resumeReplay : startReplay}
                  className="flex items-center justify-center gap-2 px-4 py-2.5 rounded-lg bg-[#0f9b8e] text-[#1a1a2e] text-sm font-semibold hover:bg-[#0f9b8e]/80 transition-colors"
                >
                  <Play className="w-3.5 h-3.5" />
                  {isPaused ? "Resume" : "Start"}
                </button>
              ) : (
                <button
                  onClick={pauseReplay}
                  className="flex items-center justify-center gap-2 px-4 py-2.5 rounded-lg bg-[#f5a623] text-[#1a1a2e] text-sm font-semibold hover:bg-[#f5a623]/80 transition-colors"
                >
                  <Pause className="w-3.5 h-3.5" />
                  Pause
                </button>
              )}
              <button
                onClick={stopReplay}
                className="flex items-center justify-center gap-2 px-4 py-2.5 rounded-lg bg-[#e94560]/20 text-[#e94560] text-sm font-semibold border border-[#e94560]/30 hover:bg-[#e94560]/30 transition-colors"
              >
                <Square className="w-3.5 h-3.5" />
                Stop
              </button>
              <button
                onClick={resetAll}
                className="col-span-2 flex items-center justify-center gap-2 px-4 py-2.5 rounded-lg bg-[#12122a] text-[#8b8994] text-sm font-medium border border-[#2a2a4a] hover:text-[#e8e6e3] hover:border-[#533483]/30 transition-colors"
              >
                <RotateCcw className="w-3.5 h-3.5" />
                Reset All
              </button>
            </div>
          </div>
        </div>

        {/* Scenario selection */}
        <div className="space-y-4">
          <div className="rounded-xl bg-[#16213e]/80 border border-[#2a2a4a] p-4">
            <div className="flex items-center gap-2 mb-3">
              <div className="w-[3px] h-4 bg-[#533483] rounded" />
              <h3 className="text-xs font-semibold text-[#e8e6e3] uppercase tracking-wider">
                Threat Scenario
              </h3>
            </div>
            <div className="space-y-2">
              {SCENARIOS.map((scenario) => (
                <button
                  key={scenario.id}
                  onClick={() => setSelectedScenario(scenario.id)}
                  className={cn(
                    "w-full flex items-center gap-3 px-3 py-2.5 rounded-lg text-sm transition-all",
                    selectedScenario === scenario.id
                      ? "border-2"
                      : "bg-[#12122a]/50 border border-[#2a2a4a] hover:border-[#533483]/30",
                  )}
                  style={
                    selectedScenario === scenario.id
                      ? {
                          background: `${scenario.color}10`,
                          borderColor: `${scenario.color}40`,
                          color: scenario.color,
                        }
                      : { color: "#8b8994" }
                  }
                >
                  <scenario.icon className="w-4 h-4 flex-shrink-0" />
                  <span className="font-medium">{scenario.label}</span>
                  {selectedScenario === scenario.id && (
                    <span className="ml-auto text-[10px] uppercase tracking-wider opacity-70">
                      Selected
                    </span>
                  )}
                </button>
              ))}
            </div>
            <p className="text-[10px] text-[#8b8994] mt-3 italic">
              These buttons replay recorded/synthetic flow records only. They do
              NOT launch real cyberattacks.
            </p>
          </div>

          {/* Session stats */}
          <div className="rounded-xl bg-[#16213e]/80 border border-[#2a2a4a] p-4">
            <div className="flex items-center gap-2 mb-3">
              <div className="w-[3px] h-4 bg-[#e94560] rounded" />
              <h3 className="text-xs font-semibold text-[#e8e6e3] uppercase tracking-wider">
                Session Statistics
              </h3>
            </div>
            <div className="space-y-2">
              {[
                { label: "Total Flows", value: sessionStats.totalFlows, color: "#533483" },
                { label: "Threats Detected", value: sessionStats.threatsDetected, color: "#e94560" },
                { label: "Avg Latency", value: `${sessionStats.avgLatency}ms`, color: "#f5a623" },
                { label: "Source IPs", value: sourceIpsRef.current.size, color: "#0f9b8e" },
              ].map((stat) => (
                <div
                  key={stat.label}
                  className="flex items-center justify-between px-3 py-2 rounded bg-[#12122a]/50"
                >
                  <span className="text-xs text-[#8b8994]">{stat.label}</span>
                  <span
                    className="text-sm font-bold font-mono"
                    style={{ color: stat.color }}
                  >
                    {stat.value}
                  </span>
                </div>
              ))}
            </div>
          </div>
        </div>

        {/* Live detection result */}
        <div className="space-y-4">
          {/* Status indicator */}
          <div
            className={cn(
              "rounded-xl border p-4 transition-all",
              isRunning
                ? "bg-[#0f9b8e]/5 border-[#0f9b8e]/30"
                : isPaused
                  ? "bg-[#f5a623]/5 border-[#f5a623]/30"
                  : "bg-[#16213e]/80 border-[#2a2a4a]",
            )}
          >
            <div className="flex items-center gap-3">
              <div
                className={cn(
                  "w-3 h-3 rounded-full",
                  isRunning ? "bg-[#0f9b8e] status-pulse" : isPaused ? "bg-[#f5a623]" : "bg-[#8b8994]",
                )}
              />
              <div>
                <p className="text-sm font-semibold text-[#e8e6e3]">
                  {isRunning
                    ? "Replay Active"
                    : isPaused
                      ? "Replay Paused"
                      : "Replay Idle"}
                </p>
                <p className="text-[10px] text-[#8b8994] uppercase tracking-wider">
                  {isRunning ? "Processing flows" : isPaused ? "Click resume to continue" : "Select scenario and click start"}
                </p>
              </div>
            </div>
          </div>

          {/* Last alert */}
          {lastAlert && (
            <div
              className={cn(
                "rounded-xl border p-4 threat-critical-glow",
                lastAlert.severity === "CRITICAL"
                  ? "bg-[#e94560]/5 border-[#e94560]/30"
                  : "bg-[#f5a623]/5 border-[#f5a623]/30",
              )}
            >
              <div className="flex items-center gap-2 mb-3">
                <Zap
                  className="w-4 h-4"
                  style={{
                    color:
                      lastAlert.severity === "CRITICAL"
                        ? "#e94560"
                        : "#f5a623",
                  }}
                />
                <span
                  className="text-xs font-bold uppercase tracking-wider"
                  style={{
                    color:
                      lastAlert.severity === "CRITICAL"
                        ? "#e94560"
                        : "#f5a623",
                  }}
                >
                  {lastAlert.severity} Threat
                </span>
              </div>
              <h3 className="text-lg font-bold text-[#e8e6e3]">
                {lastAlert.threatClass.replace("_", " ")} DETECTED
              </h3>
              <p className="text-xs text-[#8b8994] mt-1">
                {lastAlert.description}
              </p>

              <div className="grid grid-cols-2 gap-2 mt-3">
                <div className="px-3 py-2 rounded bg-[#12122a]/50">
                  <p className="text-[10px] text-[#8b8994] uppercase">Confidence</p>
                  <p className="text-lg font-bold font-mono text-[#e94560]">
                    {(lastAlert.confidence * 100).toFixed(1)}%
                  </p>
                </div>
                <div className="px-3 py-2 rounded bg-[#12122a]/50">
                  <p className="text-[10px] text-[#8b8994] uppercase">Latency</p>
                  <p className="text-lg font-bold font-mono text-[#f5a623]">
                    {lastAlert.detectionLatencyMs}ms
                  </p>
                </div>
              </div>

              {/* Evidence */}
              <div className="mt-3 pt-3 border-t border-[#2a2a4a]">
                <p className="text-[10px] text-[#f5a623] uppercase tracking-wider font-medium mb-2">
                  Supporting Evidence
                </p>
                <div className="grid grid-cols-2 gap-1.5">
                  {Object.entries(lastAlert.supportingEvidence)
                    .filter(([key]) => !key.startsWith("model") && !key.startsWith("detector"))
                    .slice(0, 6)
                    .map(([key, value]) => (
                      <div
                        key={key}
                        className="px-2 py-1.5 rounded bg-[#12122a]/50"
                      >
                        <p className="text-[9px] text-[#8b8994] uppercase">
                          {key.replace(/_/g, " ")}
                        </p>
                        <p className="text-xs font-mono text-[#e8e6e3]">
                          {typeof value === "number"
                            ? value.toLocaleString()
                            : String(value)}
                        </p>
                      </div>
                    ))}
                </div>
              </div>
            </div>
          )}

          {/* Detection pipeline visualization */}
          <div className="rounded-xl bg-[#16213e]/80 border border-[#2a2a4a] p-4">
            <div className="flex items-center gap-2 mb-3">
              <div className="w-[3px] h-4 bg-[#0f9b8e] rounded" />
              <h3 className="text-xs font-semibold text-[#e8e6e3] uppercase tracking-wider">
                Detection Pipeline
              </h3>
            </div>
            <div className="space-y-2">
              {[
                { step: "1", label: "Simulated IP Traffic", active: isRunning || isPaused },
                { step: "2", label: "Read-Only Ingestion", active: isRunning || isPaused },
                { step: "3", label: "Feature Extraction", active: isRunning || isPaused },
                { step: "4", label: "DDoS AI Inference", active: isRunning || isPaused },
                { step: "5", label: "Alert Generation", active: isRunning || isPaused },
                { step: "6", label: "Dashboard Update", active: isRunning || isPaused },
              ].map((item) => (
                <div
                  key={item.step}
                  className={cn(
                    "flex items-center gap-3 px-3 py-2 rounded-lg transition-all",
                    item.active
                      ? "bg-[#0f9b8e]/5 border border-[#0f9b8e]/15"
                      : "bg-[#12122a]/30 border border-[#2a2a4a]/30",
                  )}
                >
                  <div
                    className={cn(
                      "w-5 h-5 rounded-full flex items-center justify-center text-[10px] font-bold",
                      item.active
                        ? "bg-[#0f9b8e] text-[#1a1a2e]"
                        : "bg-[#2a2a4a] text-[#8b8994]",
                    )}
                  >
                    {item.step}
                  </div>
                  <span
                    className={cn(
                      "text-xs",
                      item.active ? "text-[#e8e6e3]" : "text-[#8b8994]",
                    )}
                  >
                    {item.label}
                  </span>
                  {item.active && isRunning && (
                    <div className="ml-auto">
                      <div className="w-1.5 h-1.5 rounded-full bg-[#0f9b8e] animate-pulse" />
                    </div>
                  )}
                </div>
              ))}
            </div>
          </div>
        </div>
      </div>
    </div>
  );
}
