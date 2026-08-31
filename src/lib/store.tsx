// Lightweight replay state store using React state
// Avoids adding zustand dependency

import { createContext, useContext, useState, type ReactNode } from "react";

export interface ReplayStateData {
  status: "idle" | "running" | "paused" | "stopped";
  speed: number;
  flowsPerSecond: number;
  measuredFlowsPerSecond: number;
  dataset: string;
  scenario: string;
  totalFlows: number;
  processedFlows: number;
  mode: "LIVE" | "REPLAY" | "MOCK";
  totalAlerts: number;
  totalIncidents: number;
}

const defaultState: ReplayStateData = {
  status: "idle",
  speed: 100,
  flowsPerSecond: 100,
  measuredFlowsPerSecond: 0,
  dataset: "synthetic",
  scenario: "normal",
  totalFlows: 0,
  processedFlows: 0,
  mode: "REPLAY",
  totalAlerts: 0,
  totalIncidents: 0,
};

interface ReplayStore {
  state: ReplayStateData;
  setState: (update: Partial<ReplayStateData>) => void;
  reset: () => void;
}

const ReplayContext = createContext<ReplayStore | null>(null);

export function ReplayProvider({ children }: { children: ReactNode }) {
  const [state, setInternalState] = useState(defaultState);

  const setState = (update: Partial<ReplayStateData>) => {
    setInternalState((prev) => ({ ...prev, ...update }));
  };

  const reset = () => setInternalState(defaultState);

  return (
    <ReplayContext.Provider value={{ state, setState, reset }}>
      {children}
    </ReplayContext.Provider>
  );
}

export function useReplayStore() {
  const ctx = useContext(ReplayContext);
  if (!ctx) return defaultState;
  return ctx.state;
}

export function useReplayActions() {
  const ctx = useContext(ReplayContext);
  if (!ctx) {
    return {
      state: defaultState,
      setState: () => {},
      reset: () => {},
    };
  }
  return ctx;
}
