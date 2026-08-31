import { Toaster } from "@/components/ui/sonner";
import React, { StrictMode, lazy, Suspense, useEffect } from "react";
import { createRoot } from "react-dom/client";
import { BrowserRouter, Route, Routes, useLocation } from "react-router";
import { ReplayProvider } from "@/lib/store";
import "./index.css";

// Lazy load route components
const Landing = lazy(() => import("./pages/Landing.tsx"));
const Overview = lazy(() => import("./pages/Overview.tsx"));
const Traffic = lazy(() => import("./pages/Traffic.tsx"));
const Threats = lazy(() => import("./pages/Threats.tsx"));
const Incidents = lazy(() => import("./pages/Incidents.tsx"));
const Analytics = lazy(() => import("./pages/Analytics.tsx"));
const ReplayLab = lazy(() => import("./pages/ReplayLab.tsx"));
const Health = lazy(() => import("./pages/Health.tsx"));
const NotFound = lazy(() => import("./pages/NotFound.tsx"));

// SOC layout
import { SOCLayout } from "@/components/soc/SOCLayout";

function RouteLoading() {
  return (
    <div className="min-h-screen flex items-center justify-center bg-[#1a1a2e]">
      <div className="text-center">
        <div className="animate-pulse text-[#8b8994] text-sm">
          Loading SOC Dashboard...
        </div>
      </div>
    </div>
  );
}

class RootErrorBoundary extends React.Component<
  { children: React.ReactNode },
  { hasError: boolean; message: string; stack: string }
> {
  state = { hasError: false, message: "", stack: "" };
  static getDerivedStateFromError(error: Error) {
    return {
      hasError: true,
      message: error.message || "Unknown runtime error",
      stack: error.stack || "",
    };
  }
  componentDidCatch(err: Error) {
    console.error("[Root crash]", err);
  }
  render() {
    if (this.state.hasError) {
      return (
        <div className="min-h-screen flex items-center justify-center bg-[#1a1a2e] text-[#e8e6e3] p-6">
          <div className="max-w-lg text-center">
            <p className="text-sm font-semibold">Runtime error</p>
            <p className="mt-2 text-xs text-[#8b8994] break-words">
              {this.state.message}
            </p>
          </div>
        </div>
      );
    }
    return this.props.children;
  }
}

function RouteSyncer() {
  const location = useLocation();
  useEffect(() => {
    window.parent.postMessage(
      { type: "iframe-route-change", path: location.pathname },
      "*",
    );
  }, [location.pathname]);
  return null;
}

createRoot(document.getElementById("root")!).render(
  <StrictMode>
    <RootErrorBoundary>
      <ReplayProvider>
        <BrowserRouter>
          <RouteSyncer />
          <Suspense fallback={<RouteLoading />}>
            <Routes>
              <Route path="/" element={<Landing />} />
              {/* SOC Dashboard routes - no auth required */}
              <Route path="/dashboard" element={<SOCLayout />}>
                <Route path="overview" element={<Overview />} />
                <Route path="traffic" element={<Traffic />} />
                <Route path="threats" element={<Threats />} />
                <Route path="incidents" element={<Incidents />} />
                <Route path="analytics" element={<Analytics />} />
                <Route path="replay" element={<ReplayLab />} />
                <Route path="health" element={<Health />} />
              </Route>
              <Route path="*" element={<NotFound />} />
            </Routes>
          </Suspense>
        </BrowserRouter>
        <Toaster />
      </ReplayProvider>
    </RootErrorBoundary>
  </StrictMode>,
);
