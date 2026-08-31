import { useState, useEffect } from "react";
import { NavLink, Outlet } from "react-router";
import {
  LayoutDashboard,
  Activity,
  ShieldAlert,
  AlertTriangle,
  BarChart3,
  FlaskConical,
  HeartPulse,
  Radio,
  Lock,
  X,
  Menu,
} from "lucide-react";
import { cn } from "@/lib/utils";

const NAV_ITEMS = [
  { label: "Overview", icon: LayoutDashboard, path: "/dashboard/overview" },
  { label: "Live Traffic", icon: Activity, path: "/dashboard/traffic" },
  { label: "Threats", icon: ShieldAlert, path: "/dashboard/threats" },
  { label: "Incidents", icon: AlertTriangle, path: "/dashboard/incidents" },
  { label: "Analytics", icon: BarChart3, path: "/dashboard/analytics" },
  { label: "Replay Lab", icon: FlaskConical, path: "/dashboard/replay" },
  { label: "System Health", icon: HeartPulse, path: "/dashboard/health" },
];

export function SOCLayout() {
  const [sidebarOpen, setSidebarOpen] = useState(true);
  const [currentTime, setCurrentTime] = useState(new Date());

  useEffect(() => {
    const timer = setInterval(() => setCurrentTime(new Date()), 1000);
    return () => clearInterval(timer);
  }, []);

  return (
    <div className="flex h-screen overflow-hidden bg-[#1a1a2e]">
      {/* Sidebar */}
      <aside
        className={cn(
          "flex flex-col border-r-2 border-[#2a2a4a] bg-[#12122a] transition-all duration-300 relative",
          sidebarOpen ? "w-64" : "w-16",
        )}
      >
        {/* Sidebar margin line */}
        <div className="absolute right-0 top-0 bottom-0 w-[2px] bg-gradient-to-b from-transparent via-[#e94560]/30 to-transparent" />

        {/* Logo area */}
        <div className="flex items-center gap-3 px-4 py-4 border-b border-[#2a2a4a]">
          <div className="flex-shrink-0 w-8 h-8 rounded-lg bg-[#e94560]/20 flex items-center justify-center">
            <ShieldAlert className="w-4 h-4 text-[#e94560]" />
          </div>
          {sidebarOpen && (
            <div className="overflow-hidden">
              <div className="text-sm font-bold text-[#e8e6e3] tracking-wide">
                SIH26145
              </div>
              <div className="text-[10px] text-[#8b8994] italic">
                Cyber Threat Detection
              </div>
            </div>
          )}
        </div>

        {/* Nav items */}
        <nav className="flex-1 py-3 px-2 space-y-1 overflow-y-auto">
          {NAV_ITEMS.map((item) => (
            <NavLink
              key={item.path}
              to={item.path}
              className={({ isActive }) =>
                cn(
                  "flex items-center gap-3 px-3 py-2.5 rounded-lg text-sm transition-all duration-150",
                  isActive
                    ? "bg-[#0f3460] text-[#e8e6e3] shadow-[inset_3px_0_0_0_#e94560]"
                    : "text-[#8b8994] hover:bg-[#1a1a3e] hover:text-[#c4c1bb]",
                )
              }
            >
              <item.icon className="w-4 h-4 flex-shrink-0" />
              {sidebarOpen && <span>{item.label}</span>}
            </NavLink>
          ))}
        </nav>

        {/* Passive monitoring badge */}
        <div className="px-3 py-3 border-t border-[#2a2a4a]">
          <div
            className={cn(
              "flex items-center gap-2 px-3 py-2 rounded-lg bg-[#0f9b8e]/10 border border-[#0f9b8e]/20",
              !sidebarOpen && "justify-center px-0",
            )}
          >
            <div className="w-2 h-2 rounded-full bg-[#0f9b8e] status-pulse" />
            {sidebarOpen && (
              <div className="text-[10px] text-[#0f9b8e] font-medium uppercase tracking-wider">
                Passive Monitoring
              </div>
            )}
          </div>
        </div>

        {/* Collapse button */}
        <button
          onClick={() => setSidebarOpen(!sidebarOpen)}
          className="absolute top-4 -right-3 w-6 h-6 rounded-full bg-[#1a1a2e] border border-[#2a2a4a] flex items-center justify-center text-[#8b8994] hover:text-[#e8e6e3] hover:border-[#533483] transition-colors z-10"
        >
          {sidebarOpen ? (
            <X className="w-3 h-3" />
          ) : (
            <Menu className="w-3 h-3" />
          )}
        </button>
      </aside>

      {/* Main content area */}
      <div className="flex-1 flex flex-col overflow-hidden">
        {/* Top bar */}
        <header className="flex items-center justify-between px-6 py-3 bg-[#12122a]/80 border-b border-[#2a2a4a] backdrop-blur-sm">
          <div className="flex items-center gap-4">
            <div className="flex items-center gap-2 px-3 py-1.5 rounded-md bg-[#0f9b8e]/10 border border-[#0f9b8e]/20">
              <Radio className="w-3 h-3 text-[#0f9b8e]" />
              <span className="text-xs font-medium text-[#0f9b8e] uppercase tracking-wider">
                Passive Monitoring
              </span>
            </div>
            <div className="flex items-center gap-2 px-3 py-1.5 rounded-md bg-[#533483]/10 border border-[#533483]/20">
              <Lock className="w-3 h-3 text-[#533483]" />
              <span className="text-xs font-medium text-[#533483] uppercase tracking-wider">
                Read-Only Ingest
              </span>
            </div>
          </div>
          <div className="flex items-center gap-6">
            <div className="text-right">
              <div className="text-[10px] text-[#8b8994] uppercase tracking-wider">
                No Return Path
              </div>
            </div>
            <div className="text-right">
              <div className="text-xs font-mono text-[#c4c1bb]">
                {currentTime.toLocaleTimeString("en-US", { hour12: false })}
              </div>
              <div className="text-[10px] text-[#8b8994]">
                {currentTime.toLocaleDateString("en-US", {
                  year: "numeric",
                  month: "short",
                  day: "numeric",
                })}
              </div>
            </div>
          </div>
        </header>

        {/* Page content */}
        <main className="flex-1 overflow-y-auto p-6">
          <Outlet />
        </main>
      </div>
    </div>
  );
}
