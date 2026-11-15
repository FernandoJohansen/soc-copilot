import { NavLink, Navigate, Route, Routes, useLocation } from "react-router-dom";
import { useHealth } from "./api";
import Analyze from "./pages/Analyze";
import IncidentDetail from "./pages/IncidentDetail";
import Incidents from "./pages/Incidents";
import Metrics from "./pages/Metrics";

const NAV = [
  { to: "/incidents", label: "Incidents" },
  { to: "/analyze", label: "Analyze" },
  { to: "/metrics", label: "Metrics" },
];

const TITLES: Record<string, string> = {
  incidents: "Incidents",
  analyze: "Analyze logs",
  metrics: "Eval metrics",
};

export default function App() {
  const section = useLocation().pathname.split("/")[1] ?? "";
  const demo = useHealth().data?.demo_mode;
  return (
    <div className="flex min-h-screen flex-col md:flex-row">
      <aside className="border-b border-line bg-surface-2 md:w-52 md:shrink-0 md:border-b-0 md:border-r">
        <div className="px-4 py-4 text-sm font-semibold tracking-tight">SOC Copilot</div>
        <nav className="flex gap-1 px-2 pb-2 md:flex-col">
          {NAV.map((item) => (
            <NavLink
              key={item.to}
              to={item.to}
              className={({ isActive }) =>
                `rounded-md px-3 py-1.5 text-sm ${
                  isActive ? "bg-surface font-medium text-ink shadow-sm" : "text-ink-2 hover:text-ink"
                }`
              }
            >
              {item.label}
            </NavLink>
          ))}
        </nav>
      </aside>
      <div className="min-w-0 flex-1">
        <header className="border-b border-line px-4 py-3 md:px-6">
          <h1 className="text-base font-semibold">{TITLES[section] ?? "SOC Copilot"}</h1>
        </header>
        {demo && (
          <p className="border-b border-line bg-surface-2 px-4 py-2 text-xs text-ink-2 md:px-6">
            Public demo with synthetic logs. It is read-only: analyses run but are not saved, and each
            visitor gets a few per hour.
          </p>
        )}
        <main className="px-4 py-5 md:px-6">
          <Routes>
            <Route path="/" element={<Navigate to="/incidents" replace />} />
            <Route path="/incidents" element={<Incidents />} />
            <Route path="/incidents/:id" element={<IncidentDetail />} />
            <Route path="/analyze" element={<Analyze />} />
            <Route path="/metrics" element={<Metrics />} />
            <Route path="*" element={<p className="text-sm text-ink-2">Page not found.</p>} />
          </Routes>
        </main>
      </div>
    </div>
  );
}
