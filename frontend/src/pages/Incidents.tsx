import { keepPreviousData, useQuery } from "@tanstack/react-query";
import { Link, useSearchParams } from "react-router-dom";
import { api } from "../api";
import { Notice, SeverityBadge, formatTime } from "../components/ui";

const selectClass = "rounded-md border border-line bg-surface px-2 py-1.5 text-sm text-ink";

export default function Incidents() {
  const [params, setParams] = useSearchParams();
  const page = Number(params.get("page") ?? "1");
  const filters = {
    severity: params.get("severity") ?? "",
    tactic: params.get("tactic") ?? "",
    status: params.get("status") ?? "",
  };
  const set = (key: string, value: string) => {
    const next = new URLSearchParams(params);
    if (value) next.set(key, value);
    else next.delete(key);
    if (key !== "page") next.delete("page");
    setParams(next);
  };

  const tactics = useQuery({ queryKey: ["tactics"], queryFn: api.tactics });
  const incidents = useQuery({
    queryKey: ["incidents", page, filters],
    queryFn: () => api.incidents({ page, ...filters }),
    placeholderData: keepPreviousData,
    refetchInterval: 10_000,
  });
  const data = incidents.data;
  const pages = data ? Math.max(1, Math.ceil(data.total / data.page_size)) : 1;

  return (
    <div className="space-y-4">
      <div className="flex flex-wrap items-center gap-2">
        <select className={selectClass} value={filters.severity} onChange={(e) => set("severity", e.target.value)} aria-label="Severity">
          <option value="">All severities</option>
          <option value="4">4 · Critical</option>
          <option value="3">3 · High</option>
          <option value="2">2 · Medium</option>
          <option value="1">1 · Low</option>
        </select>
        <select className={selectClass} value={filters.tactic} onChange={(e) => set("tactic", e.target.value)} aria-label="Tactic">
          <option value="">All tactics</option>
          {tactics.data?.map((tactic) => (
            <option key={tactic}>{tactic}</option>
          ))}
        </select>
        <select className={selectClass} value={filters.status} onChange={(e) => set("status", e.target.value)} aria-label="Status">
          <option value="">Any status</option>
          <option value="open">Open</option>
          <option value="investigating">Investigating</option>
          <option value="resolved">Resolved</option>
        </select>
        {data && <span className="ml-auto text-sm text-ink-3">{data.total} incidents</span>}
      </div>

      {incidents.isError && <Notice tone="error">Could not load incidents: {incidents.error.message}</Notice>}
      {incidents.isPending && <p className="text-sm text-ink-3">Loading…</p>}

      {data && data.items.length === 0 && (
        <Notice>
          No incidents match. Send logs through the <Link className="text-accent underline" to="/analyze">Analyze</Link> page to create one.
        </Notice>
      )}

      {data && data.items.length > 0 && (
        <div className="overflow-x-auto rounded-lg border border-line">
          <table className="w-full text-left text-sm">
            <thead className="bg-surface-2 text-xs uppercase tracking-wide text-ink-3">
              <tr>
                <th className="px-3 py-2 font-medium">ID</th>
                <th className="px-3 py-2 font-medium">Severity</th>
                <th className="px-3 py-2 font-medium">Incident</th>
                <th className="px-3 py-2 font-medium">Tactic</th>
                <th className="px-3 py-2 font-medium">Created</th>
                <th className="px-3 py-2 font-medium">Status</th>
              </tr>
            </thead>
            <tbody>
              {data.items.map((incident) => (
                <tr key={incident.id} className="border-t border-line hover:bg-surface-2">
                  <td className="px-3 py-2 tabular-nums text-ink-3">#{incident.id}</td>
                  <td className="px-3 py-2">
                    <SeverityBadge level={incident.severity} />
                  </td>
                  <td className="px-3 py-2">
                    <Link className="font-medium text-ink hover:text-accent" to={`/incidents/${incident.id}`}>
                      {incident.title}
                    </Link>
                  </td>
                  <td className="px-3 py-2 text-ink-2">{incident.mitre_tactic ?? "none"}</td>
                  <td className="whitespace-nowrap px-3 py-2 text-ink-2">{formatTime(incident.created_at)}</td>
                  <td className="px-3 py-2 capitalize text-ink-2">{incident.status}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}

      {data && pages > 1 && (
        <div className="flex items-center justify-end gap-3 text-sm">
          <button className="rounded-md border border-line px-3 py-1 disabled:opacity-40" disabled={page <= 1} onClick={() => set("page", String(page - 1))}>
            Previous
          </button>
          <span className="text-ink-3">
            Page {page} of {pages}
          </span>
          <button className="rounded-md border border-line px-3 py-1 disabled:opacity-40" disabled={page >= pages} onClick={() => set("page", String(page + 1))}>
            Next
          </button>
        </div>
      )}
    </div>
  );
}
