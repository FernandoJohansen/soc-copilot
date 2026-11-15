import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { Link, useParams } from "react-router-dom";
import { api, type Incident } from "../api";
import { AnalysisCard, Card, Notice, SeverityBadge, formatTime } from "../components/ui";

export default function IncidentDetail() {
  const { id = "" } = useParams();
  const queryClient = useQueryClient();
  const query = useQuery({ queryKey: ["incident", id], queryFn: () => api.incident(id) });
  const status = useMutation({
    mutationFn: (next: Incident["status"]) => api.setStatus(Number(id), next),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["incident", id] });
      queryClient.invalidateQueries({ queryKey: ["incidents"] });
    },
  });

  if (query.isPending) return <p className="text-sm text-ink-3">Loading…</p>;
  if (query.isError) return <Notice tone="error">Could not load incident #{id}: {query.error.message}</Notice>;
  const incident = query.data;
  const byAgent = incident.classified_by === "llm";

  return (
    <div className="space-y-4">
      <div>
        <Link className="text-sm text-ink-3 hover:text-accent" to="/incidents">
          ← All incidents
        </Link>
        <div className="mt-2 flex flex-wrap items-center gap-3">
          <h2 className="text-lg font-semibold">
            #{incident.id} {incident.title}
          </h2>
          <SeverityBadge level={incident.severity} />
          <select
            className="ml-auto rounded-md border border-line bg-surface px-2 py-1 text-sm"
            value={incident.status}
            disabled={status.isPending}
            onChange={(e) => status.mutate(e.target.value as Incident["status"])}
            aria-label="Status"
          >
            <option value="open">Open</option>
            <option value="investigating">Investigating</option>
            <option value="resolved">Resolved</option>
          </select>
        </div>
        <p className="mt-1 text-sm text-ink-3">Created {formatTime(incident.created_at)}</p>
        {status.isError && <Notice tone="error">Could not change the status: {status.error.message}</Notice>}
      </div>

      <div className="grid gap-4 lg:grid-cols-2">
        <AnalysisCard
          title={byAgent ? "Agent analysis" : "Classification (rule fallback)"}
          aside={<span className="text-xs text-ink-3">{byAgent ? "LLM agent" : `by ${incident.classified_by}`}</span>}
          analysis={{
            is_incident: true,
            severity: incident.severity,
            summary: incident.summary,
            mitre_tactic: incident.mitre_tactic,
            mitre_technique_id: incident.mitre_technique,
            mitre_technique_name: incident.mitre_technique_name,
            suggested_actions: incident.suggested_actions,
            confidence: incident.confidence ?? 0,
          }}
        />
        {incident.sigma_result ? (
          <AnalysisCard
            title="Sigma baseline"
            aside={<span className="text-xs text-ink-3">rule: {incident.sigma_result.rule}</span>}
            analysis={incident.sigma_result}
          />
        ) : (
          <Card title="Sigma baseline">
            <p className="text-sm text-ink-2">No rule matched these events.</p>
          </Card>
        )}
      </div>

      <Card title={`Event timeline (${incident.events.length})`}>
        {incident.events.length === 0 ? (
          <p className="text-sm text-ink-2">No events are linked to this incident.</p>
        ) : (
          <div className="max-h-[32rem] overflow-y-auto pl-1.5">
          <ol className="border-l border-line pl-4">
            {incident.events.map((event, index) => (
              <li key={event.id ?? index} className="relative pb-3">
                <span className="absolute -left-[1.28rem] top-1.5 size-2 rounded-full bg-ink-3" />
                <div className="flex flex-wrap gap-x-3 text-xs text-ink-3">
                  <time>{formatTime(event.timestamp)}</time>
                  <span>
                    {event.source} · {event.event_type}
                  </span>
                </div>
                <p className="break-words font-mono text-xs text-ink">
                  {String(event.raw_data.message ?? JSON.stringify(event.raw_data))}
                </p>
              </li>
            ))}
          </ol>
          </div>
        )}
      </Card>
    </div>
  );
}
