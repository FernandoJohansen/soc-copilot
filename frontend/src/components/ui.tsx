import type { ReactNode } from "react";
import type { Analysis } from "../api";

const SEVERITY = ["", "Low", "Medium", "High", "Critical"];

export function SeverityBadge({ level }: { level: number }) {
  return (
    <span className="inline-flex items-center gap-1.5 whitespace-nowrap rounded-full border border-line px-2 py-0.5 text-xs font-medium text-ink">
      <span className="size-2 rounded-full" style={{ background: `var(--sev-${level})` }} />
      {level} · {SEVERITY[level] ?? "Unknown"}
    </span>
  );
}

export function Card({ title, children, aside }: { title: string; children: ReactNode; aside?: ReactNode }) {
  return (
    <section className="rounded-lg border border-line bg-surface p-4">
      <header className="mb-3 flex items-center justify-between gap-3">
        <h2 className="text-sm font-semibold text-ink">{title}</h2>
        {aside}
      </header>
      {children}
    </section>
  );
}

export function Notice({ tone = "info", children }: { tone?: "info" | "error"; children: ReactNode }) {
  return (
    <div
      className={`rounded-md border px-3 py-2 text-sm ${
        tone === "error" ? "border-critical text-ink" : "border-line text-ink-2"
      } bg-surface-2`}
    >
      {tone === "error" && <span className="font-semibold">Error: </span>}
      {children}
    </div>
  );
}

export function attackUrl(techniqueId: string) {
  return `https://attack.mitre.org/techniques/${techniqueId.replace(".", "/")}/`;
}

export function Technique({ id, name }: { id: string | null; name?: string | null }) {
  if (!id) return <span className="text-ink-3">none</span>;
  return (
    <a className="text-accent underline-offset-2 hover:underline" href={attackUrl(id)} target="_blank" rel="noreferrer">
      {id}
      {name ? ` ${name}` : ""}
    </a>
  );
}

export function AnalysisCard({ title, analysis, aside }: { title: string; analysis: Analysis; aside?: ReactNode }) {
  return (
    <Card title={title} aside={aside}>
      {analysis.is_incident ? (
        <dl className="grid grid-cols-[7rem_1fr] gap-y-2 text-sm">
          <dt className="text-ink-3">Severity</dt>
          <dd>
            <SeverityBadge level={analysis.severity} />
          </dd>
          <dt className="text-ink-3">Tactic</dt>
          <dd>{analysis.mitre_tactic ?? "none"}</dd>
          <dt className="text-ink-3">Technique</dt>
          <dd>
            <Technique id={analysis.mitre_technique_id} name={analysis.mitre_technique_name} />
          </dd>
          <dt className="text-ink-3">Confidence</dt>
          <dd>{Math.round(analysis.confidence * 100)}%</dd>
        </dl>
      ) : (
        <p className="text-sm font-medium">Not an incident</p>
      )}
      <p className="mt-3 whitespace-pre-line text-sm text-ink-2">{analysis.summary}</p>
      {analysis.suggested_actions.length > 0 && (
        <>
          <h3 className="mt-3 text-xs font-semibold uppercase tracking-wide text-ink-3">Suggested actions</h3>
          <ul className="mt-1 list-disc space-y-1 pl-5 text-sm text-ink-2">
            {analysis.suggested_actions.map((action) => (
              <li key={action}>{action}</li>
            ))}
          </ul>
        </>
      )}
    </Card>
  );
}

export function formatTime(iso: string) {
  return new Date(iso).toLocaleString(undefined, { dateStyle: "medium", timeStyle: "medium" });
}
