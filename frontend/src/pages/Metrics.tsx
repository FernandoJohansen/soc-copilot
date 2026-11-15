import { useQuery } from "@tanstack/react-query";
import { useState } from "react";
import { ApiError, api, type EvalReport, type Expected, type Scores } from "../api";
import { Card, Notice, formatTime } from "../components/ui";

type RateKey = "detection_recall" | "detection_precision" | "severity_accuracy" | "tactic_accuracy" | "technique_accuracy";

const RATES: { key: RateKey; label: string; help: string }[] = [
  { key: "detection_recall", label: "Detection recall", help: "Share of real attacks that were flagged" },
  { key: "detection_precision", label: "Detection precision", help: "Share of flagged groups that were real attacks" },
  { key: "severity_accuracy", label: "Severity accuracy", help: "Attacks given the labelled severity" },
  { key: "tactic_accuracy", label: "Tactic accuracy", help: "Attacks given the labelled ATT&CK tactic" },
  { key: "technique_accuracy", label: "Technique accuracy", help: "Attacks given the labelled ATT&CK technique" },
];

const pct = (value: number | null | undefined) => (value == null ? "n/a" : `${Math.round(value * 100)}%`);

function Tile({ label, value, note }: { label: string; value: string; note?: string }) {
  return (
    <div className="rounded-lg border border-line p-4">
      <div className="text-xs uppercase tracking-wide text-ink-3">{label}</div>
      <div className="mt-1 text-2xl font-semibold tabular-nums">{value}</div>
      {note && <div className="mt-1 text-xs text-ink-3">{note}</div>}
    </div>
  );
}

function Bar({ value, color, name, metric }: { value: number | null; color: string; name: string; metric: string }) {
  const [hover, setHover] = useState(false);
  return (
    <div
      className="relative flex h-5 items-center gap-2"
      onMouseEnter={() => setHover(true)}
      onMouseLeave={() => setHover(false)}
    >
      <div className="h-3.5 rounded-r" style={{ width: `${(value ?? 0) * 100}%`, minWidth: value ? 2 : 0, background: color, opacity: hover ? 1 : 0.92 }} />
      <span className="relative z-[1] bg-surface px-0.5 text-xs tabular-nums text-ink-2">{pct(value)}</span>
      {hover && (
        <div className="pointer-events-none absolute left-2 top-5 z-10 whitespace-nowrap rounded-md border border-line bg-surface px-2 py-1 text-xs text-ink shadow-md">
          <span className="mr-1.5 inline-block size-2 rounded-sm" style={{ background: color }} />
          {name} · {metric}: <span className="font-semibold">{pct(value)}</span>
        </div>
      )}
    </div>
  );
}

function ComparisonChart({ agent, baseline, targets }: { agent: EvalReport | null; baseline: EvalReport; targets: Record<string, number> }) {
  return (
    <div>
      <div className="mb-3 flex flex-wrap gap-4 text-xs text-ink-2">
        {agent && (
          <span className="inline-flex items-center gap-1.5">
            <span className="size-2.5 rounded-sm bg-series-1" /> {agent.name}
          </span>
        )}
        <span className="inline-flex items-center gap-1.5">
          <span className="size-2.5 rounded-sm bg-series-2" /> {baseline.name}
        </span>
        <span className="inline-flex items-center gap-1.5">
          <span className="h-3 w-0 border-l-2 border-dashed border-ink-3" /> Phase 3 target
        </span>
      </div>
      <div className="space-y-3">
        {RATES.map(({ key, label, help }) => (
          <div key={key} className="grid grid-cols-1 gap-1 sm:grid-cols-[11rem_1fr] sm:items-center sm:gap-3">
            <div className="text-sm text-ink" title={help}>
              {label}
            </div>
            <div className="relative border-l border-line">
              <div className="space-y-0.5 py-0.5 pr-10">
                {agent && <Bar value={agent.all[key]} color="var(--series-1)" name="Agent" metric={label} />}
                <Bar value={baseline.all[key]} color="var(--series-2)" name="Baseline" metric={label} />
              </div>
              {targets[key] != null && (
                <div
                  className="pointer-events-none absolute inset-y-0 border-l-2 border-dashed border-ink-3"
                  style={{ left: `calc((100% - 2.5rem) * ${targets[key]})` }}
                  aria-label={`Target ${pct(targets[key])}`}
                />
              )}
            </div>
          </div>
        ))}
      </div>
    </div>
  );
}

function ScoreTable({ agent, baseline }: { agent: EvalReport | null; baseline: EvalReport }) {
  const sets: { label: string; pick: (r: EvalReport) => Scores }[] = [
    { label: "All entries", pick: (r) => r.all },
    { label: "Held-out split", pick: (r) => r.held_out },
    { label: "Standard attacks", pick: (r) => r.by_kind.standard },
    { label: "Evasive attacks", pick: (r) => r.by_kind.evasive },
    { label: "Benign activity", pick: (r) => r.by_kind.benign },
  ];
  const reports = [...(agent ? [agent] : []), baseline];
  return (
    <div className="overflow-x-auto">
      <table className="w-full text-left text-sm">
        <thead className="text-xs uppercase tracking-wide text-ink-3">
          <tr>
            <th className="py-1.5 pr-3 font-medium">Set</th>
            <th className="py-1.5 pr-3 font-medium">Classifier</th>
            <th className="py-1.5 pr-3 text-right font-medium">Entries</th>
            <th className="py-1.5 pr-3 text-right font-medium">Recall</th>
            <th className="py-1.5 pr-3 text-right font-medium">False positives</th>
            <th className="py-1.5 pr-3 text-right font-medium">Severity</th>
            <th className="py-1.5 pr-3 text-right font-medium">Tactic</th>
            <th className="py-1.5 text-right font-medium">Technique</th>
          </tr>
        </thead>
        <tbody className="tabular-nums">
          {sets.flatMap((set) =>
            reports.map((report, index) => {
              const s = set.pick(report);
              return (
                <tr key={set.label + report.name} className={index === 0 ? "border-t border-line" : ""}>
                  <td className="py-1.5 pr-3 text-ink">{index === 0 ? set.label : ""}</td>
                  <td className="py-1.5 pr-3 text-ink-2">{report === baseline ? "Baseline" : "Agent"}</td>
                  <td className="py-1.5 pr-3 text-right">{s.n}</td>
                  <td className="py-1.5 pr-3 text-right">{pct(s.detection_recall)}</td>
                  <td className="py-1.5 pr-3 text-right">{s.benign ? `${s.false_positives} of ${s.benign}` : "n/a"}</td>
                  <td className="py-1.5 pr-3 text-right">{pct(s.severity_accuracy)}</td>
                  <td className="py-1.5 pr-3 text-right">{pct(s.tactic_accuracy)}</td>
                  <td className="py-1.5 text-right">{pct(s.technique_accuracy)}</td>
                </tr>
              );
            }),
          )}
        </tbody>
      </table>
    </div>
  );
}

const describe = (e: Expected) =>
  e.is_incident ? `severity ${e.severity ?? "?"}, ${e.mitre_tactic ?? "no tactic"}, ${e.mitre_technique ?? "no technique"}` : "not an incident";

function Misses({ report }: { report: EvalReport }) {
  if (report.misses.length === 0) return <p className="text-sm text-ink-2">No misses.</p>;
  return (
    <ul className="max-h-80 space-y-2 overflow-y-auto text-sm">
      {report.misses.map((miss) => (
        <li key={miss.id}>
          <span className="font-mono text-xs text-ink">{miss.id}</span>
          <div className="text-ink-2">
            Expected {describe(miss.expected)}; got {miss.error ? `an error (${miss.error})` : describe(miss.got)}.
          </div>
        </li>
      ))}
    </ul>
  );
}

export default function Metrics() {
  const query = useQuery({ queryKey: ["metrics"], queryFn: api.metrics });
  if (query.isPending) return <p className="text-sm text-ink-3">Loading…</p>;
  if (query.isError) {
    const missing = query.error instanceof ApiError && query.error.status === 404;
    return (
      <Notice tone={missing ? "info" : "error"}>
        {missing ? (
          <>
            No eval results yet. Run <code className="font-mono">pytest backend/tests/evals -m eval</code> to produce{" "}
            <code className="font-mono">evals/results.json</code>.
          </>
        ) : (
          query.error.message
        )}
      </Notice>
    );
  }
  const { agent, baseline, dataset, targets } = query.data;
  const lead = agent ?? baseline;

  return (
    <div className="space-y-4">
      {!agent && (
        <Notice>
          Only the rule baseline has been evaluated so far. The agent column appears after the eval suite runs with an LLM API key.
        </Notice>
      )}
      <div className="grid grid-cols-2 gap-3 lg:grid-cols-4">
        <Tile label={agent ? "Agent severity accuracy" : "Baseline severity accuracy"} value={pct(lead.all.severity_accuracy)} note={`Target ${pct(targets.severity_accuracy)}`} />
        <Tile label={agent ? "Agent detection recall" : "Baseline detection recall"} value={pct(lead.all.detection_recall)} note={agent ? `Baseline ${pct(baseline.all.detection_recall)}` : `${dataset.attacks} attack entries`} />
        <Tile
          label="Latency p95"
          value={lead.all.latency_p95_ms >= 1000 ? `${(lead.all.latency_p95_ms / 1000).toFixed(1)} s` : `${lead.all.latency_p95_ms.toFixed(1)} ms`}
          note={agent ? `Target under ${targets.latency_p95_ms / 1000} s per call` : "Rules only, no LLM call"}
        />
        <Tile label="Cost per incident" value={agent ? `$${agent.all.cost_per_incident_usd.toFixed(4)}` : "n/a"} note={agent ? "LLM tokens, list price" : "Needs an agent run"} />
      </div>

      <Card
        title={agent ? "Agent vs. baseline" : "Baseline scores"}
        aside={<span className="text-xs text-ink-3">{dataset.entries} entries · {dataset.attacks} attacks · {dataset.benign} benign</span>}
      >
        <ComparisonChart agent={agent} baseline={baseline} targets={targets} />
      </Card>

      <Card title="Scores by set">
        <ScoreTable agent={agent} baseline={baseline} />
        <p className="mt-3 text-xs text-ink-3">
          Severity, tactic and technique are scored over attack entries; a missed attack counts as wrong. Evasive entries are the same
          attacks kept under the rules' fixed thresholds. Last run {formatTime(query.data.generated_at)}.
        </p>
      </Card>

      <div className="grid gap-4 lg:grid-cols-2">
        {agent && (
          <Card title={`Agent misses (${agent.misses.length})`}>
            <Misses report={agent} />
          </Card>
        )}
        <Card title={`Baseline misses (${baseline.misses.length})`}>
          <Misses report={baseline} />
        </Card>
      </div>
    </div>
  );
}
