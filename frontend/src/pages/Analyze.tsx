import { useMutation, useQueryClient } from "@tanstack/react-query";
import { useState } from "react";
import { Link } from "react-router-dom";
import { api, type LogEvent } from "../api";
import { AnalysisCard, Card, Notice, Technique } from "../components/ui";
import samples from "../samples.json";

const SAMPLES = samples as Record<string, LogEvent[]>;

function parseEvents(text: string): LogEvent[] {
  const parsed: unknown = JSON.parse(text);
  const list = Array.isArray(parsed) ? parsed : [parsed];
  if (list.length === 0) throw new Error("The array is empty.");
  list.forEach((item, index) => {
    if (typeof item !== "object" || item === null || !("source" in item) || !("event_type" in item)) {
      throw new Error(`Event ${index + 1} needs "source" and "event_type".`);
    }
  });
  return list as LogEvent[];
}

export default function Analyze() {
  const [text, setText] = useState("");
  const [parseError, setParseError] = useState<string | null>(null);
  const queryClient = useQueryClient();
  const analysis = useMutation({
    mutationFn: api.analyze,
    onSuccess: () => queryClient.invalidateQueries({ queryKey: ["incidents"] }),
  });

  const submit = () => {
    setParseError(null);
    try {
      analysis.mutate(parseEvents(text));
    } catch (error) {
      setParseError(error instanceof Error ? error.message : "Invalid JSON.");
    }
  };
  const result = analysis.data;

  return (
    <div className="grid gap-4 xl:grid-cols-2">
      <Card
        title="Events (JSON array)"
        aside={
          <select
            className="rounded-md border border-line bg-surface px-2 py-1 text-sm"
            value=""
            onChange={(e) => {
              if (e.target.value) setText(JSON.stringify(SAMPLES[e.target.value], null, 2));
            }}
            aria-label="Load a sample"
          >
            <option value="">Load a sample…</option>
            {Object.keys(SAMPLES).map((name) => (
              <option key={name}>{name}</option>
            ))}
          </select>
        }
      >
        <textarea
          className="h-96 w-full resize-y rounded-md border border-line bg-surface-2 p-3 font-mono text-xs text-ink"
          spellCheck={false}
          placeholder={'[\n  {"source": "auth.log", "event_type": "authentication_failure",\n   "timestamp": "2026-11-02T09:00:00Z", "raw_data": {"src_ip": "203.0.113.57", "user": "root"}}\n]'}
          value={text}
          onChange={(e) => setText(e.target.value)}
        />
        <div className="mt-3 flex items-center gap-3">
          <button
            className="rounded-md bg-accent px-4 py-1.5 text-sm font-medium text-white disabled:opacity-50"
            disabled={!text.trim() || analysis.isPending}
            onClick={submit}
          >
            {analysis.isPending ? "Analyzing…" : "Analyze"}
          </button>
          {analysis.isPending && (
            <span className="size-4 animate-spin rounded-full border-2 border-line border-t-accent" role="status" aria-label="Analyzing" />
          )}
          <span className="text-xs text-ink-3">The events and any resulting incident are saved.</span>
        </div>
        {parseError && <div className="mt-3"><Notice tone="error">{parseError}</Notice></div>}
        {analysis.isError && <div className="mt-3"><Notice tone="error">{analysis.error.message}</Notice></div>}
      </Card>

      <div className="space-y-4">
        {!result && <Notice>Paste log events or load a sample, then analyze. The agent's answer and the rule baseline appear here.</Notice>}
        {result && (
          <>
            <Notice>
              {result.event_count} events analyzed in {(result.latency_ms / 1000).toFixed(1)} s.{" "}
              {result.incident_id ? (
                <Link className="text-accent underline" to={`/incidents/${result.incident_id}`}>
                  Open incident #{result.incident_id}
                </Link>
              ) : (
                "No incident was created."
              )}
            </Notice>
            {result.llm_result ? (
              <AnalysisCard
                title="Agent analysis"
                aside={result.llm_usage && <span className="text-xs text-ink-3">{result.llm_usage.model}</span>}
                analysis={result.llm_result}
              />
            ) : (
              <Notice tone="error">
                The LLM agent did not answer ({result.llm_error}). The rule baseline below is used as the fallback.
              </Notice>
            )}
            {result.sigma_result ? (
              <AnalysisCard
                title="Sigma baseline"
                aside={<span className="text-xs text-ink-3">rule: {result.sigma_result.rule}</span>}
                analysis={result.sigma_result}
              />
            ) : (
              <Card title="Sigma baseline">
                <p className="text-sm text-ink-2">No rule matched these events.</p>
              </Card>
            )}
            {result.mitre_context.length > 0 && (
              <Card title="ATT&CK techniques retrieved for the agent">
                <ul className="space-y-1 text-sm text-ink-2">
                  {result.mitre_context.map((technique) => (
                    <li key={technique.technique_id}>
                      <Technique id={technique.technique_id} name={technique.name} /> · {technique.tactic}
                    </li>
                  ))}
                </ul>
              </Card>
            )}
          </>
        )}
      </div>
    </div>
  );
}
