export type LogEvent = {
  id?: number;
  source: string;
  event_type: string;
  timestamp: string;
  raw_data: Record<string, unknown>;
  severity?: number | null;
  incident_id?: number | null;
};

export type Analysis = {
  is_incident: boolean;
  severity: number;
  summary: string;
  mitre_tactic: string | null;
  mitre_technique_id: string | null;
  mitre_technique_name: string | null;
  suggested_actions: string[];
  confidence: number;
  rule?: string;
};

export type Incident = {
  id: number;
  title: string;
  severity: number;
  status: "open" | "investigating" | "resolved";
  summary: string;
  mitre_tactic: string | null;
  mitre_technique: string | null;
  mitre_technique_name: string | null;
  suggested_actions: string[];
  confidence: number | null;
  classified_by: string;
  created_at: string;
  updated_at: string;
};

export type IncidentDetail = Incident & { sigma_result: Analysis | null; events: LogEvent[] };

export type IncidentPage = { items: Incident[]; total: number; page: number; page_size: number };

export type AnalyzeResponse = {
  incident_id: number | null;
  event_count: number;
  sigma_result: Analysis | null;
  llm_result: Analysis | null;
  llm_error: string | null;
  llm_usage: { model: string; input_tokens: number; output_tokens: number } | null;
  mitre_context: { technique_id: string; name: string; tactic: string; distance: number }[];
  latency_ms: number;
};

export type Scores = {
  n: number;
  attacks: number;
  benign: number;
  detection_recall: number | null;
  detection_precision: number | null;
  false_positives: number;
  severity_accuracy: number | null;
  tactic_accuracy: number | null;
  technique_accuracy: number | null;
  latency_p95_ms: number;
  cost_per_incident_usd: number;
  errors: number;
};

export type Expected = {
  is_incident: boolean;
  severity: number | null;
  mitre_tactic: string | null;
  mitre_technique: string | null;
};

export type EvalReport = {
  name: string;
  all: Scores;
  held_out: Scores;
  by_kind: Record<"standard" | "evasive" | "benign", Scores>;
  misses: { id: string; expected: Expected; got: Expected; error: string | null }[];
};

export type EvalResults = {
  generated_at: string;
  agent_generated_at: string | null;
  dataset: { entries: number; attacks: number; benign: number; held_out: number };
  targets: Record<string, number>;
  baseline: EvalReport;
  agent: EvalReport | null;
};

export class ApiError extends Error {
  constructor(
    public status: number,
    message: string,
  ) {
    super(message);
  }
}

async function request<T>(path: string, init?: RequestInit): Promise<T> {
  const response = await fetch(`/api/v1${path}`, {
    ...init,
    headers: { "Content-Type": "application/json", ...init?.headers },
  });
  if (!response.ok) {
    let detail = response.statusText;
    try {
      const body = await response.json();
      detail = typeof body.detail === "string" ? body.detail : JSON.stringify(body.detail);
    } catch {
      // keep the status text
    }
    throw new ApiError(response.status, detail);
  }
  return response.json() as Promise<T>;
}

export const api = {
  incidents: (params: { page: number; severity?: string; tactic?: string; status?: string }) => {
    const query = new URLSearchParams({ page: String(params.page), page_size: "15" });
    if (params.severity) query.set("severity", params.severity);
    if (params.tactic) query.set("tactic", params.tactic);
    if (params.status) query.set("status", params.status);
    return request<IncidentPage>(`/incidents?${query}`);
  },
  tactics: () => request<string[]>("/incidents/tactics"),
  incident: (id: string) => request<IncidentDetail>(`/incidents/${id}`),
  setStatus: (id: number, status: Incident["status"]) =>
    request<Incident>(`/incidents/${id}`, { method: "PATCH", body: JSON.stringify({ status }) }),
  analyze: (events: LogEvent[]) =>
    request<AnalyzeResponse>("/analyze", { method: "POST", body: JSON.stringify({ events }) }),
  metrics: () => request<EvalResults>("/metrics"),
};
