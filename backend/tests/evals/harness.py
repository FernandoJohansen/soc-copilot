"""Shared machinery for the eval suite: run both classifiers over the golden dataset,
score them with DeepEval metrics, and write the comparison to evals/results.json."""

import asyncio
import json
import os
import time
from dataclasses import asdict, dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

os.environ.setdefault("DEEPEVAL_TELEMETRY_OPT_OUT", "YES")

from deepeval.metrics import BaseMetric  # noqa: E402
from deepeval.test_case import LLMTestCase  # noqa: E402

from app.core.config import REPO_ROOT, settings  # noqa: E402
from app.services.sigma_rules import run_sigma_rules  # noqa: E402

GOLDEN_PATH = Path(__file__).with_name("golden_labels.json")
RESULTS_PATH = REPO_ROOT / "evals" / "results.json"

# Phase 3 targets from the scope document.
TARGETS = {
    "severity_accuracy": 0.75,
    "tactic_accuracy": 0.70,
    "technique_accuracy": 0.65,
    "latency_p95_ms": 10_000,
}


@dataclass
class Prediction:
    is_incident: bool = False
    severity: int | None = None
    mitre_tactic: str | None = None
    mitre_technique: str | None = None
    latency_ms: float = 0.0
    input_tokens: int = 0
    output_tokens: int = 0
    error: str | None = None


def load_golden() -> list[dict[str, Any]]:
    return json.loads(GOLDEN_PATH.read_text())


def base_technique(technique_id: str | None) -> str | None:
    """T1110.003 -> T1110. Labels use parent techniques."""
    return technique_id.split(".")[0].upper() if technique_id else None


class FieldMatchMetric(BaseMetric):
    """Scores 1 when one field of the prediction equals the label, else 0. No LLM involved."""

    def __init__(self, field: str):
        self.field = field
        self.threshold = 1.0
        self.async_mode = False

    def measure(self, test_case: LLMTestCase, *args: Any, **kwargs: Any) -> float:
        actual = json.loads(test_case.actual_output)[self.field]
        expected = json.loads(test_case.expected_output)[self.field]
        if isinstance(actual, str) and isinstance(expected, str):
            actual, expected = actual.strip().lower(), expected.strip().lower()
        self.score = 1.0 if actual == expected else 0.0
        self.success = self.score >= self.threshold
        self.reason = f"{self.field}: expected {expected!r}, got {actual!r}"
        return self.score

    async def a_measure(self, test_case: LLMTestCase, *args: Any, **kwargs: Any) -> float:
        return self.measure(test_case)

    def is_successful(self) -> bool:
        return bool(self.success)

    @property
    def __name__(self) -> str:  # type: ignore[override]
        return f"FieldMatch[{self.field}]"


def _test_case(entry: dict[str, Any], prediction: Prediction) -> LLMTestCase:
    actual = asdict(prediction) | {"mitre_technique": base_technique(prediction.mitre_technique)}
    return LLMTestCase(
        input=entry["id"],
        actual_output=json.dumps(actual),
        expected_output=json.dumps(entry["expected"]),
    )


def _mean(metric: BaseMetric, cases: list[LLMTestCase]) -> float | None:
    if not cases:
        return None
    return round(sum(metric.measure(case) for case in cases) / len(cases), 4)


def _p95(values: list[float]) -> float:
    ordered = sorted(values)
    return round(ordered[max(0, -(-len(ordered) * 95 // 100) - 1)], 1) if ordered else 0.0


def score(entries: list[dict[str, Any]], predictions: list[Prediction]) -> dict[str, Any]:
    """Metrics for one classifier over one set of entries."""
    pairs = list(zip(entries, predictions, strict=True))
    attacks = [(e, p) for e, p in pairs if e["expected"]["is_incident"]]
    benign = [(e, p) for e, p in pairs if not e["expected"]["is_incident"]]
    true_positives = sum(p.is_incident for _, p in attacks)
    false_positives = sum(p.is_incident for _, p in benign)
    flagged = true_positives + false_positives
    attack_cases = [_test_case(e, p) for e, p in attacks]
    input_tokens = sum(p.input_tokens for p in predictions)
    output_tokens = sum(p.output_tokens for p in predictions)
    cost = (
        input_tokens * settings.llm_price_input_per_mtok
        + output_tokens * settings.llm_price_output_per_mtok
    ) / 1_000_000
    if settings.llm_provider == "ollama":
        cost = 0.0  # a local model has no per-token price
    return {
        "n": len(pairs),
        "attacks": len(attacks),
        "benign": len(benign),
        "detection_recall": round(true_positives / len(attacks), 4) if attacks else None,
        "detection_precision": round(true_positives / flagged, 4) if flagged else None,
        "false_positives": false_positives,
        # The three accuracies are over the attack entries: a missed attack counts as wrong.
        "severity_accuracy": _mean(FieldMatchMetric("severity"), attack_cases),
        "tactic_accuracy": _mean(FieldMatchMetric("mitre_tactic"), attack_cases),
        "technique_accuracy": _mean(FieldMatchMetric("mitre_technique"), attack_cases),
        "latency_p95_ms": _p95([p.latency_ms for p in predictions]),
        "cost_per_incident_usd": round(cost / len(pairs), 5) if pairs else 0.0,
        "errors": sum(p.error is not None for p in predictions),
    }


def report(name: str, entries: list[dict[str, Any]], predictions: list[Prediction]) -> dict:
    """Overall metrics plus the held-out split and a breakdown by kind of entry."""

    def subset(key: str, value: str) -> dict[str, Any]:
        chosen = [(e, p) for e, p in zip(entries, predictions, strict=True) if e[key] == value]
        return score([e for e, _ in chosen], [p for _, p in chosen])

    return {
        "name": name,
        "all": score(entries, predictions),
        "held_out": subset("split", "test"),
        "by_kind": {kind: subset("kind", kind) for kind in ("standard", "evasive", "benign")},
        "misses": [
            {
                "id": e["id"],
                "expected": e["expected"],
                "got": {
                    "is_incident": p.is_incident,
                    "severity": p.severity,
                    "mitre_tactic": p.mitre_tactic,
                    "mitre_technique": base_technique(p.mitre_technique),
                },
                "error": p.error,
            }
            for e, p in zip(entries, predictions, strict=True)
            if p.error
            or p.is_incident != e["expected"]["is_incident"]
            or (
                e["expected"]["is_incident"]
                and (
                    p.severity != e["expected"]["severity"]
                    or base_technique(p.mitre_technique) != e["expected"]["mitre_technique"]
                )
            )
        ],
    }


def run_baseline(entries: list[dict[str, Any]]) -> list[Prediction]:
    predictions = []
    for entry in entries:
        started = time.perf_counter()
        match = run_sigma_rules(entry["events"])
        latency = (time.perf_counter() - started) * 1000
        if match is None:
            predictions.append(Prediction(latency_ms=latency))
        else:
            predictions.append(
                Prediction(
                    is_incident=True,
                    severity=match.severity,
                    mitre_tactic=match.mitre_tactic,
                    mitre_technique=match.mitre_technique_id,
                    latency_ms=latency,
                )
            )
    return predictions


async def _run_agent(entries: list[dict[str, Any]], concurrency: int) -> list[Prediction]:
    import httpx

    from app.core.database import engine, init_db
    from app.main import app

    await init_db()
    semaphore = asyncio.Semaphore(concurrency)
    transport = httpx.ASGITransport(app=app)

    async with httpx.AsyncClient(transport=transport, base_url="http://eval", timeout=900) as http:

        async def one(entry: dict[str, Any]) -> Prediction:
            async with semaphore:
                started = time.perf_counter()
                response = await http.post(
                    "/api/v1/analyze", json={"events": entry["events"], "persist": False}
                )
                latency = (time.perf_counter() - started) * 1000
            if response.status_code != 200:
                return Prediction(latency_ms=latency, error=f"HTTP {response.status_code}")
            body = response.json()
            result, usage = body["llm_result"], body["llm_usage"] or {}
            if result is None:
                return Prediction(latency_ms=latency, error=body["llm_error"])
            return Prediction(
                is_incident=result["is_incident"],
                severity=result["severity"] if result["is_incident"] else None,
                mitre_tactic=result["mitre_tactic"],
                mitre_technique=result["mitre_technique_id"],
                latency_ms=latency,
                input_tokens=usage.get("input_tokens", 0),
                output_tokens=usage.get("output_tokens", 0),
            )

        # Warm up the embedding model so its load time is not charged to the first entry.
        await http.post("/api/v1/analyze", json={"events": entries[0]["events"], "persist": False})
        predictions = await asyncio.gather(*(one(entry) for entry in entries))
    await engine.dispose()
    return list(predictions)


def run_agent(entries: list[dict[str, Any]], concurrency: int | None = None) -> list[Prediction]:
    """Send every entry through POST /api/v1/analyze (in process) and collect the LLM's answer."""
    if concurrency is None:
        # A local model answers one request at a time; queueing would be charged as latency.
        concurrency = 1 if settings.llm_provider == "ollama" else 4
    return asyncio.run(_run_agent(entries, concurrency))


def agent_unavailable_reason() -> str | None:
    """Why the agent eval cannot run here, or None when it can."""
    from app.services.llm import llm_configured

    if not llm_configured():
        return f"no API key for LLM_PROVIDER={settings.llm_provider}"

    async def ping() -> None:
        from sqlalchemy import text

        from app.core.database import engine

        try:
            async with engine.connect() as conn:
                await conn.execute(text("SELECT 1"))
        finally:
            await engine.dispose()

    try:
        asyncio.run(ping())
    except Exception as e:
        return f"Postgres is not reachable ({type(e).__name__})"
    return None


def write_results(baseline: dict[str, Any], agent: dict[str, Any] | None) -> dict[str, Any]:
    """Write evals/results.json. With no agent run, the previous agent section is kept."""
    previous = json.loads(RESULTS_PATH.read_text()) if RESULTS_PATH.exists() else {}
    entries = load_golden()
    results = {
        "generated_at": datetime.now(UTC).isoformat(timespec="seconds"),
        "dataset": {
            "entries": len(entries),
            "attacks": sum(e["expected"]["is_incident"] for e in entries),
            "benign": sum(not e["expected"]["is_incident"] for e in entries),
            "held_out": sum(e["split"] == "test" for e in entries),
        },
        "targets": TARGETS,
        "baseline": baseline,
        "agent": agent if agent is not None else previous.get("agent"),
        "agent_generated_at": (
            datetime.now(UTC).isoformat(timespec="seconds")
            if agent is not None
            else previous.get("agent_generated_at")
        ),
    }
    RESULTS_PATH.parent.mkdir(exist_ok=True)
    RESULTS_PATH.write_text(json.dumps(results, indent=2) + "\n")
    return results
