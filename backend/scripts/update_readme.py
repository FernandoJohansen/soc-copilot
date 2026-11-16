"""Render evals/results.json as the eval results table in README.md and README.pt-BR.md.

python backend/scripts/update_readme.py            # rewrite the section in both READMEs
python backend/scripts/update_readme.py --stdout   # print the English table instead
"""

import argparse
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
RESULTS = ROOT / "evals" / "results.json"
READMES = {"en": ROOT / "README.md", "pt": ROOT / "README.pt-BR.md"}
START, END = "<!-- EVAL_RESULTS_START -->", "<!-- EVAL_RESULTS_END -->"

TEXT = {
    "en": {
        "header": "| Metric | {baseline} | {agent} | Target |",
        "agent": "LLM agent",
        "baseline": "Sigma-style rules",
        "recall": "Detection recall",
        "precision": "Detection precision",
        "severity": "Severity accuracy",
        "tactic": "ATT&CK tactic accuracy",
        "technique": "ATT&CK technique accuracy",
        "fp": "False positives on benign activity",
        "of": "of",
        "evasive": "Detection recall on evasive attacks",
        "latency": "Latency p95 per analysis",
        "cost": "LLM cost per analysis",
        "not_run": "not run yet",
        "footer": (
            "{entries} labelled entries: {attacks} attacks and {benign} benign, {held_out} of "
            "them held out. Accuracy is over the attack entries, and a missed attack counts "
            "as wrong. "
        ),
        "run_on": "Agent run: {date}.",
        "pending": "The agent column fills in once the eval suite runs with an LLM API key.",
    },
    "pt": {
        "header": "| Métrica | {baseline} | {agent} | Meta |",
        "agent": "Agente LLM",
        "baseline": "Regras estilo Sigma",
        "recall": "Recall de detecção",
        "precision": "Precisão de detecção",
        "severity": "Acerto de gravidade",
        "tactic": "Acerto de tática ATT&CK",
        "technique": "Acerto de técnica ATT&CK",
        "fp": "Falsos positivos em atividade benigna",
        "of": "de",
        "evasive": "Recall de detecção em ataques evasivos",
        "latency": "Latência p95 por análise",
        "cost": "Custo de LLM por análise",
        "not_run": "ainda não rodou",
        "footer": (
            "{entries} entradas rotuladas: {attacks} ataques e {benign} benignas, {held_out} "
            "delas separadas como conjunto de teste. O acerto é calculado sobre os ataques, e "
            "um ataque não detectado conta como erro. "
        ),
        "run_on": "Rodada do agente: {date}.",
        "pending": "A coluna do agente é preenchida quando os evals rodam com um modelo.",
    },
}

ROWS = [
    ("recall", "detection_recall", None),
    ("precision", "detection_precision", None),
    ("severity", "severity_accuracy", "severity_accuracy"),
    ("tactic", "tactic_accuracy", "tactic_accuracy"),
    ("technique", "technique_accuracy", "technique_accuracy"),
]


def _pct(value: float | None) -> str:
    return "n/a" if value is None else f"{value:.0%}"


def _num(value: float, digits: int, lang: str) -> str:
    """A decimal number, with a decimal comma in Portuguese."""
    text = f"{value:.{digits}f}"
    return text.replace(".", ",") if lang == "pt" else text


def _agent_name(agent: dict, t: dict) -> str:
    """The harness names the agent "LLM agent (<model>)"; translate the prefix."""
    return agent["name"].replace("LLM agent", t["agent"], 1)


def render(results: dict, lang: str = "en") -> str:
    t = TEXT[lang]
    baseline, agent, targets = results["baseline"], results["agent"], results["targets"]
    data = results["dataset"]
    lines = [
        t["header"].format(
            baseline=t["baseline"], agent=_agent_name(agent, t) if agent else t["agent"]
        ),
        "| --- | ---: | ---: | ---: |",
    ]
    for label, key, target in ROWS:
        lines.append(
            f"| {t[label]} | {_pct(baseline['all'][key])} | "
            f"{_pct(agent['all'][key]) if agent else t['not_run']} | "
            f"{'≥ ' + _pct(targets[target]) if target else ''} |"
        )
    benign = baseline["all"]["benign"]
    baseline_fp = f"{baseline['all']['false_positives']} {t['of']} {benign}"
    agent_fp = f"{agent['all']['false_positives']} {t['of']} {benign}" if agent else t["not_run"]
    lines.append(f"| {t['fp']} | {baseline_fp} | {agent_fp} | |")
    agent_evasive = agent["by_kind"]["evasive"]["detection_recall"] if agent else None
    lines.append(
        f"| {t['evasive']} | {_pct(baseline['by_kind']['evasive']['detection_recall'])} | "
        f"{_pct(agent_evasive) if agent else t['not_run']} | |"
    )
    if agent:
        lines.append(
            f"| {t['latency']} | {_num(baseline['all']['latency_p95_ms'], 1, lang)} ms | "
            f"{_num(agent['all']['latency_p95_ms'] / 1000, 1, lang)} s | "
            f"< {targets['latency_p95_ms'] / 1000:.0f} s |"
        )
        lines.append(
            f"| {t['cost']} | $0 | ${_num(agent['all']['cost_per_incident_usd'], 4, lang)} | |"
        )
    lines.append("")
    lines.append(
        t["footer"].format(**data)
        + (t["run_on"].format(date=results["agent_generated_at"][:10]) if agent else t["pending"])
    )
    return "\n".join(lines)


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--stdout", action="store_true")
    args = parser.parse_args()
    results = json.loads(RESULTS.read_text())
    if args.stdout:
        print(render(results))
        return
    for lang, readme in READMES.items():
        text = readme.read_text()
        before, rest = text.split(START, 1)
        _, after = rest.split(END, 1)
        readme.write_text(f"{before}{START}\n{render(results, lang)}\n{END}{after}")
        print(f"updated {readme}")


if __name__ == "__main__":
    main()
