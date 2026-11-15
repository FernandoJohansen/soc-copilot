"""Render evals/results.json as the "Eval Results" table in README.md.

python backend/scripts/update_readme.py            # rewrite the README section
python backend/scripts/update_readme.py --stdout   # print the table instead
"""

import argparse
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
RESULTS = ROOT / "evals" / "results.json"
README = ROOT / "README.md"
START, END = "<!-- EVAL_RESULTS_START -->", "<!-- EVAL_RESULTS_END -->"

ROWS = [
    ("Detection recall", "detection_recall", None),
    ("Detection precision", "detection_precision", None),
    ("Severity accuracy", "severity_accuracy", "severity_accuracy"),
    ("ATT&CK tactic accuracy", "tactic_accuracy", "tactic_accuracy"),
    ("ATT&CK technique accuracy", "technique_accuracy", "technique_accuracy"),
]


def _pct(value: float | None) -> str:
    return "n/a" if value is None else f"{value:.0%}"


def render(results: dict) -> str:
    baseline, agent, targets = results["baseline"], results["agent"], results["targets"]
    data = results["dataset"]
    agent_name = agent["name"] if agent else "LLM agent"
    lines = [
        f"| Metric | {baseline['name']} | {agent_name} | Target |",
        "| --- | ---: | ---: | ---: |",
    ]
    for label, key, target in ROWS:
        lines.append(
            f"| {label} | {_pct(baseline['all'][key])} | "
            f"{_pct(agent['all'][key]) if agent else 'not run yet'} | "
            f"{'≥ ' + _pct(targets[target]) if target else ''} |"
        )
    benign = baseline["all"]["benign"]
    baseline_fp = f"{baseline['all']['false_positives']} of {benign}"
    agent_fp = f"{agent['all']['false_positives']} of {benign}" if agent else "not run yet"
    lines.append(f"| False positives on benign activity | {baseline_fp} | {agent_fp} | |")
    lines.append(
        f"| Detection recall on evasive attacks | "
        f"{_pct(baseline['by_kind']['evasive']['detection_recall'])} | "
        f"{_pct(agent['by_kind']['evasive']['detection_recall']) if agent else 'not run yet'} | |"
    )
    if agent:
        lines.append(
            f"| Latency p95 per analysis | {baseline['all']['latency_p95_ms']:.1f} ms | "
            f"{agent['all']['latency_p95_ms'] / 1000:.1f} s | "
            f"< {targets['latency_p95_ms'] / 1000:.0f} s |"
        )
        lines.append(
            f"| LLM cost per analysis | $0 | ${agent['all']['cost_per_incident_usd']:.4f} | |"
        )
    lines.append("")
    lines.append(
        f"{data['entries']} labelled entries: {data['attacks']} attacks and {data['benign']} "
        f"benign, {data['held_out']} of them held out. Accuracy is over the attack entries, "
        "and a missed attack counts as wrong. "
        + (
            f"Agent run: {results['agent_generated_at'][:10]}."
            if agent
            else "The agent column fills in once the eval suite runs with an LLM API key."
        )
    )
    return "\n".join(lines)


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--stdout", action="store_true")
    args = parser.parse_args()
    table = render(json.loads(RESULTS.read_text()))
    if args.stdout:
        print(table)
        return
    text = README.read_text()
    before, rest = text.split(START, 1)
    _, after = rest.split(END, 1)
    README.write_text(f"{before}{START}\n{table}\n{END}{after}")
    print(f"updated {README}")


if __name__ == "__main__":
    main()
