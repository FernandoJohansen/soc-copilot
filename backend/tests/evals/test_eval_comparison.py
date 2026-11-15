"""Phase 3.3: the same golden dataset through the Sigma baseline, side by side with the
agent. Writes evals/results.json. The baseline half needs neither a database nor an API key."""

import json

import pytest

from tests.evals import harness

pytestmark = pytest.mark.eval


def test_golden_dataset_shape(golden):
    assert 50 <= len(golden) <= 100
    assert len({entry["id"] for entry in golden}) == len(golden)
    held_out = sum(entry["split"] == "test" for entry in golden)
    assert 0.15 <= held_out / len(golden) <= 0.25
    assert {entry["kind"] for entry in golden} == {"standard", "evasive", "benign"}


def test_baseline_catches_the_standard_scenarios(baseline_report):
    standard = baseline_report["by_kind"]["standard"]
    assert standard["detection_recall"] == 1.0
    assert standard["severity_accuracy"] == 1.0


def test_results_file_has_both_columns(baseline_report, agent_report):
    results = harness.write_results(baseline_report, agent_report)
    on_disk = json.loads(harness.RESULTS_PATH.read_text())
    assert on_disk["baseline"]["all"]["n"] == results["dataset"]["entries"]
    if agent_report is not None:
        assert on_disk["agent"]["all"]["n"] == results["dataset"]["entries"]
