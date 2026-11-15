"""Phase 3.2: the agent, through POST /api/v1/analyze, against the golden labels.

    pytest backend/tests/evals -m eval -v

Needs Postgres with the MITRE techniques seeded and an API key for LLM_PROVIDER.
"""

import pytest

from tests.evals import harness

pytestmark = [pytest.mark.eval, pytest.mark.agent]


@pytest.fixture(scope="module")
def agent(agent_report):
    if agent_report is None:
        pytest.skip(f"agent eval not run: {harness.agent_unavailable_reason()}")
    return agent_report["all"]


def test_agent_answered_every_entry(agent):
    assert agent["errors"] == 0, f"{agent['errors']} entries got no LLM answer"


@pytest.mark.parametrize("metric", ["severity_accuracy", "tactic_accuracy", "technique_accuracy"])
def test_agent_meets_accuracy_target(agent, metric):
    assert agent[metric] >= harness.TARGETS[metric], (
        f"{metric} {agent[metric]:.0%} is under the {harness.TARGETS[metric]:.0%} target"
    )


def test_agent_latency_p95(agent):
    assert agent["latency_p95_ms"] < harness.TARGETS["latency_p95_ms"]
