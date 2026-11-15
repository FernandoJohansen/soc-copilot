import pytest

from app.core.config import settings
from tests.evals import harness


@pytest.fixture(scope="session")
def golden():
    return harness.load_golden()


@pytest.fixture(scope="session")
def baseline_report(golden):
    return harness.report("Sigma-style rules", golden, harness.run_baseline(golden))


@pytest.fixture(scope="session")
def agent_report(golden):
    """The agent's report, or None when there is no API key or no database."""
    reason = harness.agent_unavailable_reason()
    if reason:
        return None
    model = settings.anthropic_model if settings.llm_provider == "claude" else settings.openai_model
    return harness.report(f"LLM agent ({model})", golden, harness.run_agent(golden))
