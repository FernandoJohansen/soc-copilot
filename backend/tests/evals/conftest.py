import pytest

from app.core.config import settings
from app.services.assets import SYNTHETIC_INVENTORY
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
    # The golden dataset is written for the synthetic network, so its inventory applies.
    settings.asset_inventory = settings.asset_inventory or str(SYNTHETIC_INVENTORY)
    reason = harness.agent_unavailable_reason()
    if reason:
        return None
    model = {
        "claude": settings.anthropic_model,
        "openai": settings.openai_model,
        "ollama": settings.ollama_model,
    }[settings.llm_provider]
    return harness.report(f"LLM agent ({model})", golden, harness.run_agent(golden))
