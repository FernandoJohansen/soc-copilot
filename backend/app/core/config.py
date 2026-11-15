from functools import lru_cache
from pathlib import Path

from pydantic_settings import BaseSettings, SettingsConfigDict

REPO_ROOT = Path(__file__).resolve().parents[3]


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=(REPO_ROOT / ".env", ".env"), extra="ignore")

    database_url: str = "postgresql+asyncpg://soc:soc@localhost:5432/soc_copilot"
    redis_url: str = "redis://localhost:6379/0"

    llm_provider: str = "ollama"
    anthropic_api_key: str = ""
    openai_api_key: str = ""
    anthropic_model: str = "claude-sonnet-5-5"
    anthropic_effort: str = "low"
    openai_model: str = "gpt-4o-mini"
    # Ollama runs a local model; no key is needed.
    ollama_base_url: str = "http://localhost:11434"
    ollama_model: str = "qwen2.5:3b"
    ollama_num_ctx: int = 16384
    ollama_timeout: float = 600.0
    llm_max_tokens: int = 8000
    # Events shown to the model per incident; the rest are summarized by count.
    llm_max_events: int = 300

    # USD per million tokens; only used to report cost in the evals.
    llm_price_input_per_mtok: float = 2.0
    llm_price_output_per_mtok: float = 10.0

    # Seed the MITRE table on startup when it is empty (on in docker-compose).
    auto_seed: bool = False

    embedding_model: str = "sentence-transformers/all-MiniLM-L6-v2"
    eval_results_path: str = str(REPO_ROOT / "evals" / "results.json")
    cors_origins: list[str] = ["http://localhost:5173", "http://localhost:3000"]


@lru_cache
def get_settings() -> Settings:
    return Settings()


settings = get_settings()
