from typing import Any

from pydantic import BaseModel, Field, field_validator, model_validator

from app.schemas.event import EventCreate


class AnalysisResult(BaseModel):
    """What a classifier (the LLM agent or the Sigma baseline) says about a group of events."""

    is_incident: bool = True
    severity: int = Field(default=3, description="1 low, 2 medium, 3 high, 4 critical")
    attack_stage: str | None = Field(
        default=None,
        description="none, reconnaissance, attempt or success; the LLM's severity is derived "
        "from it",
    )
    summary: str = ""
    mitre_tactic: str | None = None
    mitre_technique_id: str | None = None
    mitre_technique_name: str | None = None
    suggested_actions: list[str] = Field(default_factory=list)
    confidence: float = 0.5

    @field_validator("severity", mode="before")
    @classmethod
    def _clamp_severity(cls, v: Any) -> int:
        try:
            return max(1, min(4, int(v)))
        except (TypeError, ValueError):
            return 3

    @field_validator("confidence", mode="before")
    @classmethod
    def _clamp_confidence(cls, v: Any) -> float:
        try:
            return max(0.0, min(1.0, float(v)))
        except (TypeError, ValueError):
            return 0.5


class LLMUsage(BaseModel):
    model: str = ""
    input_tokens: int = 0
    output_tokens: int = 0


class SigmaMatch(AnalysisResult):
    rule: str


class AnalyzeRequest(BaseModel):
    event_ids: list[int] | None = None
    events: list[EventCreate] | None = None
    use_sigma: bool = True
    top_k: int = Field(default=5, ge=1, le=10)
    persist: bool = Field(
        default=True, description="Save the incident (and inline events) to the database."
    )

    @model_validator(mode="after")
    def _one_source(self) -> "AnalyzeRequest":
        if bool(self.event_ids) == bool(self.events):
            raise ValueError("Provide exactly one of event_ids or events.")
        return self


class AnalyzeResponse(BaseModel):
    incident_id: int | None = None
    event_count: int
    sigma_result: SigmaMatch | None = None
    llm_result: AnalysisResult | None = None
    llm_error: str | None = None
    llm_usage: LLMUsage | None = None
    mitre_context: list[dict[str, Any]] = Field(default_factory=list)
    latency_ms: float


class AutoAnalyzeRequest(BaseModel):
    window_minutes: int = Field(default=10, ge=1, le=1440)
    min_events: int = Field(default=3, ge=1)
    max_groups: int = Field(default=20, ge=1, le=100)
    use_sigma: bool = True
    top_k: int = Field(default=5, ge=1, le=10)


class AutoAnalyzeResponse(BaseModel):
    groups_found: int
    groups_analyzed: int
    results: list[AnalyzeResponse]
