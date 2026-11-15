from datetime import datetime
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field

from app.schemas.event import EventRead

IncidentStatus = Literal["open", "investigating", "resolved"]


class IncidentCreate(BaseModel):
    title: str = Field(min_length=1, max_length=200)
    severity: int = Field(ge=1, le=4)
    status: IncidentStatus = "open"
    summary: str = ""
    mitre_tactic: str | None = None
    mitre_technique: str | None = None
    mitre_technique_name: str | None = None
    suggested_actions: list[str] = Field(default_factory=list)
    event_ids: list[int] = Field(default_factory=list)


class IncidentUpdate(BaseModel):
    status: IncidentStatus


class IncidentRead(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    title: str
    severity: int
    status: str
    summary: str
    mitre_tactic: str | None
    mitre_technique: str | None
    mitre_technique_name: str | None
    suggested_actions: list[str]
    confidence: float | None
    classified_by: str
    created_at: datetime
    updated_at: datetime


class IncidentDetail(IncidentRead):
    sigma_result: dict[str, Any] | None
    events: list[EventRead]


class IncidentPage(BaseModel):
    items: list[IncidentRead]
    total: int
    page: int
    page_size: int
