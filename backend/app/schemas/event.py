from datetime import UTC, datetime
from typing import Any

from pydantic import BaseModel, ConfigDict, Field


class EventCreate(BaseModel):
    source: str = Field(min_length=1, max_length=64, examples=["auth.log"])
    event_type: str = Field(min_length=1, max_length=64, examples=["authentication_failure"])
    raw_data: dict[str, Any] = Field(default_factory=dict)
    timestamp: datetime = Field(default_factory=lambda: datetime.now(UTC))
    severity: int | None = Field(default=None, ge=1, le=4)


class EventRead(EventCreate):
    model_config = ConfigDict(from_attributes=True)

    id: int
    incident_id: int | None = None


class CefIngestRequest(BaseModel):
    lines: list[str] = Field(min_length=1)
