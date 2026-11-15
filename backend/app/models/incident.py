from datetime import UTC, datetime
from typing import Any

from sqlalchemy import DateTime, Float, Integer, String, Text
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.core.database import Base


def _now() -> datetime:
    return datetime.now(UTC)


class Incident(Base):
    __tablename__ = "incidents"

    id: Mapped[int] = mapped_column(primary_key=True)
    title: Mapped[str] = mapped_column(String(200))
    severity: Mapped[int] = mapped_column(Integer, index=True)  # 1 low .. 4 critical
    status: Mapped[str] = mapped_column(String(20), default="open", index=True)
    summary: Mapped[str] = mapped_column(Text, default="")
    mitre_tactic: Mapped[str | None] = mapped_column(String(64), nullable=True, index=True)
    mitre_technique: Mapped[str | None] = mapped_column(String(16), nullable=True)
    mitre_technique_name: Mapped[str | None] = mapped_column(String(128), nullable=True)
    suggested_actions: Mapped[list[str]] = mapped_column(JSONB, default=list)
    confidence: Mapped[float | None] = mapped_column(Float, nullable=True)
    # "llm" when the agent classified it, "sigma" when the rule baseline was the fallback.
    classified_by: Mapped[str] = mapped_column(String(16), default="llm")
    sigma_result: Mapped[dict[str, Any] | None] = mapped_column(JSONB, nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_now)
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=_now, onupdate=_now
    )

    events = relationship("Event", back_populates="incident", order_by="Event.timestamp")
