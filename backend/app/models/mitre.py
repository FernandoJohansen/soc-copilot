from pgvector.sqlalchemy import Vector
from sqlalchemy import String, Text
from sqlalchemy.orm import Mapped, mapped_column

from app.core.database import Base

EMBEDDING_DIM = 384  # all-MiniLM-L6-v2


class MitreTechnique(Base):
    __tablename__ = "mitre_techniques"

    id: Mapped[int] = mapped_column(primary_key=True)
    technique_id: Mapped[str] = mapped_column(String(16), unique=True, index=True)
    name: Mapped[str] = mapped_column(String(128))
    tactic: Mapped[str] = mapped_column(String(64))
    description: Mapped[str] = mapped_column(Text)
    detection_hints: Mapped[str] = mapped_column(Text, default="")
    embedding: Mapped[list[float]] = mapped_column(Vector(EMBEDDING_DIM))
