"""RAG over MITRE ATT&CK: embed a description of the events, fetch the closest techniques."""

import asyncio
from collections import Counter
from collections.abc import Sequence
from typing import Any

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.config import settings
from app.models.mitre import MitreTechnique

_model = None


def _get_model():
    global _model
    if _model is None:
        from sentence_transformers import SentenceTransformer

        _model = SentenceTransformer(settings.embedding_model)
    return _model


def embed_texts(texts: Sequence[str]) -> list[list[float]]:
    vectors = _get_model().encode(list(texts), normalize_embeddings=True)
    return [v.tolist() for v in vectors]


# Fields whose number of distinct values says something about the behaviour.
_DISTINCT_FIELDS = {
    "dst_port": "destination ports",
    "dst_ip": "destination addresses",
    "host": "hosts",
    "user": "user accounts",
    "src_ip": "source addresses",
}


def build_query_text(events: Sequence[dict[str, Any]], max_samples: int = 4) -> str:
    """A short natural-language description of a group of events, used as the search query."""
    kinds = Counter((e.get("source", "?"), e.get("event_type", "?")) for e in events)
    parts = [
        f"{count} {str(event_type).replace('_', ' ')} events in {source} logs"
        for (source, event_type), count in kinds.most_common()
    ]
    raws = [e.get("raw_data") or {} for e in events]
    for field, label in _DISTINCT_FIELDS.items():
        distinct = {raw[field] for raw in raws if raw.get(field) is not None}
        if len(distinct) > 1:
            parts.append(f"{len(distinct)} distinct {label}")
    samples: list[str] = []
    for raw in raws:
        message = raw.get("message")
        if message and message not in samples:
            samples.append(str(message))
        if len(samples) >= max_samples:
            break
    return ". ".join(parts) + (". Examples: " + " | ".join(samples) if samples else "")


async def retrieve_mitre_techniques(
    session: AsyncSession, query_text: str, top_k: int = 3
) -> list[dict[str, Any]]:
    """Top-k ATT&CK techniques by cosine distance to the query."""
    (vector,) = await asyncio.to_thread(embed_texts, [query_text])
    distance = MitreTechnique.embedding.cosine_distance(vector).label("distance")
    rows = await session.execute(select(MitreTechnique, distance).order_by(distance).limit(top_k))
    return [
        {
            "technique_id": technique.technique_id,
            "name": technique.name,
            "tactic": technique.tactic,
            "description": technique.description,
            "detection_hints": technique.detection_hints,
            "distance": round(float(dist), 4),
        }
        for technique, dist in rows.all()
    ]
