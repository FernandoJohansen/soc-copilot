"""Orchestration of one analysis: RAG -> Sigma baseline -> LLM agent -> persistence."""

import time
from collections import Counter
from collections.abc import Sequence
from typing import Any

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.models import Event, Incident
from app.schemas.analysis import AnalysisResult, AnalyzeResponse, AutoAnalyzeResponse
from app.schemas.event import EventCreate
from app.services.correlation import group_events
from app.services.evidence import settle_stage
from app.services.llm import (
    LLMError,
    format_events,
    format_mitre_context,
    get_llm_provider,
)
from app.services.rag import build_query_text, retrieve_mitre_techniques
from app.services.sigma_rules import run_sigma_rules


def event_to_dict(event: Event | EventCreate) -> dict[str, Any]:
    return {
        "source": event.source,
        "event_type": event.event_type,
        "timestamp": event.timestamp.isoformat(),
        "raw_data": event.raw_data,
    }


def _incident_title(result: AnalysisResult, events: Sequence[dict[str, Any]]) -> str:
    name = result.mitre_technique_name or result.mitre_tactic or "Suspicious activity"
    sources = Counter(
        str((e.get("raw_data") or {}).get("src_ip"))
        for e in events
        if (e.get("raw_data") or {}).get("src_ip")
    )
    origin = f" from {sources.most_common(1)[0][0]}" if sources else ""
    return f"{name}{origin}"[:200]


async def analyze_events(
    session: AsyncSession,
    *,
    stored: Sequence[Event] = (),
    inline: Sequence[EventCreate] = (),
    use_sigma: bool = True,
    top_k: int = 5,
    persist: bool = True,
) -> AnalyzeResponse:
    """Analyze one group of events, given as stored rows or as inline payloads."""
    started = time.perf_counter()
    source_events: Sequence[Event | EventCreate] = stored or inline
    events = sorted((event_to_dict(e) for e in source_events), key=lambda e: e["timestamp"])

    mitre_context = await retrieve_mitre_techniques(session, build_query_text(events), top_k)
    sigma_result = run_sigma_rules(events) if use_sigma else None

    llm_result = llm_usage = llm_error = None
    try:
        provider = get_llm_provider()
        response = await provider.analyze(
            format_events(events), format_mitre_context(mitre_context)
        )
        llm_result = settle_stage(response.result, events)
        llm_usage = response.usage
    except LLMError as e:
        llm_error = str(e)

    # The agent decides; the deterministic baseline is the fallback when it is unavailable.
    final: AnalysisResult | None = llm_result if llm_result is not None else sigma_result
    incident_id = None
    if persist:
        rows = list(stored) or [Event(**e.model_dump()) for e in inline]
        if inline:
            session.add_all(rows)
        if final is not None and final.is_incident:
            incident = Incident(
                title=_incident_title(final, events),
                severity=final.severity,
                summary=final.summary,
                mitre_tactic=final.mitre_tactic,
                mitre_technique=final.mitre_technique_id,
                mitre_technique_name=final.mitre_technique_name,
                suggested_actions=final.suggested_actions,
                confidence=final.confidence,
                classified_by="llm" if llm_result is not None else "sigma",
                sigma_result=sigma_result.model_dump() if sigma_result else None,
            )
            session.add(incident)
            await session.flush()
            for row in rows:
                row.incident_id = incident.id
                row.severity = final.severity
            incident_id = incident.id
        await session.commit()

    return AnalyzeResponse(
        incident_id=incident_id,
        event_count=len(events),
        sigma_result=sigma_result,
        llm_result=llm_result,
        llm_error=llm_error,
        llm_usage=llm_usage,
        mitre_context=mitre_context,
        latency_ms=round((time.perf_counter() - started) * 1000, 1),
    )


async def analyze_unassigned(
    session: AsyncSession,
    *,
    window_minutes: int = 10,
    min_events: int = 3,
    max_groups: int = 20,
    use_sigma: bool = True,
    top_k: int = 5,
) -> AutoAnalyzeResponse:
    """Group every event not yet tied to an incident (by IP, user and time), then analyze
    each group, largest first, up to max_groups."""
    rows = await session.scalars(select(Event).where(Event.incident_id.is_(None)))
    by_id: dict[int, Event] = {}
    dicts = []
    for event in rows.all():
        d = event_to_dict(event)
        d["_id"] = event.id
        by_id[event.id] = event
        dicts.append(d)
    groups = group_events(dicts, window_minutes, min_events)
    results = [
        await analyze_events(
            session,
            stored=[by_id[d["_id"]] for d in group],
            use_sigma=use_sigma,
            top_k=top_k,
        )
        for group in groups[:max_groups]
    ]
    return AutoAnalyzeResponse(
        groups_found=len(groups), groups_analyzed=len(results), results=results
    )
