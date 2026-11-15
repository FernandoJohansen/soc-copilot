from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.database import get_session
from app.models import Event
from app.schemas.analysis import (
    AnalyzeRequest,
    AnalyzeResponse,
    AutoAnalyzeRequest,
    AutoAnalyzeResponse,
)
from app.services.analysis import analyze_events, event_to_dict
from app.services.correlation import group_events

router = APIRouter(tags=["analyze"])


@router.post("/analyze", response_model=AnalyzeResponse)
async def analyze(payload: AnalyzeRequest, session: AsyncSession = Depends(get_session)):
    """Classify one group of events: RAG over ATT&CK, the Sigma baseline, then the LLM agent."""
    stored: list[Event] = []
    if payload.event_ids:
        rows = await session.scalars(select(Event).where(Event.id.in_(payload.event_ids)))
        stored = list(rows.all())
        missing = set(payload.event_ids) - {e.id for e in stored}
        if missing:
            raise HTTPException(status_code=404, detail=f"Events not found: {sorted(missing)}")
    return await analyze_events(
        session,
        stored=stored,
        inline=payload.events or [],
        use_sigma=payload.use_sigma,
        top_k=payload.top_k,
        persist=payload.persist,
    )


@router.post("/analyze/auto", response_model=AutoAnalyzeResponse)
async def analyze_auto(payload: AutoAnalyzeRequest, session: AsyncSession = Depends(get_session)):
    """Group every event not yet tied to an incident (by IP, user and time), then analyze
    each group. Groups are analyzed largest first, up to max_groups."""
    rows = await session.scalars(select(Event).where(Event.incident_id.is_(None)))
    by_key = {}
    dicts = []
    for event in rows.all():
        d = event_to_dict(event)
        d["_id"] = event.id
        by_key[event.id] = event
        dicts.append(d)
    groups = group_events(dicts, payload.window_minutes, payload.min_events)
    results = []
    for group in groups[: payload.max_groups]:
        results.append(
            await analyze_events(
                session,
                stored=[by_key[d["_id"]] for d in group],
                use_sigma=payload.use_sigma,
                top_k=payload.top_k,
            )
        )
    return AutoAnalyzeResponse(
        groups_found=len(groups), groups_analyzed=len(results), results=results
    )
