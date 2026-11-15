from fastapi import APIRouter, Depends, HTTPException, Request
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core import demo
from app.core.config import settings
from app.core.database import get_session
from app.models import Event
from app.schemas.analysis import (
    AnalyzeRequest,
    AnalyzeResponse,
    AutoAnalyzeRequest,
    AutoAnalyzeResponse,
)
from app.services.analysis import analyze_events, analyze_unassigned

router = APIRouter(tags=["analyze"])


def _demo_admit(payload: AnalyzeRequest, request: Request) -> None:
    """In demo mode, bound the request size and spend one unit of the visitor's quota."""
    size = len(payload.events or payload.event_ids or [])
    if size > settings.demo_max_events:
        raise HTTPException(
            status_code=413,
            detail=f"The demo analyzes at most {settings.demo_max_events} events at a time.",
        )
    refused = demo.quota.take(demo.client_ip(request))
    if refused:
        raise HTTPException(status_code=429, detail=refused)


@router.post("/analyze", response_model=AnalyzeResponse)
async def analyze(
    payload: AnalyzeRequest, request: Request, session: AsyncSession = Depends(get_session)
):
    """Classify one group of events: RAG over ATT&CK, the Sigma baseline, then the LLM agent.

    In demo mode nothing is saved and calls are rate-limited."""
    if settings.demo_mode:
        _demo_admit(payload, request)
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
        persist=payload.persist and not settings.demo_mode,
    )


@router.post("/analyze/auto", response_model=AutoAnalyzeResponse)
async def analyze_auto(payload: AutoAnalyzeRequest, session: AsyncSession = Depends(get_session)):
    """Group every event not yet tied to an incident (by IP, user and time), then analyze
    each group. Groups are analyzed largest first, up to max_groups."""
    return await analyze_unassigned(session, **payload.model_dump())
