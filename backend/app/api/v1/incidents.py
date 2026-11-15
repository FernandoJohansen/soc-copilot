from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload

from app.core.database import get_session
from app.models import Event, Incident
from app.schemas.incident import (
    IncidentCreate,
    IncidentDetail,
    IncidentPage,
    IncidentRead,
    IncidentUpdate,
)

router = APIRouter(prefix="/incidents", tags=["incidents"])


@router.get("", response_model=IncidentPage)
async def list_incidents(
    severity: int | None = Query(default=None, ge=1, le=4),
    tactic: str | None = None,
    status: str | None = None,
    page: int = Query(default=1, ge=1),
    page_size: int = Query(default=20, ge=1, le=100),
    session: AsyncSession = Depends(get_session),
):
    filters = []
    if severity is not None:
        filters.append(Incident.severity == severity)
    if tactic:
        filters.append(Incident.mitre_tactic == tactic)
    if status:
        filters.append(Incident.status == status)
    total = await session.scalar(select(func.count(Incident.id)).where(*filters))
    items = await session.scalars(
        select(Incident)
        .where(*filters)
        .order_by(Incident.created_at.desc(), Incident.id.desc())
        .limit(page_size)
        .offset((page - 1) * page_size)
    )
    return IncidentPage(items=items.all(), total=total or 0, page=page, page_size=page_size)


@router.get("/tactics", response_model=list[str])
async def list_tactics(session: AsyncSession = Depends(get_session)):
    """Tactics that appear in at least one incident, for the dashboard filter."""
    rows = await session.scalars(
        select(Incident.mitre_tactic)
        .where(Incident.mitre_tactic.is_not(None))
        .distinct()
        .order_by(Incident.mitre_tactic)
    )
    return rows.all()


async def _load(session: AsyncSession, incident_id: int) -> Incident:
    incident = await session.scalar(
        select(Incident).where(Incident.id == incident_id).options(selectinload(Incident.events))
    )
    if incident is None:
        raise HTTPException(status_code=404, detail="Incident not found")
    return incident


@router.get("/{incident_id}", response_model=IncidentDetail)
async def get_incident(incident_id: int, session: AsyncSession = Depends(get_session)):
    return await _load(session, incident_id)


@router.post("", response_model=IncidentRead, status_code=201)
async def create_incident(payload: IncidentCreate, session: AsyncSession = Depends(get_session)):
    data = payload.model_dump(exclude={"event_ids"})
    incident = Incident(**data, classified_by="manual")
    session.add(incident)
    await session.flush()
    if payload.event_ids:
        events = await session.scalars(select(Event).where(Event.id.in_(payload.event_ids)))
        for event in events:
            event.incident_id = incident.id
    await session.commit()
    return incident


@router.patch("/{incident_id}", response_model=IncidentRead)
async def update_incident(
    incident_id: int, payload: IncidentUpdate, session: AsyncSession = Depends(get_session)
):
    incident = await session.get(Incident, incident_id)
    if incident is None:
        raise HTTPException(status_code=404, detail="Incident not found")
    incident.status = payload.status
    await session.commit()
    await session.refresh(incident)
    return incident
