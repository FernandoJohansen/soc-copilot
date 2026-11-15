from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.database import get_session
from app.models import Event
from app.schemas.event import CefIngestRequest, EventCreate, EventRead
from app.services.cef import parse_cef

router = APIRouter(prefix="/events", tags=["events"])


@router.post("", response_model=EventRead, status_code=201)
async def create_event(payload: EventCreate, session: AsyncSession = Depends(get_session)):
    event = Event(**payload.model_dump())
    session.add(event)
    await session.commit()
    return event


@router.post("/batch", response_model=list[EventRead], status_code=201)
async def create_events(payload: list[EventCreate], session: AsyncSession = Depends(get_session)):
    events = [Event(**item.model_dump()) for item in payload]
    session.add_all(events)
    await session.commit()
    return events


@router.post("/cef", response_model=list[EventRead], status_code=201)
async def ingest_cef(payload: CefIngestRequest, session: AsyncSession = Depends(get_session)):
    events = []
    for number, line in enumerate(payload.lines, start=1):
        try:
            events.append(Event(**parse_cef(line)))
        except ValueError as e:
            raise HTTPException(status_code=422, detail=f"line {number}: {e}") from e
    session.add_all(events)
    await session.commit()
    return events


@router.get("", response_model=list[EventRead])
async def list_events(
    source: str | None = None,
    unassigned: bool = False,
    limit: int = Query(default=100, ge=1, le=1000),
    offset: int = Query(default=0, ge=0),
    session: AsyncSession = Depends(get_session),
):
    query = select(Event).order_by(Event.timestamp.desc()).limit(limit).offset(offset)
    if source:
        query = query.where(Event.source == source)
    if unassigned:
        query = query.where(Event.incident_id.is_(None))
    return (await session.scalars(query)).all()


@router.get("/{event_id}", response_model=EventRead)
async def get_event(event_id: int, session: AsyncSession = Depends(get_session)):
    event = await session.get(Event, event_id)
    if event is None:
        raise HTTPException(status_code=404, detail="Event not found")
    return event
