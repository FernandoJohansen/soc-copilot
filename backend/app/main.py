from contextlib import asynccontextmanager

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from app.api.v1 import analyze, events, incidents, metrics
from app.core.config import settings
from app.core.database import init_db


@asynccontextmanager
async def lifespan(_: FastAPI):
    await init_db()
    if settings.auto_seed:
        from scripts.seed_mitre import seed_if_empty

        await seed_if_empty()
    yield


app = FastAPI(
    title="SOC Copilot",
    description="LLM agent that triages security logs into explained incidents, "
    "measured against a Sigma-style rule baseline.",
    version="0.1.0",
    lifespan=lifespan,
)
app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.cors_origins,
    allow_methods=["*"],
    allow_headers=["*"],
)

for router in (events.router, incidents.router, analyze.router, metrics.router):
    app.include_router(router, prefix="/api/v1")


@app.get("/health", tags=["health"])
async def health() -> dict[str, str]:
    return {"status": "ok", "llm_provider": settings.llm_provider}
