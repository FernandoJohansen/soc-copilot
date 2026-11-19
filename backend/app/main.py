from contextlib import asynccontextmanager

from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse

from app.api.v1 import analyze, events, incidents, metrics
from app.core import demo
from app.core.config import settings
from app.core.database import init_db
from app.services.assets import load_inventory


@asynccontextmanager
async def lifespan(_: FastAPI):
    # A missing or malformed inventory stops the API here, not on the first analysis.
    load_inventory(settings.asset_inventory)
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


@app.middleware("http")
async def demo_read_only(request: Request, call_next):
    if settings.demo_mode and demo.is_blocked(request.method, request.url.path):
        return JSONResponse({"detail": demo.READ_ONLY_DETAIL}, status_code=403)
    return await call_next(request)


for router in (events.router, incidents.router, analyze.router, metrics.router):
    app.include_router(router, prefix="/api/v1")


@app.get("/health", tags=["health"])
async def health() -> dict[str, str | bool]:
    return {
        "status": "ok",
        "llm_provider": settings.llm_provider,
        "demo_mode": settings.demo_mode,
    }
