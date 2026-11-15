import json
from pathlib import Path
from typing import Any

from fastapi import APIRouter, HTTPException

from app.core.config import settings

router = APIRouter(tags=["metrics"])


@router.get("/metrics")
async def get_metrics() -> dict[str, Any]:
    """The latest eval report (agent vs. Sigma baseline), as written by the eval suite."""
    path = Path(settings.eval_results_path)
    if not path.exists():
        raise HTTPException(status_code=404, detail="No eval results yet. Run the eval suite.")
    return json.loads(path.read_text())
