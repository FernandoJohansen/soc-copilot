"""Load the sample scenarios and turn them into incidents, for a public demo.

Demo mode closes the HTTP write endpoints, so this runs the same pipeline in-process:

    docker compose -f docker-compose.prod.yml exec api python scripts/seed_demo.py

It does nothing when incidents already exist, unless --force is given. It makes one LLM
call per event group (about five with the default scenarios).
"""

import argparse
import asyncio
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from sqlalchemy import func, select  # noqa: E402

from app.core.database import SessionLocal, init_db  # noqa: E402
from app.models import Incident  # noqa: E402
from app.services.analysis import analyze_unassigned  # noqa: E402
from scripts.generate_logs import _insert, generate_all  # noqa: E402
from scripts.seed_mitre import seed_if_empty  # noqa: E402


async def seed(seed: int, force: bool) -> None:
    await init_db()
    await seed_if_empty()
    async with SessionLocal() as session:
        existing = await session.scalar(select(func.count(Incident.id)))
    if existing and not force:
        print(f"{existing} incidents already exist; nothing to do (use --force to add more).")
        return

    await _insert(generate_all(seed))
    async with SessionLocal() as session:
        # The sample phishing click comes 14 minutes after the email, past the API's default
        # 10-minute window; the scenarios are an hour apart, so 30 minutes merges nothing else.
        report = await analyze_unassigned(session, window_minutes=30, min_events=2)
    for result in report.results:
        by = "llm" if result.llm_result else f"sigma fallback ({result.llm_error})"
        print(f"incident {result.incident_id}: {result.event_count} events, classified by {by}")
    print(f"{report.groups_analyzed} of {report.groups_found} groups analyzed.")


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--seed", type=int, default=42)
    parser.add_argument("--force", action="store_true", help="seed even if incidents exist")
    args = parser.parse_args()
    asyncio.run(seed(args.seed, args.force))


if __name__ == "__main__":
    main()
