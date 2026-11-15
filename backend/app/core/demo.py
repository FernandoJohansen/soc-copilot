"""Public demo mode: a read-only API whose one open write, POST /analyze, is rate-limited.

The quota lives in process memory, which is right for the single uvicorn process the
compose files run. More workers or replicas would each keep their own count.
"""

import time
from collections import defaultdict, deque
from collections.abc import Callable

from fastapi import Request

from app.core.config import settings

SAFE_METHODS = frozenset({"GET", "HEAD", "OPTIONS"})
# Writes that stay open in demo mode. /analyze runs with persist forced off.
DEMO_WRITABLE_PATHS = frozenset({"/api/v1/analyze"})

READ_ONLY_DETAIL = "This is a read-only demo. Run the project locally to ingest and change data."


def is_blocked(method: str, path: str) -> bool:
    """True when demo mode refuses this request."""
    return method.upper() not in SAFE_METHODS and path not in DEMO_WRITABLE_PATHS


def client_ip(request: Request) -> str:
    """The visitor's address.

    In production Caddy is the only entry point and sets X-Forwarded-For to the address it
    saw (it drops any value the client sent); Nginx appends its own hop after it. So the
    first entry is the visitor. Without a proxy, fall back to the socket peer.
    """
    forwarded = request.headers.get("x-forwarded-for", "")
    first = forwarded.split(",")[0].strip()
    if first:
        return first
    return request.client.host if request.client else "unknown"


class AnalyzeQuota:
    """A sliding one-hour window per IP, plus one counter per UTC day for everyone."""

    _MAX_TRACKED_IPS = 10_000

    def __init__(
        self, per_ip_per_hour: int, per_day: int, clock: Callable[[], float] = time.time
    ) -> None:
        self.per_ip_per_hour = per_ip_per_hour
        self.per_day = per_day
        self._clock = clock
        self._hits: defaultdict[str, deque[float]] = defaultdict(deque)
        self._day = -1
        self._day_count = 0

    def _prune(self, now: float) -> None:
        for ip in [ip for ip, hits in self._hits.items() if not hits or now - hits[-1] >= 3600]:
            del self._hits[ip]

    def take(self, ip: str) -> str | None:
        """Record one analysis for `ip`. Returns why it is refused, or None if allowed."""
        now = self._clock()
        day = int(now // 86_400)
        if day != self._day:
            self._day, self._day_count = day, 0
        if self._day_count >= self.per_day:
            return "The demo's analysis budget for today is used up. Try again tomorrow."

        hits = self._hits[ip]
        while hits and now - hits[0] >= 3600:
            hits.popleft()
        if len(hits) >= self.per_ip_per_hour:
            retry = int(3600 - (now - hits[0])) // 60 + 1 if hits else 60
            return (
                f"The demo allows {self.per_ip_per_hour} analyses per hour. "
                f"Try again in {retry} minutes."
            )

        hits.append(now)
        self._day_count += 1
        if len(self._hits) > self._MAX_TRACKED_IPS:
            self._prune(now)
        return None


quota = AnalyzeQuota(settings.demo_analyses_per_ip_per_hour, settings.demo_analyses_per_day)
