"""Group raw events into incident candidates.

Two events land in the same group when they share an entity (source IP or user) and are
no more than `window_minutes` apart. Sharing is transitive, so a phishing chain that goes
email (user) -> proxy click (user + IP) -> download (IP) ends up as one group.
"""

from collections.abc import Sequence
from datetime import datetime, timedelta
from typing import Any

EventDict = dict[str, Any]

_ENTITY_FIELDS = (("ip", "src_ip"), ("user", "user"), ("user", "recipient"))


def _entities(event: EventDict) -> set[tuple[str, str]]:
    raw = event.get("raw_data") or {}
    found = set()
    for kind, field in _ENTITY_FIELDS:
        value = raw.get(field)
        if value:
            found.add((kind, str(value).lower()))
    return found


def _as_datetime(value: Any) -> datetime:
    if isinstance(value, datetime):
        return value
    return datetime.fromisoformat(str(value).replace("Z", "+00:00"))


def group_events(
    events: Sequence[EventDict], window_minutes: int = 10, min_events: int = 1
) -> list[list[EventDict]]:
    """Return groups of related events, each sorted by time, largest group first."""
    ordered = sorted(events, key=lambda e: _as_datetime(e["timestamp"]))
    parent = list(range(len(ordered)))

    def find(i: int) -> int:
        while parent[i] != i:
            parent[i] = parent[parent[i]]
            i = parent[i]
        return i

    window = timedelta(minutes=window_minutes)
    last_seen: dict[tuple[str, str], tuple[int, datetime]] = {}
    for i, event in enumerate(ordered):
        ts = _as_datetime(event["timestamp"])
        for entity in _entities(event):
            if entity in last_seen:
                j, previous_ts = last_seen[entity]
                if ts - previous_ts <= window:
                    parent[find(i)] = find(j)
            last_seen[entity] = (i, ts)

    groups: dict[int, list[EventDict]] = {}
    for i, event in enumerate(ordered):
        groups.setdefault(find(i), []).append(event)
    result = [g for g in groups.values() if len(g) >= min_events]
    result.sort(key=len, reverse=True)
    return result
