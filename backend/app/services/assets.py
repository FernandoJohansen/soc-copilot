"""The inventory of known assets: which hosts do what, so their routine work is not an attack.

Some benign activity looks the same as an attack in the events. The backup server logs on
to every file server and reads its shares, which is what lateral movement looks like; a CI
runner with an expired key fails to log in again and again, which is what password guessing
looks like. Nothing in the events tells them apart. What does is knowing the network, the
way an analyst knows that bkp-01 is the backup server.

An event is an asset's routine only when all of these match:

- the source IP is the asset's, and the source host name too when the event carries one;
- the account is one the asset uses;
- the event kind is one the asset produces in its normal work.

So the inventory excuses events, not accounts or hosts. svc_backup logging on from a
workstation is not routine, and neither is a service installed from the backup server,
because installing services is not what a backup server does.

The inventory is off unless ASSET_INVENTORY names a JSON file. On a network that does not
match it, it would hide real activity, so it never applies by default.

    {"assets": [{"name": "bkp-01", "ip": "10.0.0.20", "role": "backup server",
                 "accounts": ["svc_backup"],
                 "routine": ["windows_security/logon", "windows_security/share_access"]}]}
"""

import json
from collections.abc import Sequence
from dataclasses import dataclass
from functools import lru_cache
from pathlib import Path
from typing import Any

EventDict = dict[str, Any]

# The inventory of the synthetic network that scripts/generate_logs.py writes logs for. The
# evals and the demo use it; it describes no real network.
SYNTHETIC_INVENTORY = Path(__file__).resolve().parents[1] / "data" / "synthetic_assets.json"


@dataclass(frozen=True)
class Asset:
    name: str
    ip: str
    role: str
    accounts: frozenset[str]
    routine: frozenset[tuple[str, str]]  # (source, event_type)

    def does(self, event: EventDict) -> bool:
        raw = event.get("raw_data") or {}
        if raw.get("src_ip") != self.ip:
            return False
        if raw.get("src_host") not in (None, self.name):
            return False
        if raw.get("user") not in self.accounts:
            return False
        return (event.get("source"), event.get("event_type")) in self.routine


def _kind(text: str) -> tuple[str, str]:
    source, sep, event_type = text.partition("/")
    if not sep or not source or not event_type:
        raise ValueError(f"routine entries are 'source/event_type', got {text!r}")
    return source, event_type


def parse_inventory(data: dict[str, Any]) -> tuple[Asset, ...]:
    assets = []
    for item in data.get("assets", []):
        if not item.get("name") or not item.get("ip"):
            raise ValueError(f"every asset needs a name and an ip, got {item!r}")
        if not item.get("accounts") or not item.get("routine"):
            raise ValueError(f"asset {item.get('name')!r} needs accounts and routine")
        assets.append(
            Asset(
                name=item["name"],
                ip=item["ip"],
                role=item.get("role", ""),
                accounts=frozenset(item["accounts"]),
                routine=frozenset(_kind(k) for k in item["routine"]),
            )
        )
    return tuple(assets)


@lru_cache
def load_inventory(path: str) -> tuple[Asset, ...]:
    """The assets in the JSON file at `path`; none when `path` is empty."""
    if not path:
        return ()
    return parse_inventory(json.loads(Path(path).read_text()))


def routine_owner(event: EventDict, assets: Sequence[Asset]) -> Asset | None:
    """The asset whose routine work this event is, if any."""
    return next((a for a in assets if a.does(event)), None)
