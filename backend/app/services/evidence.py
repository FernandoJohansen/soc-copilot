"""What the events prove, checked in code, so the LLM's attack stage can be held to it.

The model names the attack stage, and the severity follows from the stage. Left alone, a
7B model calls almost everything "success": port scans and failed brute force come out
critical. These checks do not detect attacks (that is the model's job and the Sigma
baseline's); they only answer "do the events show this far?". The stage the model gives is
capped at the highest stage the evidence supports.

The checks are deliberately loose: a benign backup job passes the lateral-movement check,
and a CDN passes the DNS one. A cap can only lower a stage, so a loose check costs nothing
on benign groups, while a strict one would wrongly demote real attacks.
"""

from collections import defaultdict
from collections.abc import Sequence
from dataclasses import dataclass
from datetime import datetime
from typing import Any

from app.schemas.analysis import AnalysisResult
from app.services.severity import STAGE_SEVERITY

EventDict = dict[str, Any]

STAGES = list(STAGE_SEVERITY)  # none < reconnaissance < attempt < success

# Below this many distinct names under one domain from one host, DNS is ordinary browsing.
MIN_TUNNEL_QUERIES = 20

# A scan finds hosts; it does not get into them, whatever the model says about the stage.
TACTIC_MAX_STAGE = {"discovery": "reconnaissance"}

# Once the events show these, the attacker is already inside (the stage policy says so):
# the stage is raised to "success" when the model under-calls it.
ALWAYS_SUCCESS = {"lateral movement", "exfiltration"}


@dataclass(frozen=True)
class Finding:
    stage: str
    tactic: str
    what: str


def _raw(event: EventDict, key: str, default: Any = None) -> Any:
    return (event.get("raw_data") or {}).get(key, default)


def _ts(event: EventDict) -> datetime:
    value = event["timestamp"]
    if isinstance(value, datetime):
        return value
    return datetime.fromisoformat(str(value).replace("Z", "+00:00"))


def _of(events: Sequence[EventDict], source: str, event_type: str) -> list[EventDict]:
    return [e for e in events if e.get("source") == source and e.get("event_type") == event_type]


def _login_after_failures(events: Sequence[EventDict]) -> Finding | None:
    """A successful login from an IP that had failed before it."""
    first_failure: dict[str, datetime] = {}
    for e in _of(events, "auth.log", "authentication_failure"):
        ip = _raw(e, "src_ip")
        if ip and (ip not in first_failure or _ts(e) < first_failure[ip]):
            first_failure[ip] = _ts(e)
    for e in _of(events, "auth.log", "authentication_success"):
        ip = _raw(e, "src_ip")
        if ip in first_failure and _ts(e) > first_failure[ip]:
            return Finding("success", "credential access", f"{ip} logged in after failing")
    return None


def _download(events: Sequence[EventDict]) -> Finding | None:
    downloads = _of(events, "proxy", "file_download")
    if downloads:
        name = _raw(downloads[0], "filename") or _raw(downloads[0], "url")
        return Finding("success", "initial access", f"a file was downloaded ({name})")
    return None


def _internal_spread(events: Sequence[EventDict]) -> Finding | None:
    """One source reaching other hosts: network logons to two or more, an admin share or a
    remotely installed service."""
    hosts: dict[str, set[str]] = defaultdict(set)
    for e in _of(events, "windows_security", "logon"):
        if _raw(e, "src_ip") and _raw(e, "host"):
            hosts[_raw(e, "src_ip")].add(_raw(e, "host"))
    for ip, reached in hosts.items():
        if len(reached) >= 2:
            return Finding("success", "lateral movement", f"{ip} logged on to {len(reached)} hosts")
    for e in _of(events, "windows_security", "share_access"):
        if str(_raw(e, "share", "")).rstrip("\\").endswith(("$", "ADMIN$", "C$")):
            return Finding("success", "lateral movement", f"{_raw(e, 'share')} was opened")
    if _of(events, "windows_security", "service_install"):
        return Finding("success", "lateral movement", "a service was installed remotely")
    return None


def _dns_tunnel_shape(events: Sequence[EventDict]) -> Finding | None:
    """Many distinct names under one domain from one host: what a DNS tunnel looks like."""
    names: dict[tuple[str, str], set[str]] = defaultdict(set)
    for e in _of(events, "dns", "query"):
        key = (str(_raw(e, "src_ip")), str(_raw(e, "domain")))
        names[key].add(str(_raw(e, "query")))
    for (ip, domain), queries in names.items():
        if len(queries) >= MIN_TUNNEL_QUERIES:
            return Finding(
                "success", "exfiltration", f"{ip} queried {len(queries)} names under {domain}"
            )
    return None


def _attempts(events: Sequence[EventDict]) -> list[Finding]:
    found = []
    if _of(events, "auth.log", "authentication_failure"):
        found.append(Finding("attempt", "credential access", "failed logins"))
    if _of(events, "email_gateway", "email_received"):
        found.append(Finding("attempt", "initial access", "an email was delivered"))
    return found


def findings(events: Sequence[EventDict]) -> list[Finding]:
    checks = (_login_after_failures, _download, _internal_spread, _dns_tunnel_shape)
    return [f for check in checks if (f := check(events))] + _attempts(events)


def _rank(stage: str | None) -> int:
    return STAGES.index(stage) if stage in STAGES else -1


def settle_stage(result: AnalysisResult, events: Sequence[EventDict]) -> AnalysisResult:
    """Hold the model's attack stage to what the events show, and re-derive the severity.

    Returns the result unchanged when it is not an incident or has no stage (the Sigma
    baseline, an unparseable answer); otherwise a copy with stage, severity and
    stage_note set.
    """
    if not result.is_incident or _rank(result.attack_stage) < 0:
        return result
    evidence = findings(events)
    tactic = (result.mitre_tactic or "").strip().lower()

    # Anything the model calls an incident is at least reconnaissance, even with no finding.
    ceiling = max([_rank("reconnaissance")] + [_rank(f.stage) for f in evidence])
    stage = min(_rank(result.attack_stage), ceiling)
    if tactic in TACTIC_MAX_STAGE:
        stage = min(stage, _rank(TACTIC_MAX_STAGE[tactic]))
    if tactic in ALWAYS_SUCCESS and any(f.tactic == tactic for f in evidence):
        stage = _rank("success")
    stage = max(stage, _rank("reconnaissance"))  # an incident is never "none"

    settled = STAGES[stage]
    if settled == result.attack_stage:
        if result.severity == STAGE_SEVERITY[settled]:
            return result
        return result.model_copy(update={"severity": STAGE_SEVERITY[settled]})
    strongest = max(evidence, key=lambda f: _rank(f.stage), default=None)
    shown = strongest.what if strongest else "no attack step beyond the activity itself"
    note = f"Stage set to {settled} from {result.attack_stage}: the events show {shown}."
    if tactic in TACTIC_MAX_STAGE and _rank(result.attack_stage) > stage:
        note = f"Stage capped at {settled} for {result.mitre_tactic}; the model said " + (
            f"{result.attack_stage}."
        )
    return result.model_copy(
        update={
            "attack_stage": settled,
            "severity": STAGE_SEVERITY[settled],
            "stage_note": note,
        }
    )
