"""What the events prove, checked in code, so the LLM's verdict can be held to it.

The model names the attack stage, and the severity follows from the stage. Left alone, a
7B model calls almost everything "success" (port scans and failed brute force come out
critical) and flags ordinary activity as incidents. These checks do not rank or explain
attacks; that is the model's job. They answer two narrower questions:

- How far do the events show the attack got? The model's stage is capped there.
- Do the events show any attack step at all? If not, and every event is of a kind these
  checks know how to read, the model's "incident" is overruled. Groups with any other kind
  of event keep the model's verdict, so the agent can still flag attacks nothing here
  describes.

The checks are deliberately loose: a benign backup job passes the lateral-movement check.
A loose check only lets the model's answer through, while a strict one would overrule it
on real attacks. What tells the backup job apart is knowing the network, not the events:
events that are the routine work of a known asset (services/assets.py) are set aside
before the checks run.
"""

from collections import defaultdict
from collections.abc import Sequence
from dataclasses import dataclass
from datetime import datetime
from typing import Any

from app.schemas.analysis import AnalysisResult
from app.services.assets import Asset, routine_owner
from app.services.severity import STAGE_SEVERITY

EventDict = dict[str, Any]

STAGES = list(STAGE_SEVERITY)  # none < reconnaissance < attempt < success

# Account-lockout policies commonly trip at 5 failures (CIS recommends 5 or fewer); below
# that, failed logins are a user mistyping, not password guessing.
MIN_FAILURES = 5

# One source reaching this many distinct host:port pairs is scanning, not using a service.
MIN_SCAN_TARGETS = 10

# Below this many distinct names under one domain from one host, DNS is ordinary browsing.
MIN_TUNNEL_QUERIES = 20

# Large CDNs and clouds serve thousands of random-looking hostnames. DNS-tunnel detection
# excludes them; a tunnel needs a domain the attacker controls the name server for.
CDN_DOMAINS = (
    "akamaiedge.net",
    "akamaized.net",
    "amazonaws.com",
    "azureedge.net",
    "cloudflare.net",
    "cloudfront.net",
    "edgekey.net",
    "fastly.net",
    "googleusercontent.com",
    "googlevideo.com",
)

# A sender domain younger than this is a classic phishing sign.
YOUNG_DOMAIN_DAYS = 30

# The event kinds these checks read. A group made only of these, with no finding, is
# ordinary activity; a group with any other kind is left to the model.
KNOWN_KINDS = {
    ("auth.log", "authentication_failure"),
    ("auth.log", "authentication_success"),
    ("dns", "query"),
    ("email_gateway", "email_received"),
    ("firewall", "connection_attempt"),
    ("proxy", "file_download"),
    ("proxy", "url_click"),
    ("windows_security", "logon"),
    ("windows_security", "service_install"),
    ("windows_security", "share_access"),
}

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


def _failures_by_ip(events: Sequence[EventDict]) -> dict[str, list[datetime]]:
    by_ip: dict[str, list[datetime]] = defaultdict(list)
    for e in _of(events, "auth.log", "authentication_failure"):
        if _raw(e, "src_ip"):
            by_ip[_raw(e, "src_ip")].append(_ts(e))
    return {ip: times for ip, times in by_ip.items() if len(times) >= MIN_FAILURES}


def _password_guessing(events: Sequence[EventDict]) -> list[Finding]:
    """Repeated failed logins from one IP; success if that IP then logged in."""
    guessing = _failures_by_ip(events)
    for e in _of(events, "auth.log", "authentication_success"):
        ip = _raw(e, "src_ip")
        if ip in guessing and _ts(e) > min(guessing[ip]):
            n = len(guessing[ip])
            return [Finding("success", "credential access", f"{ip} logged in after {n} failures")]
    return [
        Finding("attempt", "credential access", f"{len(times)} failed logins from {ip}")
        for ip, times in guessing.items()
    ][:1]


def _scan(events: Sequence[EventDict]) -> Finding | None:
    targets: dict[str, set[tuple[Any, Any]]] = defaultdict(set)
    for e in _of(events, "firewall", "connection_attempt"):
        targets[str(_raw(e, "src_ip"))].add((_raw(e, "dst_ip"), _raw(e, "dst_port")))
    for ip, reached in targets.items():
        if len(reached) >= MIN_SCAN_TARGETS:
            return Finding("reconnaissance", "discovery", f"{ip} probed {len(reached)} targets")
    return None


def _suspicious_email(events: Sequence[EventDict]) -> Finding | None:
    """A delivered email with a phishing sign: a young sender domain, or SPF failing on a
    message that was not relayed by a mailing list (relaying breaks SPF). An email with
    neither field known still counts: absent data should not clear it."""
    for e in _of(events, "email_gateway", "email_received"):
        age, spf = _raw(e, "sender_domain_age_days"), _raw(e, "spf")
        young = age is None or age < YOUNG_DOMAIN_DAYS
        spf_fails = spf in (None, "fail", "softfail") and not _raw(e, "via")
        if young or spf_fails:
            sender = _raw(e, "sender") or "an unknown sender"
            return Finding("attempt", "initial access", f"an email from {sender} was delivered")
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
        if domain.endswith(CDN_DOMAINS):
            continue
        if len(queries) >= MIN_TUNNEL_QUERIES:
            return Finding(
                "success", "exfiltration", f"{ip} queried {len(queries)} names under {domain}"
            )
    return None


def findings(events: Sequence[EventDict]) -> list[Finding]:
    checks = (_download, _internal_spread, _dns_tunnel_shape, _suspicious_email, _scan)
    return _password_guessing(events) + [f for check in checks if (f := check(events))]


def _all_known(events: Sequence[EventDict]) -> bool:
    return bool(events) and all(
        (e.get("source"), e.get("event_type")) in KNOWN_KINDS for e in events
    )


def _rank(stage: str | None) -> int:
    return STAGES.index(stage) if stage in STAGES else -1


def _set_aside(events: Sequence[EventDict], assets: Sequence[Asset]) -> str:
    """Name the known assets whose routine work is among the events, for the note."""
    owners = {a.name: a.role for e in events if (a := routine_owner(e, assets))}
    if not owners:
        return ""
    named = ", ".join(f"{name} ({role})" if role else name for name, role in sorted(owners.items()))
    return f" Set aside as routine work of known assets: {named}."


def settle_stage(
    result: AnalysisResult, events: Sequence[EventDict], assets: Sequence[Asset] = ()
) -> AnalysisResult:
    """Hold the model's verdict and attack stage to what the events show, and re-derive
    the severity.

    Events that are the routine work of one of `assets` do not count as evidence.

    Returns the result unchanged when it is not an incident or has no stage (the Sigma
    baseline, an unparseable answer); otherwise a copy with the corrections and an
    evidence_note saying what changed.
    """
    if not result.is_incident or _rank(result.attack_stage) < 0:
        return result
    evidence = findings([e for e in events if not routine_owner(e, assets)])
    aside = _set_aside(events, assets)
    if not evidence and _all_known(events):
        return result.model_copy(
            update={
                "is_incident": False,
                "attack_stage": "none",
                "severity": 1,
                "mitre_tactic": None,
                "mitre_technique_id": None,
                "mitre_technique_name": None,
                "evidence_note": (
                    f"Not an incident: the model said {result.attack_stage}, but the events "
                    "show no attack step (no repeated failed logins, scan, suspicious email, "
                    "download, spread between hosts or DNS tunnel)." + aside
                ),
            }
        )
    tactic = (result.mitre_tactic or "").strip().lower()

    # Anything the model calls an incident is at least reconnaissance, even with no finding.
    # Events these checks cannot read may show a later stage, so they lift the cap.
    ceiling = max([_rank("reconnaissance")] + [_rank(f.stage) for f in evidence])
    if not _all_known(events):
        ceiling = _rank("success")
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
            "evidence_note": note + aside,
        }
    )
