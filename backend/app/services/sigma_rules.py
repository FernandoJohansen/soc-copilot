"""Deterministic, Sigma-style detection rules.

This is the baseline the LLM agent is measured against, and the fallback when the LLM is
unavailable. Every rule looks at one source, checks a fixed threshold and returns a
SigmaMatch or None. Events are plain dicts: source, event_type, timestamp, raw_data.
"""

from collections import defaultdict
from collections.abc import Callable, Sequence
from datetime import datetime, timedelta
from typing import Any

from app.schemas.analysis import SigmaMatch

EventDict = dict[str, Any]


def _ts(event: EventDict) -> datetime:
    value = event["timestamp"]
    if isinstance(value, datetime):
        return value
    return datetime.fromisoformat(str(value).replace("Z", "+00:00"))


def _select(events: Sequence[EventDict], source: str, event_type: str) -> list[EventDict]:
    return [e for e in events if e.get("source") == source and e.get("event_type") == event_type]


def _raw(event: EventDict, key: str, default: Any = None) -> Any:
    return (event.get("raw_data") or {}).get(key, default)


def _max_in_window(times: list[datetime], window: timedelta) -> int:
    """Largest number of timestamps that fit inside any window of the given length."""
    times = sorted(times)
    best = start = 0
    for end, current in enumerate(times):
        while current - times[start] > window:
            start += 1
        best = max(best, end - start + 1)
    return best


def brute_force_ssh(events: Sequence[EventDict]) -> SigmaMatch | None:
    """10 or more failed SSH logins from one IP within 5 minutes."""
    failures: dict[str, list[datetime]] = defaultdict(list)
    for e in _select(events, "auth.log", "authentication_failure"):
        failures[str(_raw(e, "src_ip"))].append(_ts(e))
    for ip, times in failures.items():
        count = _max_in_window(times, timedelta(minutes=5))
        if count < 10:
            continue
        succeeded = any(
            _raw(e, "src_ip") == ip and _ts(e) >= min(times)
            for e in _select(events, "auth.log", "authentication_success")
        )
        return SigmaMatch(
            rule="brute_force_ssh",
            severity=4 if succeeded else 3,
            summary=(
                f"{len(times)} failed SSH logins from {ip}"
                + ("; a login from the same IP then succeeded." if succeeded else ".")
            ),
            mitre_tactic="Credential Access",
            mitre_technique_id="T1110",
            mitre_technique_name="Brute Force",
            suggested_actions=[
                f"Block {ip} at the firewall.",
                "Reset the password of any account that logged in from this IP.",
                "Disable SSH password authentication in favour of keys.",
            ],
            confidence=0.9,
        )
    return None


def port_scan(events: Sequence[EventDict]) -> SigmaMatch | None:
    """One IP hitting 20 or more distinct ports within 60 seconds."""
    by_ip: dict[str, list[EventDict]] = defaultdict(list)
    for e in _select(events, "firewall", "connection_attempt"):
        by_ip[str(_raw(e, "src_ip"))].append(e)
    window = timedelta(seconds=60)
    for ip, attempts in by_ip.items():
        attempts.sort(key=_ts)
        start = 0
        for end in range(len(attempts)):
            while _ts(attempts[end]) - _ts(attempts[start]) > window:
                start += 1
            ports = {(_raw(a, "dst_ip"), _raw(a, "dst_port")) for a in attempts[start : end + 1]}
            if len(ports) >= 20:
                return SigmaMatch(
                    rule="port_scan",
                    severity=2,
                    summary=f"{ip} probed {len(ports)} distinct ports in under a minute.",
                    mitre_tactic="Discovery",
                    mitre_technique_id="T1046",
                    mitre_technique_name="Network Service Discovery",
                    suggested_actions=[
                        f"Identify the host behind {ip} and check whether the scan is authorized.",
                        "Review which of the probed ports answered.",
                    ],
                    confidence=0.8,
                )
    return None


def phishing(events: Sequence[EventDict]) -> SigmaMatch | None:
    """An email that failed SPF, followed by a click on a link to the same domain."""
    clicks = _select(events, "proxy", "url_click")
    downloads = _select(events, "proxy", "file_download")
    for email in _select(events, "email_gateway", "email_received"):
        domain = _raw(email, "link_domain")
        if _raw(email, "spf") != "fail" or not domain:
            continue
        if not any(_raw(c, "domain") == domain for c in clicks):
            continue
        downloaded = any(_raw(d, "domain") == domain for d in downloads)
        recipient = _raw(email, "recipient", "a user")
        return SigmaMatch(
            rule="phishing",
            severity=4 if downloaded else 3,
            summary=(
                f"{recipient} received an email that failed SPF and clicked its link to {domain}"
                + ("; a file was then downloaded from that domain." if downloaded else ".")
            ),
            mitre_tactic="Initial Access",
            mitre_technique_id="T1566",
            mitre_technique_name="Phishing",
            suggested_actions=[
                f"Block {domain} at the proxy and mail gateway.",
                f"Reset the credentials of {recipient}.",
                "Isolate the workstation if a file was downloaded.",
            ],
            confidence=0.85,
        )
    return None


def lateral_movement(events: Sequence[EventDict]) -> SigmaMatch | None:
    """Network logons from one IP to 3+ hosts in 10 minutes, with admin-share access."""
    by_ip: dict[str, list[EventDict]] = defaultdict(list)
    for e in _select(events, "windows_security", "logon"):
        if _raw(e, "logon_type") == 3:
            by_ip[str(_raw(e, "src_ip"))].append(e)
    window = timedelta(minutes=10)
    for ip, logons in by_ip.items():
        logons.sort(key=_ts)
        start = 0
        for end in range(len(logons)):
            while _ts(logons[end]) - _ts(logons[start]) > window:
                start += 1
            hosts = {_raw(entry, "host") for entry in logons[start : end + 1]}
            if len(hosts) < 3:
                continue
            admin_share = any(
                _raw(s, "src_ip") == ip
                and str(_raw(s, "share", "")).upper().endswith(("C$", "ADMIN$"))
                for s in _select(events, "windows_security", "share_access")
            )
            if not admin_share:
                continue
            return SigmaMatch(
                rule="lateral_movement",
                severity=4,
                summary=(
                    f"{ip} logged on to {len(hosts)} hosts over the network within 10 minutes "
                    "and opened administrative shares."
                ),
                mitre_tactic="Lateral Movement",
                mitre_technique_id="T1021",
                mitre_technique_name="Remote Services",
                suggested_actions=[
                    f"Isolate the host at {ip}.",
                    "Disable the account used and rotate its credentials.",
                    "Inspect the accessed hosts for new services or scheduled tasks.",
                ],
                confidence=0.8,
            )
    return None


def dns_exfiltration(events: Sequence[EventDict]) -> SigmaMatch | None:
    """20 or more DNS queries of 50+ characters to one domain from one host in 5 minutes."""
    long_queries: dict[tuple[str, str], list[datetime]] = defaultdict(list)
    for e in _select(events, "dns", "query"):
        if len(str(_raw(e, "query", ""))) >= 50:
            long_queries[(str(_raw(e, "src_ip")), str(_raw(e, "domain")))].append(_ts(e))
    for (ip, domain), times in long_queries.items():
        if _max_in_window(times, timedelta(minutes=5)) >= 20:
            return SigmaMatch(
                rule="dns_exfiltration",
                severity=4,
                summary=f"{ip} sent {len(times)} unusually long DNS queries to {domain}.",
                mitre_tactic="Exfiltration",
                mitre_technique_id="T1048",
                mitre_technique_name="Exfiltration Over Alternative Protocol",
                suggested_actions=[
                    f"Block DNS resolution of {domain}.",
                    f"Isolate {ip} and identify the process issuing the queries.",
                    "Estimate how much data left from the query volume.",
                ],
                confidence=0.85,
            )
    return None


RULES: list[Callable[[Sequence[EventDict]], SigmaMatch | None]] = [
    brute_force_ssh,
    port_scan,
    phishing,
    lateral_movement,
    dns_exfiltration,
]


def run_sigma_rules(events: Sequence[EventDict]) -> SigmaMatch | None:
    """Return the first rule that matches, or None."""
    for rule in RULES:
        match = rule(events)
        if match is not None:
            return match
    return None
