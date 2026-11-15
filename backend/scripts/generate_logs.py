"""Synthetic security logs for the five MVP scenarios, plus benign look-alikes.

Every generator takes a seeded `random.Random` and a start time and returns a list of
event dicts ({source, event_type, timestamp, raw_data}), so the same seed always yields
the same logs. The golden eval dataset is built from these functions.

Run it to load one example of each scenario into the database:

    python scripts/generate_logs.py            # insert into Postgres
    python scripts/generate_logs.py --out logs.json --no-db
"""

import argparse
import asyncio
import base64
import json
import random
import sys
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

EventDict = dict[str, Any]
BASE_TIME = datetime(2026, 11, 2, 9, 0, tzinfo=UTC)

EXTERNAL_IPS = ["203.0.113.57", "198.51.100.23", "203.0.113.140", "198.51.100.201", "192.0.2.77"]
WORKSTATIONS = {
    "alice": "10.0.3.21",
    "bruno": "10.0.3.34",
    "carla": "10.0.3.45",
    "diego": "10.0.3.52",
    "erika": "10.0.3.68",
    "fabio": "10.0.3.71",
}
SERVERS = ["web-01", "web-02", "db-01", "app-01", "fs-01", "fs-02", "dc-01", "mail-01"]
SERVER_IPS = {name: f"10.0.1.{10 + i}" for i, name in enumerate(SERVERS)}


def _event(ts: datetime, source: str, event_type: str, **raw: Any) -> EventDict:
    return {
        "source": source,
        "event_type": event_type,
        "timestamp": ts.isoformat(),
        "raw_data": raw,
    }


def _sorted(events: list[EventDict]) -> list[EventDict]:
    return sorted(events, key=lambda e: e["timestamp"])


# --------------------------------------------------------------------------- attacks


def brute_force_ssh(
    rng: random.Random,
    start: datetime,
    *,
    attempts: int = 15,
    spacing: tuple[float, float] = (2, 6),
    success: bool = False,
    spray: bool = False,
) -> list[EventDict]:
    """Failed SSH logins from one external IP. `spray` tries many users once each."""
    ip, host = rng.choice(EXTERNAL_IPS), rng.choice(["web-01", "web-02", "app-01"])
    users = (
        list(WORKSTATIONS) + ["admin", "root", "deploy", "backup", "test", "oracle"]
        if spray
        else ["root", "admin", "ubuntu"]
    )
    events, ts, user = [], start, users[0]
    for i in range(attempts):
        user = users[i % len(users)] if spray else rng.choice(users)
        ts += timedelta(seconds=rng.uniform(*spacing))
        port = rng.randint(30000, 65000)
        events.append(
            _event(
                ts,
                "auth.log",
                "authentication_failure",
                host=host,
                user=user,
                src_ip=ip,
                service="sshd",
                message=f"Failed password for {user} from {ip} port {port} ssh2",
            )
        )
    if success:
        ts += timedelta(seconds=rng.uniform(*spacing))
        events.append(
            _event(
                ts,
                "auth.log",
                "authentication_success",
                host=host,
                user=user,
                src_ip=ip,
                service="sshd",
                message=f"Accepted password for {user} from {ip} port 51022 ssh2",
            )
        )
    return events


def port_scan(
    rng: random.Random,
    start: datetime,
    *,
    ports: int = 30,
    duration_s: float = 20,
    sweep: bool = False,
) -> list[EventDict]:
    """An internal host probing many ports on one target (or one port on many hosts)."""
    user = rng.choice(list(WORKSTATIONS))
    src, target = WORKSTATIONS[user], rng.choice(list(SERVER_IPS.values()))
    chosen = rng.sample(range(1, 10000), ports)
    events = []
    for i, port in enumerate(chosen):
        ts = start + timedelta(seconds=duration_s * i / ports + rng.uniform(0, 0.3))
        dst_ip, dst_port = (f"10.0.1.{10 + i}", 445) if sweep else (target, port)
        events.append(
            _event(
                ts,
                "firewall",
                "connection_attempt",
                src_ip=src,
                dst_ip=dst_ip,
                dst_port=dst_port,
                protocol="tcp",
                action="allow" if dst_port in (22, 80, 443, 445) else "deny",
                message=f"TCP SYN {src} -> {dst_ip}:{dst_port}",
            )
        )
    return events


def phishing(
    rng: random.Random, start: datetime, *, download: bool = False, spf: str = "fail"
) -> list[EventDict]:
    """A credential-themed email from a look-alike domain, a click, optionally a download."""
    user = rng.choice(list(WORKSTATIONS))
    domain = rng.choice(
        [
            "micros0ft-login.com",
            "secure-payroll-update.net",
            "docs-sharepoint-auth.com",
            "corp-vpn-renewal.info",
        ]
    )
    url = f"http://{domain}/verify?id={rng.randint(10000, 99999)}"
    subject = rng.choice(
        [
            "Action required: your password expires today",
            "Payroll update - confirm your details",
            "Shared document: Q4 bonuses.xlsx",
        ]
    )
    events = [
        _event(
            start,
            "email_gateway",
            "email_received",
            user=user,
            recipient=f"{user}@corp.example",
            sender=f"it-support@{domain}",
            subject=subject,
            link_url=url,
            link_domain=domain,
            spf=spf,
            sender_domain_age_days=rng.randint(1, 9),
            message=f"Email from it-support@{domain} to {user}: {subject}",
        )
    ]
    click = start + timedelta(minutes=rng.uniform(2, 20))
    events.append(
        _event(
            click,
            "proxy",
            "url_click",
            user=user,
            src_ip=WORKSTATIONS[user],
            url=url,
            domain=domain,
            category="newly_registered_domain",
            message=f"{user} opened {url}",
        )
    )
    if download:
        filename = rng.choice(["invoice_8841.iso", "Q4_bonuses.docm", "vpn_update.exe"])
        events.append(
            _event(
                click + timedelta(seconds=rng.uniform(15, 90)),
                "proxy",
                "file_download",
                user=user,
                src_ip=WORKSTATIONS[user],
                url=f"http://{domain}/files/{filename}",
                domain=domain,
                filename=filename,
                message=f"{user} downloaded {filename} from {domain}",
            )
        )
    return events


def lateral_movement(
    rng: random.Random, start: datetime, *, hosts: int = 4, service_install: bool = False
) -> list[EventDict]:
    """A workstation using a service account to log on to servers and open admin shares."""
    user = rng.choice(list(WORKSTATIONS))
    src, account = WORKSTATIONS[user], rng.choice(["svc_backup", "svc_sql", "adm_helpdesk"])
    targets = rng.sample(["fs-01", "fs-02", "dc-01", "db-01", "app-01", "mail-01"], hosts)
    events, ts = [], start
    for host in targets:
        ts += timedelta(seconds=rng.uniform(20, 90))
        events.append(
            _event(
                ts,
                "windows_security",
                "logon",
                event_id=4624,
                user=account,
                src_ip=src,
                src_host=f"{user}-ws",
                host=host,
                logon_type=3,
                message=f"Network logon by {account} from {src} on {host}",
            )
        )
        ts += timedelta(seconds=rng.uniform(2, 10))
        share = rng.choice(["C$", "ADMIN$"])
        events.append(
            _event(
                ts,
                "windows_security",
                "share_access",
                event_id=5140,
                user=account,
                src_ip=src,
                host=host,
                share=f"\\\\{host}\\{share}",
                message=f"{account} accessed \\\\{host}\\{share} from {src}",
            )
        )
        if service_install:
            ts += timedelta(seconds=rng.uniform(1, 5))
            events.append(
                _event(
                    ts,
                    "windows_security",
                    "service_install",
                    event_id=7045,
                    user=account,
                    src_ip=src,
                    host=host,
                    service_name="PSEXESVC",
                    message=f"Service PSEXESVC installed on {host} by {account}",
                )
            )
    return events


def dns_exfiltration(
    rng: random.Random,
    start: datetime,
    *,
    queries: int = 40,
    spacing: tuple[float, float] = (1, 4),
    label_len: int = 56,
) -> list[EventDict]:
    """One host sending long encoded DNS queries to a single domain."""
    user = rng.choice(list(WORKSTATIONS))
    src = WORKSTATIONS[user]
    domain = rng.choice(["cdn-metrics-sync.net", "telemetry-upd8.com", "static-assets-cache.org"])
    events, ts = [], start
    for i in range(queries):
        ts += timedelta(seconds=rng.uniform(*spacing))
        chunk = base64.b32encode(rng.randbytes(label_len)).decode().rstrip("=").lower()[:label_len]
        query = f"{chunk}.{i:04d}.{domain}"
        events.append(
            _event(
                ts,
                "dns",
                "query",
                src_ip=src,
                query=query,
                domain=domain,
                qtype="TXT",
                message=f"{src} queried TXT {query}",
            )
        )
    return events


# ---------------------------------------------------------------------------- benign


def typo_logins(rng: random.Random, start: datetime) -> list[EventDict]:
    """A user mistypes a password a few times, then logs in from their usual workstation."""
    user = rng.choice(list(WORKSTATIONS))
    ip, events, ts = WORKSTATIONS[user], [], start
    for _ in range(rng.randint(2, 4)):
        ts += timedelta(seconds=rng.uniform(4, 12))
        events.append(
            _event(
                ts,
                "auth.log",
                "authentication_failure",
                host="app-01",
                user=user,
                src_ip=ip,
                service="sshd",
                message=f"Failed password for {user} from {ip} port 50211 ssh2",
            )
        )
    events.append(
        _event(
            ts + timedelta(seconds=9),
            "auth.log",
            "authentication_success",
            host="app-01",
            user=user,
            src_ip=ip,
            service="sshd",
            message=f"Accepted password for {user} from {ip} port 50211 ssh2",
        )
    )
    return events


def stale_service_credential(rng: random.Random, start: datetime) -> list[EventDict]:
    """A CI runner retrying a deploy with an expired key, on a fixed 30-second timer."""
    attempts, ip = rng.randint(12, 18), "10.0.2.15"
    return [
        _event(
            start + timedelta(seconds=30 * i),
            "auth.log",
            "authentication_failure",
            host="app-01",
            user="svc_deploy",
            src_ip=ip,
            src_host="ci-runner-02",
            service="sshd",
            message=f"Failed publickey for svc_deploy from {ip} port 44120 ssh2",
        )
        for i in range(attempts)
    ]


def monitoring_poll(rng: random.Random, start: datetime) -> list[EventDict]:
    """The monitoring server checking the same service ports on every server."""
    events = []
    for i, (host, ip) in enumerate(rng.sample(list(SERVER_IPS.items()), 6)):
        for j, port in enumerate([22, 80, 443, 5432, 9100]):
            ts = start + timedelta(seconds=i * 1.5 + j * 0.2)
            events.append(
                _event(
                    ts,
                    "firewall",
                    "connection_attempt",
                    src_ip="10.0.0.5",
                    src_host="mon-01",
                    dst_ip=ip,
                    dst_host=host,
                    dst_port=port,
                    protocol="tcp",
                    action="allow",
                    rule="monitoring-checks",
                    message=f"TCP SYN 10.0.0.5 (mon-01) -> {ip}:{port} allowed "
                    "by rule monitoring-checks",
                )
            )
    return events


def newsletter(rng: random.Random, start: datetime, *, forwarded: bool = False) -> list[EventDict]:
    """A known sender's newsletter and a click. `forwarded` fails SPF via a mailing list."""
    user = rng.choice(list(WORKSTATIONS))
    domain = rng.choice(["partner-logistics.com", "industry-weekly.org"])
    url = f"https://{domain}/news/2026/11/edition"
    return [
        _event(
            start,
            "email_gateway",
            "email_received",
            user=user,
            recipient=f"{user}@corp.example",
            sender=f"newsletter@{domain}",
            subject="Weekly digest",
            link_url=url,
            link_domain=domain,
            spf="fail" if forwarded else "pass",
            sender_domain_age_days=rng.randint(2500, 6000),
            via="lists.corp.example" if forwarded else None,
            message=f"Email from newsletter@{domain} to {user}: Weekly digest",
        ),
        _event(
            start + timedelta(minutes=rng.uniform(5, 60)),
            "proxy",
            "url_click",
            user=user,
            src_ip=WORKSTATIONS[user],
            url=url,
            domain=domain,
            category="business",
            message=f"{user} opened {url}",
        ),
    ]


def backup_job(
    rng: random.Random, start: datetime, *, admin_share: bool = False
) -> list[EventDict]:
    """The nightly backup: the backup server logging on to the file servers at 02:00."""
    night = start.replace(hour=2, minute=0, second=0)
    events, ts = [], night
    for host in ["fs-01", "fs-02", "db-01", "app-01", "mail-01"]:
        ts += timedelta(seconds=rng.uniform(40, 120))
        share = "C$" if admin_share else "Backups$"
        events.append(
            _event(
                ts,
                "windows_security",
                "logon",
                event_id=4624,
                user="svc_backup",
                src_ip="10.0.0.20",
                src_host="bkp-01",
                host=host,
                logon_type=3,
                message=f"Network logon by svc_backup from 10.0.0.20 (bkp-01) on {host}",
            )
        )
        events.append(
            _event(
                ts + timedelta(seconds=3),
                "windows_security",
                "share_access",
                event_id=5140,
                user="svc_backup",
                src_ip="10.0.0.20",
                src_host="bkp-01",
                host=host,
                share=f"\\\\{host}\\{share}",
                message=f"svc_backup accessed \\\\{host}\\{share} from 10.0.0.20 (bkp-01)",
            )
        )
    return events


def cdn_dns(rng: random.Random, start: datetime) -> list[EventDict]:
    """A browser resolving long, generated CDN hostnames while loading a page."""
    user = rng.choice(list(WORKSTATIONS))
    src, events, ts = WORKSTATIONS[user], [], start
    for _ in range(rng.randint(22, 30)):
        ts += timedelta(seconds=rng.uniform(0.2, 3))
        edge = "".join(rng.choices("abcdefghijklmnopqrstuvwxyz0123456789", k=14))
        query = f"{edge}.video-edge-{rng.randint(1, 9)}.prod.eu-west-1.cloudfront.net"
        events.append(
            _event(
                ts,
                "dns",
                "query",
                src_ip=src,
                query=query,
                domain="cloudfront.net",
                qtype="A",
                message=f"{src} queried A {query}",
            )
        )
    return events


def background_noise(rng: random.Random, start: datetime, count: int = 12) -> list[EventDict]:
    """Ordinary activity: successful logins, web browsing, DNS lookups, allowed traffic."""
    sites = ["github.com", "docs.python.org", "mail.corp.example", "wiki.corp.example"]
    events = []
    for _ in range(count):
        user = rng.choice(list(WORKSTATIONS))
        ip, ts = WORKSTATIONS[user], start + timedelta(seconds=rng.uniform(0, 900))
        kind, site = rng.randrange(4), rng.choice(sites)
        if kind == 0:
            events.append(
                _event(
                    ts,
                    "auth.log",
                    "authentication_success",
                    host="app-01",
                    user=user,
                    src_ip=ip,
                    service="sshd",
                    message=f"Accepted publickey for {user} from {ip} port 50022 ssh2",
                )
            )
        elif kind == 1:
            events.append(
                _event(
                    ts,
                    "proxy",
                    "url_click",
                    user=user,
                    src_ip=ip,
                    url=f"https://{site}/",
                    domain=site,
                    category="business",
                    message=f"{user} opened https://{site}/",
                )
            )
        elif kind == 2:
            events.append(
                _event(
                    ts,
                    "dns",
                    "query",
                    src_ip=ip,
                    query=site,
                    domain=site,
                    qtype="A",
                    message=f"{ip} queried A {site}",
                )
            )
        else:
            events.append(
                _event(
                    ts,
                    "firewall",
                    "connection_attempt",
                    src_ip=ip,
                    dst_ip=SERVER_IPS["web-01"],
                    dst_port=443,
                    protocol="tcp",
                    action="allow",
                    message=f"TCP SYN {ip} -> web-01:443",
                )
            )
    return _sorted(events)


SCENARIOS = {
    "brute_force_ssh": brute_force_ssh,
    "port_scan": port_scan,
    "phishing": phishing,
    "lateral_movement": lateral_movement,
    "dns_exfiltration": dns_exfiltration,
}


def generate_all(seed: int = 42) -> dict[str, list[EventDict]]:
    """One example of each of the five scenarios."""
    rng = random.Random(seed)
    return {
        name: _sorted(scenario(rng, BASE_TIME + timedelta(hours=i)))
        for i, (name, scenario) in enumerate(SCENARIOS.items())
    }


async def _insert(scenarios: dict[str, list[EventDict]]) -> None:
    from app.core.database import SessionLocal, init_db
    from app.models import Event

    await init_db()
    async with SessionLocal() as session:
        for name, events in scenarios.items():
            rows = [
                Event(
                    source=e["source"],
                    event_type=e["event_type"],
                    raw_data=e["raw_data"],
                    timestamp=datetime.fromisoformat(e["timestamp"]),
                )
                for e in events
            ]
            session.add_all(rows)
            await session.commit()
            ids = [row.id for row in rows]
            print(f"{name}: {len(ids)} events, ids {ids[0]}-{ids[-1]}")


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--seed", type=int, default=42)
    parser.add_argument("--out", type=Path, help="also write the events to this JSON file")
    parser.add_argument("--no-db", action="store_true", help="do not insert into Postgres")
    args = parser.parse_args()

    scenarios = generate_all(args.seed)
    if args.out:
        args.out.write_text(json.dumps(scenarios, indent=2))
        print(f"wrote {args.out}")
    if not args.no_db:
        asyncio.run(_insert(scenarios))


if __name__ == "__main__":
    main()
