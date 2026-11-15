"""Build the golden eval dataset from the log generators.

    python scripts/build_golden.py

Writes backend/tests/evals/golden_labels.json. Three kinds of entry:
  standard  the five scenarios as generated, at volumes the Sigma rules are built for
  evasive   the same attacks, slowed down or reshaped so fixed thresholds miss them
  benign    ordinary activity, some of it shaped to trip the Sigma rules
The last copy of every variant with three or more copies goes to the held-out `test` split.
"""

import json
import random
import sys
from collections.abc import Callable
from datetime import timedelta
from pathlib import Path
from typing import Any

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from scripts import generate_logs as g  # noqa: E402

OUTPUT = Path(__file__).resolve().parents[1] / "tests" / "evals" / "golden_labels.json"

CREDENTIAL = ("Credential Access", "T1110")
DISCOVERY = ("Discovery", "T1046")
PHISHING = ("Initial Access", "T1566")
LATERAL = ("Lateral Movement", "T1021")
EXFIL = ("Exfiltration", "T1048")

Generator = Callable[[random.Random, Any], list[dict[str, Any]]]

# (scenario, variant, kind, copies, severity, (tactic, technique) or None, generator, note)
SPEC: list[tuple[str, str, str, int, int, tuple[str, str] | None, Generator, str]] = [
    (
        "brute_force_ssh",
        "burst",
        "standard",
        3,
        3,
        CREDENTIAL,
        lambda r, t: g.brute_force_ssh(r, t, attempts=r.randint(15, 40)),
        "Fast password guessing from one external IP, no successful login.",
    ),
    (
        "brute_force_ssh",
        "burst_then_success",
        "standard",
        2,
        4,
        CREDENTIAL,
        lambda r, t: g.brute_force_ssh(r, t, attempts=r.randint(15, 30), success=True),
        "Password guessing that ends in a successful login from the attacking IP.",
    ),
    (
        "port_scan",
        "vertical",
        "standard",
        3,
        2,
        DISCOVERY,
        lambda r, t: g.port_scan(r, t, ports=r.randint(25, 60)),
        "Many ports on one server probed in seconds.",
    ),
    (
        "port_scan",
        "smb_sweep",
        "standard",
        2,
        2,
        DISCOVERY,
        lambda r, t: g.port_scan(r, t, ports=r.randint(22, 30), sweep=True),
        "Port 445 probed across the server subnet.",
    ),
    (
        "phishing",
        "click",
        "standard",
        3,
        3,
        PHISHING,
        lambda r, t: g.phishing(r, t),
        "Look-alike domain, SPF fail, the user clicked; nothing downloaded.",
    ),
    (
        "phishing",
        "click_and_download",
        "standard",
        2,
        4,
        PHISHING,
        lambda r, t: g.phishing(r, t, download=True),
        "The user clicked and downloaded an executable or macro document.",
    ),
    (
        "lateral_movement",
        "admin_shares",
        "standard",
        4,
        4,
        LATERAL,
        lambda r, t: g.lateral_movement(r, t, hosts=r.randint(3, 5)),
        "A workstation uses a service account on several servers and opens admin shares.",
    ),
    (
        "dns_exfiltration",
        "fast_tunnel",
        "standard",
        5,
        4,
        EXFIL,
        lambda r, t: g.dns_exfiltration(r, t, queries=r.randint(30, 70)),
        "Dozens of long encoded TXT queries to one domain within minutes.",
    ),
    # -- evasive: same attacks, below the fixed thresholds
    (
        "brute_force_ssh",
        "low_and_slow",
        "evasive",
        3,
        3,
        CREDENTIAL,
        lambda r, t: g.brute_force_ssh(r, t, attempts=r.randint(12, 20), spacing=(45, 90)),
        "Under 10 failures in any 5 minutes, but a steady stream from one external IP.",
    ),
    (
        "brute_force_ssh",
        "password_spray",
        "evasive",
        3,
        3,
        CREDENTIAL,
        lambda r, t: g.brute_force_ssh(r, t, attempts=12, spacing=(50, 90), spray=True),
        "One attempt per account across twelve accounts from one external IP.",
    ),
    (
        "port_scan",
        "slow_scan",
        "evasive",
        3,
        2,
        DISCOVERY,
        lambda r, t: g.port_scan(r, t, ports=r.randint(35, 50), duration_s=1800),
        "Dozens of ports on one server probed over half an hour.",
    ),
    (
        "phishing",
        "spf_pass_download",
        "evasive",
        3,
        4,
        PHISHING,
        lambda r, t: g.phishing(r, t, download=True, spf="pass"),
        "The look-alike domain publishes valid SPF; the user clicked and downloaded a file.",
    ),
    (
        "lateral_movement",
        "two_hosts_psexec",
        "evasive",
        3,
        4,
        LATERAL,
        lambda r, t: g.lateral_movement(r, t, hosts=2, service_install=True),
        "Only two hosts, but a remote-execution service is installed on each.",
    ),
    (
        "dns_exfiltration",
        "slow_tunnel",
        "evasive",
        2,
        4,
        EXFIL,
        lambda r, t: g.dns_exfiltration(r, t, queries=r.randint(28, 36), spacing=(25, 40)),
        "Long encoded queries at about two per minute.",
    ),
    (
        "dns_exfiltration",
        "short_labels",
        "evasive",
        2,
        4,
        EXFIL,
        lambda r, t: g.dns_exfiltration(r, t, queries=r.randint(40, 60), label_len=18),
        "Encoded queries kept under 50 characters.",
    ),
    # -- benign
    (
        "benign",
        "password_typos",
        "benign",
        4,
        1,
        None,
        lambda r, t: g.typo_logins(r, t),
        "A few failures, then a login, from the user's own workstation.",
    ),
    (
        "benign",
        "stale_ci_credential",
        "benign",
        3,
        1,
        None,
        lambda r, t: g.stale_service_credential(r, t),
        "A CI runner retrying with an expired key every 30 seconds. Trips the brute-force rule.",
    ),
    (
        "benign",
        "monitoring_poll",
        "benign",
        3,
        1,
        None,
        lambda r, t: g.monitoring_poll(r, t),
        "The monitoring server's allowed health checks. Trips the port-scan rule.",
    ),
    (
        "benign",
        "newsletter",
        "benign",
        2,
        1,
        None,
        lambda r, t: g.newsletter(r, t),
        "A long-established sender, SPF pass, a click to a business site.",
    ),
    (
        "benign",
        "forwarded_newsletter",
        "benign",
        2,
        1,
        None,
        lambda r, t: g.newsletter(r, t, forwarded=True),
        "The same newsletter relayed by an internal list, so SPF fails. Trips the phishing rule.",
    ),
    (
        "benign",
        "backup_job",
        "benign",
        2,
        1,
        None,
        lambda r, t: g.backup_job(r, t),
        "The backup server reading backup shares at 02:00.",
    ),
    (
        "benign",
        "backup_job_admin_share",
        "benign",
        2,
        1,
        None,
        lambda r, t: g.backup_job(r, t, admin_share=True),
        "The backup server reading C$ at 02:00. Trips the lateral-movement rule.",
    ),
    (
        "benign",
        "cdn_hostnames",
        "benign",
        3,
        1,
        None,
        lambda r, t: g.cdn_dns(r, t),
        "A browser resolving long CDN hostnames. Trips the DNS-exfiltration rule.",
    ),
    (
        "benign",
        "ordinary_activity",
        "benign",
        3,
        1,
        None,
        lambda r, t: g.background_noise(r, t, count=r.randint(10, 20)),
        "Logins, browsing and lookups with nothing unusual.",
    ),
]


def build(seed: int = 2026) -> list[dict[str, Any]]:
    rng = random.Random(seed)
    entries = []
    for scenario, variant, kind, copies, severity, mitre, generator, note in SPEC:
        for copy in range(copies):
            start = g.BASE_TIME + timedelta(days=len(entries), minutes=rng.randint(0, 480))
            events = generator(rng, start)
            if kind != "benign" and rng.random() < 0.5:
                # Unrelated ordinary activity from the same period, as in a real log pull.
                events = events + g.background_noise(rng, start, count=rng.randint(4, 10))
            entries.append(
                {
                    "id": f"{scenario}-{variant}-{copy + 1}",
                    "scenario": scenario,
                    "variant": variant,
                    "kind": kind,
                    # The last copy of each variant is held out and never used to tune the prompt.
                    "split": "test" if copies >= 3 and copy == copies - 1 else "dev",
                    "note": note,
                    "expected": {
                        "is_incident": mitre is not None,
                        "severity": severity,
                        "mitre_tactic": mitre[0] if mitre else None,
                        "mitre_technique": mitre[1] if mitre else None,
                    },
                    "events": sorted(events, key=lambda e: e["timestamp"]),
                }
            )
    return entries


def main() -> None:
    entries = build()
    OUTPUT.write_text(json.dumps(entries, indent=1) + "\n")
    by_kind: dict[str, int] = {}
    for entry in entries:
        by_kind[entry["kind"]] = by_kind.get(entry["kind"], 0) + 1
    held_out = sum(e["split"] == "test" for e in entries)
    print(f"wrote {len(entries)} entries to {OUTPUT} ({by_kind}; {held_out} held out)")


if __name__ == "__main__":
    main()
