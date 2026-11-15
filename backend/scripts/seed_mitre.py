"""Seed pgvector with 15 MITRE ATT&CK (Enterprise) techniques and their embeddings.

    python scripts/seed_mitre.py

Safe to re-run: existing rows are updated in place.
"""

import asyncio
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from sqlalchemy import select  # noqa: E402

# (technique_id, name, tactic, description, detection_hints)
TECHNIQUES: list[tuple[str, str, str, str, str]] = [
    (
        "T1110",
        "Brute Force",
        "Credential Access",
        "Adversaries guess passwords to gain access to accounts, by trying many passwords "
        "against one account or one password against many accounts (password spraying).",
        "Many failed logins from one source in auth logs, failures across many usernames, "
        "a success right after a run of failures.",
    ),
    (
        "T1046",
        "Network Service Discovery",
        "Discovery",
        "Adversaries scan for services running on remote hosts and network devices, to find "
        "ones that can be exploited or used to move through the network.",
        "One host connecting to many ports or many hosts in a short time, mostly denied "
        "connections in firewall logs.",
    ),
    (
        "T1566",
        "Phishing",
        "Initial Access",
        "Adversaries send messages with malicious links or attachments to get users to give "
        "up credentials or run code.",
        "Email from a newly registered or look-alike domain, SPF or DKIM failures, a click on "
        "the embedded link, a download of an executable, disk image or macro document.",
    ),
    (
        "T1021",
        "Remote Services",
        "Lateral Movement",
        "Adversaries use valid accounts to log on to remote services such as SMB, RDP or SSH "
        "and move from host to host inside the network.",
        "Network logons (type 3) from one workstation to several servers, access to admin "
        "shares C$ or ADMIN$, remote service installation such as PSEXESVC.",
    ),
    (
        "T1048",
        "Exfiltration Over Alternative Protocol",
        "Exfiltration",
        "Adversaries steal data by sending it over a protocol other than the command and "
        "control channel, such as DNS, FTP or SMTP.",
        "Many long or high-entropy DNS queries to one domain, TXT lookups from a workstation, "
        "outbound volume to an unusual destination.",
    ),
    (
        "T1078",
        "Valid Accounts",
        "Defense Evasion",
        "Adversaries obtain and use credentials of existing accounts to gain access, persist "
        "or escalate privileges while blending in with normal activity.",
        "Logins at unusual hours or from unusual hosts, a service account used interactively "
        "or from a workstation.",
    ),
    (
        "T1059",
        "Command and Scripting Interpreter",
        "Execution",
        "Adversaries abuse command and script interpreters such as PowerShell, cmd or bash to "
        "execute commands and payloads.",
        "Process creation events for interpreters with encoded or download-and-run arguments.",
    ),
    (
        "T1136",
        "Create Account",
        "Persistence",
        "Adversaries create a local, domain or cloud account to keep access to a system.",
        "Account creation events (Windows 4720) outside provisioning, a new account added to "
        "an administrators group.",
    ),
    (
        "T1071",
        "Application Layer Protocol",
        "Command and Control",
        "Adversaries communicate with compromised hosts over common application protocols "
        "such as HTTP, HTTPS or DNS so the traffic blends in.",
        "Regular beaconing to one external host, DNS or HTTP requests at fixed intervals.",
    ),
    (
        "T1190",
        "Exploit Public-Facing Application",
        "Initial Access",
        "Adversaries exploit a weakness in an internet-facing application, such as SQL "
        "injection or path traversal, to gain access.",
        "Web requests with SQL keywords, ../ sequences or shell metacharacters, bursts of "
        "HTTP 500 responses from one client.",
    ),
    (
        "T1204",
        "User Execution",
        "Execution",
        "Adversaries rely on a user opening a malicious file or link to run their code.",
        "A user downloading and opening an executable, disk image or macro document shortly "
        "after receiving an email.",
    ),
    (
        "T1003",
        "OS Credential Dumping",
        "Credential Access",
        "Adversaries dump credentials from operating system memory or files such as LSASS, "
        "the SAM database or NTDS.dit.",
        "Access to the LSASS process, use of procdump, comsvcs.dll or ntdsutil.",
    ),
    (
        "T1041",
        "Exfiltration Over C2 Channel",
        "Exfiltration",
        "Adversaries send stolen data over the same channel they use for command and control.",
        "Large uploads to a host that also receives beaconing traffic.",
    ),
    (
        "T1595",
        "Active Scanning",
        "Reconnaissance",
        "Adversaries probe victim infrastructure from the internet before an attack, to map "
        "IP ranges, open ports and vulnerabilities.",
        "An external address touching many ports or addresses on the perimeter firewall.",
    ),
    (
        "T1486",
        "Data Encrypted for Impact",
        "Impact",
        "Adversaries encrypt data on target systems to interrupt availability, usually to "
        "demand a ransom.",
        "Mass file renames or rewrites, ransom notes, deletion of shadow copies.",
    ),
]


async def seed() -> int:
    from app.core.database import SessionLocal, init_db
    from app.models import MitreTechnique
    from app.services.rag import embed_texts

    await init_db()
    texts = [
        f"{name}. Tactic: {tactic}. {description} Detection: {hints}"
        for _, name, tactic, description, hints in TECHNIQUES
    ]
    vectors = embed_texts(texts)
    async with SessionLocal() as session:
        existing = {t.technique_id: t for t in (await session.scalars(select(MitreTechnique)))}
        for (technique_id, name, tactic, description, hints), vector in zip(
            TECHNIQUES, vectors, strict=True
        ):
            row = existing.get(technique_id) or MitreTechnique(technique_id=technique_id)
            row.name, row.tactic, row.description = name, tactic, description
            row.detection_hints, row.embedding = hints, vector
            session.add(row)
        await session.commit()
    return len(TECHNIQUES)


async def seed_if_empty() -> None:
    from sqlalchemy import func

    from app.core.database import SessionLocal
    from app.models import MitreTechnique

    async with SessionLocal() as session:
        count = await session.scalar(select(func.count(MitreTechnique.id)))
    if not count:
        await seed()


if __name__ == "__main__":
    print(f"seeded {asyncio.run(seed())} MITRE ATT&CK techniques")
