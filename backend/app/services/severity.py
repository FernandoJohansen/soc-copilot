"""The severity policy shared by the Sigma baseline, the LLM prompt and the eval labels."""

SEVERITY_LABELS = {1: "low", 2: "medium", 3: "high", 4: "critical"}

SEVERITY_POLICY = """\
1 (low): benign or informational activity; no action needed beyond a note.
2 (medium): reconnaissance or probing with no sign that anything was accessed.
3 (high): an active attack attempt against accounts or users with no evidence it succeeded.
4 (critical): evidence of success: an attacker authenticated, malware was downloaded or run, \
an attacker is moving between internal hosts, or data is leaving the network."""

# The LLM does not pick the number. It names the attack stage the events show, and the
# severity follows from the policy above. Models identify what happened far better than
# they map it onto a scale: a 7B model given the scale directly rated most incidents one
# level low and never used 4.
STAGE_SEVERITY = {"none": 1, "reconnaissance": 2, "attempt": 3, "success": 4}

STAGE_POLICY = """\
- "none": not an incident; the activity has an ordinary explanation.
- "reconnaissance": the attacker is mapping the environment (port or host scans, service \
probing, enumeration) and nothing shows that anything was accessed.
- "attempt": an active attack on accounts or users that has not succeeded: password \
guessing or spraying with no successful login, a phishing email delivered or its link \
clicked with nothing downloaded.
- "success": the events show the attack worked or the attacker is already inside: a \
successful login from the source that was guessing passwords, a file (an executable or a \
macro document) downloaded through a phishing link, an internal host authenticating to \
other internal hosts or opening their admin shares, data leaving through an unusual \
channel such as encoded DNS queries. Lateral movement and exfiltration are always \
"success": the attacker is already inside."""


def severity_for_stage(stage: str | None) -> int | None:
    """The policy severity for an attack stage, or None if the stage is not recognized."""
    return STAGE_SEVERITY.get((stage or "").strip().lower())
