"""The severity policy shared by the Sigma baseline, the LLM prompt and the eval labels."""

SEVERITY_LABELS = {1: "low", 2: "medium", 3: "high", 4: "critical"}

SEVERITY_POLICY = """\
1 (low): benign or informational activity; no action needed beyond a note.
2 (medium): reconnaissance or probing with no sign that anything was accessed.
3 (high): an active attack attempt against accounts or users with no evidence it succeeded.
4 (critical): evidence of success: an attacker authenticated, malware was downloaded or run, \
an attacker is moving between internal hosts, or data is leaving the network."""
