from datetime import UTC, datetime, timedelta

from app.schemas.analysis import AnalysisResult
from app.services.evidence import settle_stage

T0 = datetime(2026, 11, 1, 12, 0, tzinfo=UTC)


def ev(source, event_type, seconds=0, **raw):
    return {
        "source": source,
        "event_type": event_type,
        "timestamp": (T0 + timedelta(seconds=seconds)).isoformat(),
        "raw_data": raw,
    }


def failures(ip="192.0.2.77", n=15):
    return [ev("auth.log", "authentication_failure", i, src_ip=ip, user="root") for i in range(n)]


def said(stage, tactic, is_incident=True):
    return AnalysisResult(is_incident=is_incident, attack_stage=stage, mitre_tactic=tactic)


def test_failed_brute_force_cannot_be_success():
    result = settle_stage(said("success", "Credential Access"), failures())
    assert (result.attack_stage, result.severity) == ("attempt", 3)
    assert "failed logins" in result.stage_note


def test_login_after_failures_from_the_same_ip_is_success():
    events = failures() + [ev("auth.log", "authentication_success", 60, src_ip="192.0.2.77")]
    result = settle_stage(said("success", "Credential Access"), events)
    assert (result.attack_stage, result.severity, result.stage_note) == ("success", 4, None)


def test_a_login_from_another_ip_is_not_evidence_of_success():
    events = failures() + [ev("auth.log", "authentication_success", 60, src_ip="10.0.3.52")]
    assert settle_stage(said("success", "Credential Access"), events).severity == 3


def test_scan_is_capped_at_reconnaissance_whatever_tactic_the_model_picks():
    scan = [
        ev("firewall", "connection_attempt", i, src_ip="203.0.113.9", dst_port=p)
        for i, p in enumerate(range(20, 50))
    ]
    for tactic in ("Discovery", "Lateral Movement", "Credential Access"):
        assert settle_stage(said("success", tactic), scan).severity == 2


def test_discovery_stays_reconnaissance_even_with_success_evidence_present():
    events = [ev("proxy", "file_download", filename="a.exe")]
    assert settle_stage(said("success", "Discovery"), events).attack_stage == "reconnaissance"


def test_phishing_click_without_download_is_attempt():
    events = [
        ev("email_gateway", "email_received", link_domain="evil.example"),
        ev("proxy", "url_click", 30, domain="evil.example"),
    ]
    assert settle_stage(said("success", "Initial Access"), events).severity == 3
    download = [*events, ev("proxy", "file_download", 40, filename="invoice.docm")]
    assert settle_stage(said("success", "Initial Access"), download).severity == 4


def test_lateral_movement_with_evidence_is_raised_to_success():
    events = [
        ev("windows_security", "logon", i, src_ip="10.0.3.71", host=h)
        for i, h in enumerate(("dc-01", "mail-01"))
    ]
    result = settle_stage(said("attempt", "Lateral Movement"), events)
    assert (result.attack_stage, result.severity) == ("success", 4)


def test_dns_tunnel_shape_supports_exfiltration():
    events = [
        ev("dns", "query", i, src_ip="10.0.3.52", domain="t.example", query=f"{i:04x}x.t.example")
        for i in range(25)
    ]
    assert settle_stage(said("attempt", "Exfiltration"), events).severity == 4
    assert settle_stage(said("success", "Exfiltration"), events[:5]).severity == 2


def test_non_incidents_and_stageless_results_are_left_alone():
    benign = said("none", None, is_incident=False)
    assert settle_stage(benign, failures()) is benign
    baseline = AnalysisResult(severity=4, mitre_tactic="Credential Access")
    assert settle_stage(baseline, failures()) is baseline
