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
    assert "failed logins" in result.evidence_note


def test_login_after_failures_from_the_same_ip_is_success():
    events = failures() + [ev("auth.log", "authentication_success", 60, src_ip="192.0.2.77")]
    result = settle_stage(said("success", "Credential Access"), events)
    assert (result.attack_stage, result.severity, result.evidence_note) == ("success", 4, None)


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
    assert not settle_stage(said("success", "Exfiltration"), events[:5]).is_incident


def test_non_incidents_and_stageless_results_are_left_alone():
    benign = said("none", None, is_incident=False)
    assert settle_stage(benign, failures()) is benign
    baseline = AnalysisResult(severity=4, mitre_tactic="Credential Access")
    assert settle_stage(baseline, failures()) is baseline


def test_a_few_typos_then_a_login_is_not_an_incident():
    events = failures(ip="10.0.3.34", n=3) + [
        ev("auth.log", "authentication_success", 30, src_ip="10.0.3.34")
    ]
    result = settle_stage(said("success", "Credential Access"), events)
    assert (result.is_incident, result.severity, result.mitre_tactic) == (False, 1, None)
    assert result.evidence_note.startswith("Not an incident")


def test_cdn_hostnames_are_not_a_dns_tunnel():
    events = [
        ev(
            "dns",
            "query",
            i,
            src_ip="10.0.3.68",
            domain="cloudfront.net",
            query=f"{i:x}q.cloudfront.net",
        )
        for i in range(30)
    ]
    assert not settle_stage(said("success", "Exfiltration"), events).is_incident


def test_a_domain_that_only_ends_like_a_cdn_is_still_a_dns_tunnel():
    events = [
        ev("dns", "query", i, src_ip="10.0.3.68", domain="exfilcloudfront.net", query=f"{i:x}q")
        for i in range(30)
    ]
    result = settle_stage(said("success", "Exfiltration"), events)
    assert (result.is_incident, result.attack_stage) == (True, "success")


def test_email_fields_from_raw_json_are_read_leniently():
    def email(**raw):
        return [ev("email_gateway", "email_received", **raw), ev("proxy", "url_click", 60)]

    as_text = email(spf="pass", sender_domain_age_days="4")
    assert settle_stage(said("attempt", "Initial Access"), as_text).severity == 3
    upper = email(spf="FAIL", sender_domain_age_days=3000)
    assert settle_stage(said("attempt", "Initial Access"), upper).is_incident


def test_email_from_an_old_domain_relayed_by_a_list_is_not_phishing():
    def email(**raw):
        return [ev("email_gateway", "email_received", **raw), ev("proxy", "url_click", 60)]

    relayed = email(spf="fail", sender_domain_age_days=3500, via="lists.corp.example")
    assert not settle_stage(said("attempt", "Initial Access"), relayed).is_incident
    young = email(spf="pass", sender_domain_age_days=4)
    assert settle_stage(said("attempt", "Initial Access"), young).severity == 3
    spoofed = email(spf="fail", sender_domain_age_days=3500)
    assert settle_stage(said("attempt", "Initial Access"), spoofed).severity == 3


def test_events_the_checks_cannot_read_keep_the_models_verdict():
    events = [ev("nginx", "access", i, path="/?id=1' OR 1=1--") for i in range(5)]
    result = settle_stage(said("attempt", "Initial Access"), events)
    assert (result.is_incident, result.severity) == (True, 3)
