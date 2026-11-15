import random

import pytest

from app.services.sigma_rules import run_sigma_rules
from scripts import generate_logs as g


@pytest.fixture
def rng():
    return random.Random(7)


def test_brute_force_matches(rng):
    match = run_sigma_rules(g.brute_force_ssh(rng, g.BASE_TIME, attempts=15))
    assert (match.rule, match.severity, match.mitre_technique_id) == ("brute_force_ssh", 3, "T1110")


def test_brute_force_with_success_is_critical(rng):
    match = run_sigma_rules(g.brute_force_ssh(rng, g.BASE_TIME, attempts=15, success=True))
    assert match.severity == 4


def test_slow_brute_force_stays_under_the_threshold(rng):
    events = g.brute_force_ssh(rng, g.BASE_TIME, attempts=15, spacing=(45, 90))
    assert run_sigma_rules(events) is None


def test_port_scan_matches(rng):
    match = run_sigma_rules(g.port_scan(rng, g.BASE_TIME, ports=30))
    assert (match.rule, match.mitre_tactic) == ("port_scan", "Discovery")


def test_phishing_severity_depends_on_download(rng):
    assert run_sigma_rules(g.phishing(rng, g.BASE_TIME)).severity == 3
    assert run_sigma_rules(g.phishing(rng, g.BASE_TIME, download=True)).severity == 4


def test_phishing_needs_spf_failure(rng):
    assert run_sigma_rules(g.phishing(rng, g.BASE_TIME, spf="pass")) is None


def test_lateral_movement_matches(rng):
    match = run_sigma_rules(g.lateral_movement(rng, g.BASE_TIME, hosts=4))
    assert (match.rule, match.mitre_technique_id) == ("lateral_movement", "T1021")


def test_dns_exfiltration_matches(rng):
    match = run_sigma_rules(g.dns_exfiltration(rng, g.BASE_TIME, queries=40))
    assert (match.rule, match.mitre_tactic) == ("dns_exfiltration", "Exfiltration")


def test_ordinary_activity_matches_nothing(rng):
    assert run_sigma_rules(g.background_noise(rng, g.BASE_TIME, count=40)) is None
    assert run_sigma_rules(g.typo_logins(rng, g.BASE_TIME)) is None
    assert run_sigma_rules([]) is None
