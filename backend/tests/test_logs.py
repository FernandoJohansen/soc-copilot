import random
from datetime import datetime

from app.schemas.event import EventCreate
from app.services.cef import parse_cef
from app.services.correlation import group_events
from scripts import generate_logs as g


def test_generators_are_deterministic():
    assert g.generate_all(seed=1) == g.generate_all(seed=1)
    assert g.generate_all(seed=1) != g.generate_all(seed=2)


def test_every_scenario_yields_valid_events():
    scenarios = g.generate_all()
    assert set(scenarios) == set(g.SCENARIOS)
    for events in scenarios.values():
        assert events
        for event in events:
            EventCreate(**event)
            assert datetime.fromisoformat(event["timestamp"]).tzinfo is not None


def test_grouping_separates_unrelated_attackers():
    rng = random.Random(3)
    one = g.brute_force_ssh(rng, g.BASE_TIME, attempts=12)
    other = g.dns_exfiltration(rng, g.BASE_TIME, queries=20)
    groups = group_events(one + other, window_minutes=10, min_events=5)
    assert sorted(len(group) for group in groups) == [12, 20]


def test_grouping_links_a_phishing_chain_through_the_user():
    events = g.phishing(random.Random(3), g.BASE_TIME, download=True)
    assert [len(group) for group in group_events(events, window_minutes=30)] == [3]


def test_grouping_splits_on_a_quiet_gap():
    rng = random.Random(3)
    morning = g.typo_logins(rng, g.BASE_TIME)
    user = morning[0]["raw_data"]["user"]
    evening = [e | {"timestamp": e["timestamp"].replace("T09", "T19")} for e in morning]
    assert all(e["raw_data"]["user"] == user for e in evening)
    assert len(group_events(morning + evening, window_minutes=10)) == 2


def test_parse_cef_maps_header_and_extension():
    line = (
        "CEF:0|Acme|Firewall|1.0|100|Connection Attempt|5|"
        "src=10.0.3.21 dst=10.0.1.10 dpt=445 msg=TCP SYN blocked rt=1793610000000"
    )
    event = parse_cef(line)
    assert (event["source"], event["event_type"], event["severity"]) == (
        "firewall",
        "connection_attempt",
        2,
    )
    assert event["raw_data"]["src_ip"] == "10.0.3.21"
    assert event["raw_data"]["dst_port"] == 445
    assert event["raw_data"]["message"] == "TCP SYN blocked"
    assert event["timestamp"].year == 2026
