import json
from pathlib import Path

import pytest

from app.schemas.analysis import AnalysisResult
from app.services.assets import SYNTHETIC_INVENTORY, load_inventory, parse_inventory, routine_owner
from app.services.evidence import settle_stage
from tests.test_evidence import ev

ASSETS = load_inventory(str(SYNTHETIC_INVENTORY))


def said(stage, tactic):
    return AnalysisResult(is_incident=True, attack_stage=stage, mitre_tactic=tactic)


def backup_logons(src_ip="10.0.0.20", src_host="bkp-01", user="svc_backup", share="Backups$"):
    events = []
    for i, host in enumerate(["fs-01", "fs-02", "db-01"]):
        raw = {"src_ip": src_ip, "src_host": src_host, "user": user, "host": host}
        events.append(ev("windows_security", "logon", i * 60, logon_type=3, **raw))
        events.append(
            ev("windows_security", "share_access", i * 60 + 3, share=f"\\\\{host}\\{share}", **raw)
        )
    return events


def ci_failures(user="svc_deploy", src_host="ci-runner-02"):
    return [
        ev(
            "auth.log",
            "authentication_failure",
            i,
            src_ip="10.0.2.15",
            src_host=src_host,
            user=user,
            host="app-01",
        )
        for i in range(15)
    ]


def test_without_an_inventory_the_backup_job_reads_as_lateral_movement():
    result = settle_stage(said("success", "Lateral Movement"), backup_logons())
    assert result.is_incident


@pytest.mark.parametrize("share", ["Backups$", "C$"])
def test_the_backup_server_doing_its_job_is_not_an_incident(share):
    result = settle_stage(said("success", "Lateral Movement"), backup_logons(share=share), ASSETS)
    assert (result.is_incident, result.severity) == (False, 1)
    assert "bkp-01 (backup server)" in result.evidence_note


def test_a_ci_runner_with_an_expired_key_is_not_password_guessing():
    result = settle_stage(said("attempt", "Credential Access"), ci_failures(), ASSETS)
    assert not result.is_incident
    assert "ci-runner-02" in result.evidence_note


def test_the_backup_account_from_a_workstation_is_still_lateral_movement():
    events = backup_logons(src_ip="10.0.3.68", src_host="erika-ws")
    result = settle_stage(said("success", "Lateral Movement"), events, ASSETS)
    assert (result.is_incident, result.attack_stage) == (True, "success")


def test_another_account_from_the_backup_server_is_not_its_routine():
    events = backup_logons(user="adm_helpdesk")
    assert settle_stage(said("success", "Lateral Movement"), events, ASSETS).is_incident


def test_the_backup_ip_under_another_host_name_is_not_the_backup_server():
    events = backup_logons(src_host="evil-laptop")
    assert settle_stage(said("success", "Lateral Movement"), events, ASSETS).is_incident


def test_a_service_installed_from_the_backup_server_is_not_its_routine():
    events = backup_logons() + [
        ev(
            "windows_security",
            "service_install",
            300,
            src_ip="10.0.0.20",
            src_host="bkp-01",
            user="svc_backup",
            host="fs-01",
            service_name="PSEXESVC",
        )
    ]
    result = settle_stage(said("success", "Lateral Movement"), events, ASSETS)
    assert (result.is_incident, result.attack_stage) == (True, "success")


def test_guessing_other_accounts_from_the_ci_runner_is_still_an_attempt():
    result = settle_stage(said("success", "Credential Access"), ci_failures(user="root"), ASSETS)
    assert (result.is_incident, result.attack_stage) == (True, "attempt")


def test_an_attack_beside_routine_work_is_judged_on_the_attack_alone():
    attack = [
        ev("auth.log", "authentication_failure", i, src_ip="192.0.2.77", user="root")
        for i in range(15)
    ]
    events = backup_logons() + attack
    result = settle_stage(said("success", "Lateral Movement"), events, ASSETS)
    # The backup logons no longer prove lateral movement, so the stage falls to the guessing.
    assert (result.is_incident, result.attack_stage) == (True, "attempt")
    assert "bkp-01" in result.evidence_note


def test_the_inventory_is_off_when_no_file_is_set():
    assert load_inventory("") == ()


def test_routine_entries_must_name_source_and_event_type():
    bad = {"assets": [{"name": "x", "ip": "1.2.3.4", "accounts": ["a"], "routine": ["logon"]}]}
    with pytest.raises(ValueError):
        parse_inventory(bad)


def test_an_asset_without_accounts_is_rejected():
    bad = {"assets": [{"name": "x", "ip": "1.2.3.4", "routine": ["auth.log/x"]}]}
    with pytest.raises(ValueError):
        parse_inventory(bad)


def test_an_asset_without_an_ip_is_rejected_by_name():
    bad = {"assets": [{"name": "bkp-01", "accounts": ["a"], "routine": ["auth.log/x"]}]}
    with pytest.raises(ValueError, match="bkp-01"):
        parse_inventory(bad)


def test_the_synthetic_inventory_excuses_no_event_of_any_attack():
    golden = json.loads((Path(__file__).parent / "evals" / "golden_labels.json").read_text())
    attacks = [e for e in golden if e["expected"]["is_incident"]]
    assert attacks
    for entry in attacks:
        assert not [e for e in entry["events"] if routine_owner(e, ASSETS)], entry["id"]
