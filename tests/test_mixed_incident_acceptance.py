"""Verify the local Snort and Sysmon investigation path with benign fixtures."""

import json
import time

import pytest

from tests.conftest import snort, windows


@pytest.fixture
def benign_pair():
    network = snort("fixture-snort", level=7, src="10.44.1.10", dst="192.168.44.10")
    network["timestamp"] = "2026-01-10T10:12:20.201+00:00"
    network["data"].update(msg="Authorized lab connectivity check", proto="ICMP")
    host = windows("fixture-sysmon", level=7)
    host["timestamp"] = "2026-01-10T10:12:20.355+00:00"
    host["agent"] = {"ip": "10.44.0.10", "name": "fixture-host"}
    host["data"]["win"] = {
        "system": {"eventID": "1", "providerName": "Microsoft-Windows-Sysmon"},
        "eventdata": {"image": r"C:\Windows\System32\ping.exe"},
    }
    return network, host


def test_benign_snort_and_sysmon_share_incident_with_original_times_and_citations(
    console, settings, benign_pair
):
    service = console.app.state.service
    settings.host_ips = {"10.44.0.10": "192.168.44.10"}
    network, host = benign_pair
    headers = {"Authorization": "Bearer " + settings.ingest_key}
    for alert in (network, host):
        assert console.post("/ingest", headers=headers, json=alert).status_code == 202
    service.tick(time.time() + settings.quiet + 1)
    (case,) = service.store.cases()
    run = service.store.get_run(case["latest_run_id"])
    assert run["status"] == "completed"
    rows = {row["kind"]: row for row in run["evidence"]["alerts"]}
    assert rows["net"]["dst_ip"] == rows["host"]["host_ip"] == "192.168.44.10"
    assert rows["net"]["timestamp"] == network["timestamp"] and rows["host"]["timestamp"] == host["timestamp"]
    with service.store.connect() as db:
        cited = {
            row["agent"]: set(json.loads(row["evidence"]))
            for row in db.execute(
                "SELECT agent,evidence FROM ledger WHERE run_id=? AND agent IN ('net','host','judge')",
                (run["id"],),
            )
        }
    assert cited == {"net": {network["id"]}, "host": {host["id"]}, "judge": {network["id"], host["id"]}}
    assert set(run["verdict"]["evidence_ids"]) == cited["judge"]
    assert run["verdict"]["verdict"] == "review" and run["verdict"]["block_ip"] is None
    detail = console.get("/api/v1/incidents/" + case["id"]).json()
    assert not detail["can_approve"] and detail["actions"] == []


@pytest.mark.parametrize("separation", ["other_host", "past_gap"])
def test_mixed_alerts_outside_host_or_received_time_scope_stay_separate(
    console, settings, benign_pair, separation
):
    service = console.app.state.service
    settings.host_ips = {"10.44.0.10": "192.168.44.10", "10.44.0.11": "192.168.44.11"}
    network, host = benign_pair
    if separation == "other_host":
        host["agent"] = {"ip": "10.44.0.11", "name": "other-fixture-host"}
        # A sensor management address must not connect unrelated endpoint evidence.
        network["agent"] = {"ip": host["agent"]["ip"]}
    start = time.time()
    delay = settings.gap + 1 if separation == "past_gap" else 1
    assert service.store.ingest(network, received=start, host_ips=settings.host_ips)
    assert service.store.ingest(host, received=start + delay, host_ips=settings.host_ips)
    service.tick(start + delay + settings.quiet + 1)

    cases = service.store.cases()
    assert {tuple(case["incident"]["raw_ids"]) for case in cases} == {(network["id"],), (host["id"],)}
    for case in cases:
        run = service.store.get_run(case["latest_run_id"])
        assert run["status"] == "completed"
        assert run["verdict"]["evidence_ids"] == case["incident"]["raw_ids"]
        assert run["verdict"]["verdict"] == "review" and run["verdict"]["block_ip"] is None
