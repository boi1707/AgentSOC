import json
from dataclasses import replace

import httpx
import pytest
from pydantic import ValidationError

from src.adapters.wazuh import EVENT_FIELDS, SYSTEM_FIELDS, normalize
from src.incident import Grouper
from src.service import Service
from src.storage import Store
from tests.conftest import snort

GUID = "{395b0161-db92-6b07-3d05-000000000800}"
HASH = "ab" * 32


def sysmon(event_id=11, aid="sysmon-file-1", **event):
    return {
        "id": aid,
        "rule": {"id": "92205", "level": 9},
        "agent": {"ip": "10.44.0.10", "name": "win-lab"},
        "data": {
            "win": {
                "system": {
                    "eventID": str(event_id),
                    "eventRecordID": "541",
                    "providerName": "Microsoft-Windows-Sysmon",
                    "channel": "Microsoft-Windows-Sysmon/Operational",
                    "systemTime": "2026-11-26T06:00:00Z",
                    "message": "RAW MESSAGE MUST NOT REACH A MODEL",
                },
                "eventdata": {
                    "processGuid": GUID,
                    "processId": "8748",
                    "image": r"C:\Windows\SysWOW64\WindowsPowerShell\v1.0\powershell.exe",
                    "user": r"NT AUTHORITY\SYSTEM",
                    "targetFilename": r"C:\Windows\SystemTemp\__PSScriptPolicyTest_ajjmzc31.k4g.ps1",
                    **event,
                },
            }
        },
    }


@pytest.mark.parametrize(
    "event_id,fields",
    [
        (
            1,
            {
                "parentProcessGuid": GUID,
                "parentProcessId": 700,
                "parentImage": r"C:\Windows\explorer.exe",
                "parentCommandLine": "explorer.exe",
                "parentUser": r"LAB\Alice",
                "commandLine": "powershell.exe -NoProfile",
                "originalFileName": "PowerShell.EXE",
                "integrityLevel": "System",
                "hashes": "SHA256=" + HASH,
            },
        ),
        (
            3,
            {
                "sourceIp": "10.44.1.10",
                "destinationIp": "192.168.44.10",
                "sourcePort": "50000",
                "destinationPort": 443,
                "protocol": "tcp",
                "initiated": True,
            },
        ),
        (
            10,
            {
                "sourceImage": r"C:\Windows\tool.exe",
                "targetImage": r"C:\Windows\System32\lsass.exe",
                "sourceProcessGuid": GUID,
                "targetProcessGuid": GUID,
                "sourceProcessId": "800",
                "targetProcessId": 900,
                "grantedAccess": "0x1010",
            },
        ),
        (11, {"creationUtcTime": "2026-11-26 06:00:00.123", "utcTime": "2026-11-26 06:00:01.123"}),
        (
            13,
            {
                "targetObject": r"HKU\S-1-5-21-111-222-333-1001\Software\Microsoft\Windows\CurrentVersion\Run\Lab",
                "eventType": "SetValue",
                "details": r"C:\Users\Alice\AppData\lab.exe",
                "type": "REG_SZ",
            },
        ),
        (22, {"queryName": "dc01.lab.internal", "queryStatus": "0", "queryResults": "10.44.0.10;"}),
    ],
)
def test_allowlisted_sysmon_semantics_survive(event_id, fields):
    raw = sysmon(event_id, **fields)
    value = normalize(raw, {"10.44.0.10": "192.168.44.10"})
    row = value["evidence"]
    assert value["schema_version"] == 2 and row["kind"] == "host"
    assert row["host_ip"] == "192.168.44.10" and row["id"] == raw["id"]
    assert row["eventRecordID"] == "541" and row["eventRecordID"] != row["id"]
    for key, expected in fields.items():
        assert row[key] == expected
    for key in SYSTEM_FIELDS:
        assert row[key] == raw["data"]["win"]["system"][key]
    assert "RAW MESSAGE" not in json.dumps(row)


def test_optional_fields_are_not_invented_and_unknown_fields_stay_raw():
    raw = sysmon()
    raw["data"]["win"]["eventdata"] = {"image": "powershell.exe", "arbitraryRawDump": "PRIVATE"}
    row = normalize(raw)["evidence"]
    assert row["image"] == "powershell.exe" and "targetFilename" not in row
    assert "PRIVATE" not in json.dumps(row)


@pytest.mark.parametrize("field", list(EVENT_FIELDS))
def test_known_evidence_fields_reject_objects_and_oversize(field):
    with pytest.raises(ValidationError):
        normalize(sysmon(**{field: {"bad": "object"}}))
    with pytest.raises(ValidationError):
        normalize(sysmon(**{field: "x" * (EVENT_FIELDS[field] + 1)}))


@pytest.mark.parametrize("field", list(SYSTEM_FIELDS))
def test_metadata_rejects_invalid_values(field):
    raw = sysmon()
    raw["data"]["win"]["system"][field] = []
    with pytest.raises(ValidationError):
        normalize(raw)


def test_file_fields_reach_host_and_judge_but_empty_net_is_audited(settings):
    config = replace(settings, llm_mode="live", host_ips={"10.44.0.10": "192.168.44.10"})
    service = Service(config)
    calls = []

    def post(url, **kwargs):
        messages = kwargs["json"]["messages"]
        payload = json.loads(messages[1]["content"])
        calls.append((messages, payload))
        if isinstance(payload, list):
            result = {
                "finding": "Single Sysmon file creation, incomplete attack evidence",
                "evidence_ids": [payload[0]["id"]],
                "suspicious": False,
                "candidate": None,
            }
        else:
            result = {
                "verdict": "review",
                "confidence": 0.60,
                "evidence_ids": payload["ids"],
                "reason": "Only current file creation evidence; historical Defender/LSASS context is not causal proof.",
                "block_ip": None,
                "missing_data": ["No corroborated malicious sequence"],
            }
        return httpx.Response(
            200,
            request=httpx.Request("POST", "https://provider.invalid"),
            json={"choices": [{"message": {"content": json.dumps(result)}}]},
        )

    service.llm.post = post
    service.store.ingest(sysmon(), 0)
    service.tick(40)
    case = service.store.cases()[0]
    assert len(calls) == 2
    for messages, payload in calls:
        row = payload[0] if isinstance(payload, list) else payload["evidence"][0]
        assert row["processGuid"] == GUID and row["processId"] == "8748"
        assert "__PSScriptPolicyTest_ajjmzc31.k4g.ps1" in row["targetFilename"]
        assert "RAW MESSAGE" not in json.dumps(messages) and r"NT AUTHORITY" not in json.dumps(messages)
    assert case["verdict"]["verdict"] == "review" and case["verdict"]["confidence"] == 0.6
    assert case["verdict"]["grounded"] == 1 and case["verdict"]["block_ip"] is None
    with service.store.connect() as db:
        assert db.execute("SELECT status FROM steps WHERE role='net'").fetchone()[0] == "skipped"
        assert db.execute("SELECT count(*) FROM ledger WHERE agent='net'").fetchone()[0] == 0
        assert (
            db.execute("SELECT count(*) FROM audit WHERE action='analysis.role_skipped'").fetchone()[0] == 1
        )


def test_aggregation_ignores_delivery_metadata_but_preserves_security_differences():
    group = Grouper(host_ips={"10.44.0.10": "192.168.44.10"})
    first = sysmon(aid="one")
    second = sysmon(aid="two")
    second["data"]["win"]["system"].update(eventRecordID="999", systemTime="2026-11-26T07:00:00Z")
    second["data"]["win"]["eventdata"]["utcTime"] = "later"
    first["data"]["win"]["eventdata"]["utcTime"] = "earlier"
    group.add(first, 0)
    group.add(second, 1)
    group.add(sysmon(aid="other-file", targetFilename=r"C:\Windows\SystemTemp\other.ps1"), 2)
    group.add(sysmon(aid="other-process", processGuid="{395b0161-db92-6b07-3d05-000000000801}"), 3)
    value = group.ready(34)[0]
    assert len(value["alerts"]) == 3 and len(value["raw_ids"]) == 4
    assert sorted(r["count"] for r in value["alerts"]) == [1, 1, 2]


def test_cap_and_mixed_mapping_preserve_all_raw_ids(settings):
    group = Grouper(cap=40, host_ips={"10.44.0.10": "192.168.44.10"})
    group.add(snort("network", src="10.44.1.10", dst="192.168.44.10"), 0)
    for n in range(45):
        group.add(sysmon(aid=f"host-{n}", processId=str(n)), n / 100)
    value = group.ready(31)[0]
    assert len(value["raw_ids"]) == 46 and len(value["alerts"]) == 40 and value["dropped_rows"] == 6
    assert "192.168.44.10" in value["ips"] and "10.44.0.10" not in value["ips"]


def test_historical_normalization_and_frozen_snapshots_are_not_rewritten(settings):
    store = Store(settings.db)
    store.ingest(sysmon(), 0)
    old = {
        "schema_version": 1,
        "evidence": {"id": "sysmon-file-1", "kind": "host", "level": 9, "image": "powershell.exe"},
        "entities": ["host:win-lab"],
        "ips": [],
    }
    with store.connect() as db:
        db.execute("UPDATE inbox SET normalized=?", (json.dumps(old),))
    cid = store.enqueue(
        {"raw_ids": ["sysmon-file-1"], "alerts": [old["evidence"]], "ips": [], "entities": ["host:win-lab"]},
        settings=settings,
    )
    before = store.get_run(store.get(cid)["latest_run_id"])["evidence"]
    Store(settings.db)
    with store.connect() as db:
        assert db.execute("SELECT normalized FROM inbox").fetchone()[0] == json.dumps(old)
    assert store.get_run(store.get(cid)["latest_run_id"])["evidence"] == before
