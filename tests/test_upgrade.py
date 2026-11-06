import json
import sqlite3
import time
from concurrent.futures import ThreadPoolExecutor

import httpx
import pytest
from fastapi.testclient import TestClient

from src.anon import Anon
from src.api.main import create_app
from src.service import Service
from src.storage import SCHEMA, Store
from src.tools import ToolRequest, execute
from tests.conftest import snort, windows


@pytest.fixture
def console(settings):
    with TestClient(create_app(settings, worker=False)) as client:
        result = client.post(
            "/api/v1/auth/login", json={"username": "admin", "password": settings.approve_key}
        )
        assert result.status_code == 200
        client.headers["X-CSRF-Token"] = result.json()["csrf"]
        yield client


def incident(client):
    service = client.app.state.service
    service.store.ingest(snort(), 0)
    service.store.ingest(windows(), 1)
    service.tick(40)
    return service.store.cases()[0]


def test_old_database_migration_preserves_all_history(tmp_path):
    path = tmp_path / "old.db"
    raw = json.dumps(snort())
    snapshot = json.dumps({"raw_ids": ["n1"], "alerts": [], "ips": []})
    with sqlite3.connect(path) as db:
        db.executescript(SCHEMA)
        db.execute("INSERT INTO inbox VALUES('n1',1,?,'old-case')", (raw,))
        db.execute("INSERT INTO cases VALUES('old-case',2,'pending',?,'{}','{}')", (snapshot,))
        db.execute("INSERT INTO ledger VALUES(1,3,'old-case','net','mock','[]','{}','[]','{}',10,NULL)")
        db.execute("INSERT INTO actions VALUES(1,4,'old-case','reject',NULL,'dry-run','rejected')")
    store = Store(path)
    Store(path)
    assert store.get("old-case")["workflow_status"] == "review"
    with store.connect() as db:
        assert db.execute("SELECT alert FROM inbox").fetchone()[0] == raw
        assert db.execute("SELECT count(*) FROM ledger").fetchone()[0] == 1
        assert db.execute("SELECT run_id FROM ledger").fetchone()[0] is None
        assert db.execute("SELECT result,actor FROM actions").fetchone()[0] == "rejected"
        assert db.execute("SELECT count(*) FROM incident_alerts").fetchone()[0] == 1
        assert db.execute("SELECT count(*) FROM runs").fetchone()[0] == 0


def test_generic_wazuh_alerts_survive_without_a_correlation_entity(console, settings):
    token = {"Authorization": "Bearer " + settings.ingest_key}
    for aid in ("fim-1", "fim-2"):
        payload = {
            "id": aid,
            "rule": {"id": "550", "level": 7, "description": "File integrity change"},
            "syscheck": {"path": "/etc/ssh/sshd_config"},
        }
        assert console.post("/ingest", json=payload, headers=token).status_code == 202
    console.app.state.service.tick()
    result = console.get("/api/v1/alerts?status=uncorrelated").json()
    assert result["total"] == 2
    assert all(
        a["event_type"] == "file_integrity" and not a["normalized"]["entities"] for a in result["items"]
    )
    assert console.get("/api/v1/incidents").json()["total"] == 0
    assert (
        console.get("/api/v1/alerts/fim-1").json()["raw_event"]["syscheck"]["path"] == "/etc/ssh/sshd_config"
    )

    assert set(console.get("/api/v1/alerts/fim-1").json()["raw_event"]) == {"id", "rule", "syscheck"}


def test_linux_authentication_is_not_forced_into_network_or_sysmon(console, settings):
    payload = {
        "id": "linux-1",
        "rule": {"id": "5710", "level": 12, "groups": ["sshd", "authentication_failed"]},
        "agent": {"name": "linux-server"},
        "data": {"srcip": "8.8.8.8", "dstuser": "analyst"},
    }
    assert (
        console.post(
            "/ingest", json=payload, headers={"Authorization": "Bearer " + settings.ingest_key}
        ).status_code
        == 202
    )
    console.app.state.service.tick()
    row = console.get("/api/v1/alerts/linux-1").json()
    assert row["event_type"] == "authentication" and row["normalized"]["evidence"]["kind"] == "generic"
    assert row["case_id"]
    with console.app.state.service.store.connect() as db:
        assert db.execute("SELECT status FROM jobs").fetchone()[0] == "completed"
        assert (
            db.execute("SELECT count(*) FROM ledger WHERE agent IN ('net','host','judge')").fetchone()[0] == 3
        )
        assert all("linux-server" not in r[0] for r in db.execute("SELECT prompt FROM ledger"))


def test_source_external_id_idempotency(settings):
    service = Service(settings)
    assert service.store.ingest(snort(), 0, source="east")
    assert not service.store.ingest(snort(), 0, source="east")
    assert service.store.ingest(snort(), 0, source="west")
    service.tick(40)
    assert service.store.cases()[0]["incident"]["raw_ids"] == ["east:n1", "west:n1"]


def test_atomic_job_claim_and_expired_lease_recovery(settings):
    store = Store(settings.db)
    cid = store.enqueue({"raw_ids": [], "alerts": [], "ips": [], "entities": [], "dropped_rows": 0})
    with ThreadPoolExecutor(max_workers=4) as pool:
        jobs = list(pool.map(lambda i: store.claim_job(str(i), now=time.time(), lease=5), range(4)))
    claimed = [j for j in jobs if j]
    assert len(claimed) == 1
    recovered = Store(settings.db).claim_job("new-worker", now=time.time() + 10)
    assert recovered["case_id"] == cid and recovered["attempts"] == 2
    assert not store.complete_job(claimed[0], {"verdict": "benign"}, {})


def test_transient_provider_error_retries_with_backoff_then_dead_letters(settings):
    settings.llm_mode = "live"
    service = Service(settings)
    service.store.ingest(windows(), 0)
    service.llm.post = lambda *a, **k: (_ for _ in ()).throw(httpx.ConnectError("must not appear in API"))
    service.tick(1)
    with service.store.connect() as db:
        job = dict(db.execute("SELECT * FROM jobs").fetchone())
    assert job["status"] == "queued" and job["attempts"] == 1 and job["available"] > time.time()
    service.tick(2)
    with service.store.connect() as db:
        assert db.execute("SELECT attempts FROM jobs").fetchone()[0] == 1
    for _ in range(2):
        with service.store.connect() as db:
            db.execute("UPDATE jobs SET available=0")
        service.tick(3)
    with service.store.connect() as db:
        assert db.execute("SELECT status FROM jobs").fetchone()[0] == "dead_letter"
    verdict = service.store.cases()[0]["verdict"]
    assert verdict["verdict"] == "review" and verdict["mode"] == "live"
    assert "must not appear" not in json.dumps(verdict)


def test_non_transient_provider_error_does_not_retry(settings):
    settings.llm_mode = "live"
    service = Service(settings)
    service.store.ingest(windows(), 0)
    service.llm.post = lambda *a, **k: httpx.Response(
        401, request=httpx.Request("POST", "https://example.org")
    )
    service.tick(1)
    with service.store.connect() as db:
        row = db.execute("SELECT status,attempts FROM jobs").fetchone()
    assert tuple(row) == ("dead_letter", 1)


@pytest.mark.parametrize(
    "role,can_note,can_approve",
    [("viewer", False, False), ("analyst", True, False), ("approver", True, True)],
)
def test_role_permissions_and_csrf(console, settings, role, can_note, can_approve):
    case = incident(console)
    created = console.post(
        "/api/v1/users", json={"username": role, "role": role, "password": "test-password-abcdefghijkl"}
    )
    assert created.status_code == 201
    console.post("/api/v1/auth/logout")
    result = console.post(
        "/api/v1/auth/login", json={"username": role, "password": "test-password-abcdefghijkl"}
    )
    console.headers["X-CSRF-Token"] = result.json()["csrf"]
    assert console.get("/api/v1/incidents").status_code == 200
    posted = console.post(f"/api/v1/incidents/{case['id']}/notes", json={"body": "Observed evidence"})
    assert posted.status_code == (201 if can_note else 403)
    assert console.post(
        f"/api/v1/incidents/{case['id']}/response",
        json={"decision": "approve", "run_id": case["latest_run_id"]},
    ).status_code == (200 if can_approve else 403)
    console.headers.pop("X-CSRF-Token")
    assert console.post("/api/v1/auth/logout").status_code == 403
    assert "agentsoc_session" in console.cookies
    cookie = result.headers["set-cookie"].lower()
    assert "httponly" in cookie and "samesite=strict" in cookie


def test_replay_is_a_new_frozen_run_and_cannot_execute_response(console):
    case = incident(console)
    original = case["latest_run_id"]
    snapshot = console.get("/api/v1/runs/" + original).json()["evidence"]
    result = console.post(f"/api/v1/incidents/{case['id']}/replay", json={"parent_run_id": original})
    rid = result.json()["run_id"]
    assert rid != original and not result.json()["response_allowed"]
    service = console.app.state.service
    service.store.ingest(windows("late"))
    service.tick()
    run = console.get("/api/v1/runs/" + rid).json()
    assert run["evidence"] == snapshot and run["replay"] == 1
    assert (
        console.post(
            f"/api/v1/incidents/{case['id']}/response", json={"decision": "approve", "run_id": rid}
        ).status_code
        == 400
    )
    assert service.store.get(case["id"])["latest_run_id"] == original
    with service.store.connect() as db:
        assert db.execute("SELECT count(*) FROM actions").fetchone()[0] == 0
    related = [s for s in run["steps"] if s["tool_name"] == "related_alerts"]
    assert all(item["id"] != "late" for step in related for item in step["response"]["items"])


def test_tool_scope_and_bound_queries(console):
    case = incident(console)
    with pytest.raises(PermissionError):
        execute(
            console.app.state.service.store,
            ToolRequest(name="related_alerts", run_id=case["latest_run_id"], entity="ip:unrelated"),
            Anon(),
            incident_id=case["id"],
        )
    with pytest.raises(PermissionError):
        execute(
            console.app.state.service.store,
            ToolRequest(name="incident_evidence", run_id=case["latest_run_id"]),
            Anon(),
            incident_id="other",
        )


def test_pagination_aggregates_and_filters_are_server_side(console):
    service = console.app.state.service
    for i in range(31):
        service.store.ingest(snort(str(i), level=15 if i < 7 else 8), i)
    page = console.get("/api/v1/alerts?limit=5&severity=critical&order=oldest").json()
    assert page["total"] == 7 and len(page["items"]) == 5 and page["severity_counts"]["critical"] == 7
    next_page = console.get("/api/v1/alerts?limit=5&severity=critical&offset=5&order=oldest").json()
    assert len(next_page["items"]) == 2
    assert not set(a["id"] for a in page["items"]) & set(a["id"] for a in next_page["items"])
    overview = console.get("/api/v1/overview").json()
    assert overview["metrics"]["alerts_received"] == 31 and overview["severity"]["critical"] == 7
    assert console.get("/api/v1/alerts?entity=ip:8.8.8.8").json()["total"] == 0


def test_readiness_requires_fresh_worker_and_does_not_claim_provider_connectivity(console):
    assert console.get("/live").status_code == 200
    assert console.get("/ready").status_code == 503
    console.app.state.service.tick()
    assert console.get("/ready").status_code == 200
    state = console.get("/api/v1/system").json()
    assert state["provider"]["reachable"] is None and state["wazuh_connection"] == "not_probed"


def test_credentials_and_restore_map_are_never_returned(console, settings):
    case = incident(console)
    for url in ("/api/v1/overview", "/api/v1/system", "/api/v1/ledger", f"/api/v1/incidents/{case['id']}"):
        result = console.get(url)
        assert result.status_code == 200
        assert (
            '"restore"' not in result.text
            and settings.ingest_key not in result.text
            and settings.approve_key not in result.text
        )


def test_json_escaping_when_restoring_model_response(console):
    case = incident(console)
    with console.app.state.service.store.connect() as db:
        verdict = case["verdict"] | {"reason": "Inspect USER_9999"}
        db.execute(
            "UPDATE cases SET verdict=?,restore=? WHERE id=?",
            (json.dumps(verdict), json.dumps({"USER_9999": 'C:\\Users\\test\\file "quoted"'}), case["id"]),
        )
    result = console.get(f"/api/v1/incidents/{case['id']}")
    assert result.status_code == 200 and '"quoted"' in result.json()["verdict"]["reason"]


def test_response_intent_is_durable_before_executor_is_called(console, monkeypatch):
    from src import response

    case = incident(console)
    repo = console.app.state.service.store

    def execute(target, config):
        with repo.connect() as db:
            intent = db.execute("SELECT * FROM actions WHERE case_id=?", (case["id"],)).fetchone()
        assert intent["result"] == "executing" and intent["actor"] == "admin"
        assert intent["ip"] == target and intent["run_id"] == case["latest_run_id"]
        return "dry_run"

    monkeypatch.setattr(response, "execute", execute)
    body = {"decision": "approve", "run_id": case["latest_run_id"]}
    url = f"/api/v1/incidents/{case['id']}/response"
    assert console.post(url, json=body).status_code == 200
    assert console.post(url, json=body).status_code == 409
    with repo.connect() as db:
        assert db.execute("SELECT count(*) FROM actions").fetchone()[0] == 1
        assert db.execute("SELECT completed_at FROM actions").fetchone()[0]


def test_replay_requires_an_existing_nonempty_parent(console):
    case = incident(console)
    before = console.app.state.service.store.get(case["id"])["latest_run_id"]
    assert (
        console.post(f"/api/v1/incidents/{case['id']}/replay", json={"parent_run_id": ""}).status_code == 422
    )
    assert console.app.state.service.store.get(case["id"])["latest_run_id"] == before


def test_cross_origin_write_is_denied_and_audited(console):
    response = console.post("/api/v1/auth/logout", headers={"Origin": "https://other.invalid"})
    assert response.status_code == 403
    assert console.get("/api/v1/audit?action=origin.denied").json()["total"] == 1


def test_placeholder_entities_do_not_create_unknown_buckets(console, settings):
    for aid in ("unknown1", "unknown2"):
        value = {"id": aid, "rule": {"level": 12}, "agent": {"name": "unknown", "ip": "0.0.0.0"}}
        assert (
            console.post(
                "/ingest", json=value, headers={"Authorization": "Bearer " + settings.ingest_key}
            ).status_code
            == 202
        )
    console.app.state.service.tick()
    assert console.get("/api/v1/alerts?status=uncorrelated").json()["total"] == 2
    assert console.get("/api/v1/incidents").json()["total"] == 0


def test_previous_investigations_tool_returns_real_related_history(settings):
    service = Service(settings)
    service.store.ingest(windows("old"))
    service.tick()
    first = service.store.cases()[0]["latest_run_id"]
    service.store.ingest(windows("new"))
    service.tick()
    latest = service.store.cases()[0]["latest_run_id"]
    with service.store.connect() as db:
        rows = db.execute(
            "SELECT response FROM ledger WHERE run_id=? AND tool_name='previous_investigations'", (latest,)
        ).fetchall()
    assert first in [item["id"] for row in rows for item in json.loads(row[0])["items"]]


@pytest.mark.parametrize(
    "field,value", [("agent", {"name": {"not": "a string"}}), ("data", {"src_addr": {"not": "an IP string"}})]
)
def test_malformed_vendor_identity_cannot_crash_the_console(console, settings, field, value):
    body = snort()
    body[field] = value
    assert (
        console.post(
            "/ingest", json=body, headers={"Authorization": "Bearer " + settings.ingest_key}
        ).status_code
        == 422
    )
    assert console.get("/api/v1/alerts").json()["total"] == 0


def test_external_alert_id_with_slash_is_retrievable(console, settings):
    value = snort("manager/folder/event")
    assert (
        console.post(
            "/ingest", json=value, headers={"Authorization": "Bearer " + settings.ingest_key}
        ).status_code
        == 202
    )
    assert console.get("/api/v1/alerts/manager%2Ffolder%2Fevent").json()["raw_event"]["id"] == value["id"]


def test_source_namespaces_cannot_drop_a_different_external_id(settings):
    store = Store(settings.db)
    assert store.ingest(snort("east:n1"), source="wazuh")
    assert store.ingest(snort("n1"), source="east")
    assert not store.ingest(snort("n1"), source="east")
    with store.connect() as db:
        rows = db.execute("SELECT id,source,external_id,normalized FROM inbox").fetchall()
    assert len(rows) == 2 and len({r["id"] for r in rows}) == 2
    assert {(r["source"], r["external_id"]) for r in rows} == {("wazuh", "east:n1"), ("east", "n1")}
    assert all(json.loads(r["normalized"])["evidence"]["id"] == r["id"] for r in rows)
