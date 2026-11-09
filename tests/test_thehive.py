import json

import httpx
import pytest

from src.service import Service
from src.thehive import payload, sync_pending
from tests.conftest import windows


def prepared(settings):
    service = Service(settings)
    service.store.ingest(windows())
    service.tick()
    settings.thehive_url = "http://thehive:9000"
    settings.thehive_key = "h" * 32
    return service.store


def due(store):
    with store.connect() as db:
        db.execute("UPDATE thehive_sync SET available=0")


def test_create_restart_update_and_no_duplicate(settings):
    store = prepared(settings)
    calls = []

    def handler(req):
        calls.append((req.method, req.url.path, json.loads(req.content)))
        if req.url.path.endswith("/query"):
            return httpx.Response(200, json=[])
        return httpx.Response(201 if req.method == "POST" else 200, json={"_id": "~42"})

    transport = httpx.MockTransport(handler)
    sync_pending(store, settings, transport=transport)
    due(store)
    sync_pending(store, settings, transport=transport)
    assert sum(path == "/api/v1/case" for _, path, _ in calls) == 1
    cid = store.cases()[0]["id"]
    store.record_action(cid, "reject", None, "dry-run", "rejected")
    due(store)
    sync_pending(store, settings, transport=transport)
    assert "rejected" in calls[-1][2]["description"]
    with store.connect() as db:
        assert db.execute("SELECT remote_id FROM thehive_sync").fetchone()[0] == "~42"


def test_unavailable_does_not_change_analysis(settings):
    store = prepared(settings)

    def handler(req):
        raise httpx.ConnectError("secret must never be logged", request=req)

    sync_pending(store, settings, transport=httpx.MockTransport(handler))
    assert store.cases()[0]["status"] == "pending"
    with store.connect() as db:
        row = db.execute("SELECT * FROM thehive_sync").fetchone()
        assert row["error"] == "ConnectError"
        assert row["state"] == "pending"


def test_ambiguous_create_reconciles_without_reposting(settings):
    store = prepared(settings)
    posted = []
    found = []

    def handler(req):
        if req.url.path.endswith("/query"):
            return httpx.Response(200, json=found)
        if req.method == "POST":
            posted.append(req)
            raise httpx.ReadTimeout("lost response", request=req)
        return httpx.Response(200, json={})

    transport = httpx.MockTransport(handler)
    sync_pending(store, settings, transport=transport)
    due(store)
    sync_pending(store, settings, transport=transport)
    assert len(posted) == 1
    found.append({"_id": "~recovered"})
    due(store)
    sync_pending(store, settings, transport=transport)
    assert len(posted) == 1
    with store.connect() as db:
        assert db.execute("SELECT remote_id,state FROM thehive_sync").fetchone()[:] == (
            "~recovered",
            "synced",
        )


def test_secrets_never_restored_to_remote(settings):
    store = prepared(settings)
    case = store.cases()[0]
    case["verdict"]["reason"] = "HOST_0001 SECRET_0001 " + settings.thehive_key
    case["restore"] = {"HOST_0001": "win-victim", "SECRET_0001": "sensitive-value"}
    body = json.dumps(payload(case, settings))
    assert "win-victim" in body
    assert "sensitive-value" not in body
    assert settings.thehive_key not in body


def test_demo_and_unconfigured_do_not_send(settings):
    store = prepared(settings)

    def handler(req):
        raise AssertionError("network must not be used")

    settings.demo = True
    sync_pending(store, settings, transport=httpx.MockTransport(handler))
    settings.demo = False
    settings.thehive_key = ""
    sync_pending(store, settings, transport=httpx.MockTransport(handler))


def test_lease_prevents_second_sender(settings):
    store = prepared(settings)
    with store.connect() as db:
        db.execute("UPDATE thehive_sync SET lease_until=9999999999")

    def handler(req):
        raise AssertionError("leased rows must not send")

    sync_pending(store, settings, transport=httpx.MockTransport(handler))


def test_replay_does_not_queue_a_new_remote_case(settings):
    store = prepared(settings)
    case = store.cases()[0]
    with store.connect() as db:
        db.execute("DELETE FROM thehive_sync")
    store.new_run(case["id"], parent=case["latest_run_id"], settings=settings)
    job = store.claim_job("replay-test")
    store.complete_job(job, case["verdict"], case["restore"])
    with store.connect() as db:
        assert db.execute("SELECT count(*) FROM thehive_sync").fetchone()[0] == 0


def test_outage_recovers_without_reanalysis(settings):
    store = prepared(settings)

    def offline(req):
        return httpx.Response(503)

    sync_pending(store, settings, transport=httpx.MockTransport(offline))
    due(store)

    def online(req):
        return (
            httpx.Response(200, json=[])
            if req.url.path.endswith("/query")
            else httpx.Response(201, json={"_id": "~7"})
        )

    sync_pending(store, settings, transport=httpx.MockTransport(online))
    with store.connect() as db:
        assert db.execute("SELECT state FROM thehive_sync").fetchone()[0] == "synced"
        assert db.execute("SELECT count(*) FROM runs").fetchone()[0] == 1


@pytest.mark.parametrize("query_status", [401, 403, 429, 503])
def test_ambiguous_create_stays_fenced_after_query_errors(settings, query_status):
    store = prepared(settings)
    posts = []
    query_response = [httpx.Response(200, json=[])]

    def handler(req):
        if req.url.path.endswith("/query"):
            return query_response[0]
        posts.append(req)
        raise httpx.ReadTimeout("lost create acknowledgement", request=req)

    transport = httpx.MockTransport(handler)
    sync_pending(store, settings, transport=transport)
    query_response[0] = httpx.Response(query_status)
    due(store)
    sync_pending(store, settings, transport=transport)
    with store.connect() as db:
        assert db.execute("SELECT state FROM thehive_sync").fetchone()[0] == "creating"
    query_response[0] = httpx.Response(200, json=[])
    due(store)
    sync_pending(store, settings, transport=transport)
    assert len(posts) == 1
    with store.connect() as db:
        assert db.execute("SELECT error FROM thehive_sync").fetchone()[0] == "CreateOutcomeUnknown"


def test_payload_redacts_escaped_credentials_and_restores_valid_json(settings):
    store = prepared(settings)
    case = store.cases()[0]
    settings.thehive_key = 'sensitive"key\\with\nnewline'
    path = 'C:\\Users\\example\\"quoted".exe'
    case["restore"] = {"HOST_0001": path, "SECRET_0001": settings.thehive_key}
    case["verdict"]["reason"] = "HOST_0001 SECRET_0001 " + settings.thehive_key
    content = json.loads(payload(case, settings)["description"].split("\n\n", 1)[1])
    assert content["verdict"]["reason"] == path + " [REDACTED] [REDACTED]"


def test_lost_lease_cannot_create_or_overwrite_new_owner(settings):
    store = prepared(settings)
    calls = []

    def handler(req):
        calls.append(req)
        with store.connect() as db:
            db.execute("UPDATE thehive_sync SET lease_until=9999999999,state='synced',remote_id='~new'")
        return httpx.Response(200, json=[])

    sync_pending(store, settings, transport=httpx.MockTransport(handler))
    assert len(calls) == 1  # Query only: no create after losing ownership.
    with store.connect() as db:
        assert db.execute("SELECT state,remote_id,lease_until FROM thehive_sync").fetchone()[:] == (
            "synced",
            "~new",
            9999999999,
        )
