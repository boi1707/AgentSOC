import json
import time
from concurrent.futures import ThreadPoolExecutor
from dataclasses import replace

import httpx
import pytest
from fastapi.testclient import TestClient

from src.api.main import create_app
from src.integrations import incident_integrations, integration_health
from src.logs import JsonFormatter
from src.service import Service
from src.shuffle import deliver_pending
from src.storage import Store
from src.virustotal import enrich_pending, public_ips


def completed(settings, ips=None):
    store = Store(settings.db)
    cid = store.enqueue({"ips": ips or [], "raw_ids": [], "alerts": [], "entities": []}, settings=settings)
    job = store.claim_job("fixture")
    store.complete_job(job, {"verdict": "review", "confidence": 0, "reason": "fixture"}, {})
    return store, cid


def lookup_response():
    return httpx.Response(
        200,
        json={
            "data": {
                "attributes": {
                    "last_analysis_stats": {"malicious": 2, "suspicious": 1, "harmless": 12},
                    "irrelevant_sensitive_field": "must not persist",
                }
            }
        },
    )


def test_vt_only_public_ips_and_three_max():
    assert public_ips(
        [
            "10.8.0.1",
            "192.168.1.1",
            "127.0.0.1",
            "169.254.1.1",
            "100.64.0.1",
            "224.0.0.1",
            "0.0.0.0",
            "::1",
            "fe80::1",
            "fc00::1",
            "::ffff:192.168.1.1",
            "192.0.2.1",
            "not-an-ip",
            "1.1.1.1",
        ]
    ) == ["1.1.1.1"]
    assert len(public_ips(["1.1.1.1", "8.8.8.8", "9.9.9.9", "4.2.2.2"])) == 3
    assert public_ips(["8.8.8.8"], ["8.8.8.8"]) == []


def test_vt_persists_minimal_report_and_cache_across_restart(settings):
    store, cid = completed(settings, ["8.8.8.8", "192.168.1.1"])
    settings.vt_key = "vt-secret"
    requests = []

    def handler(req):
        requests.append(req)
        assert req.method == "GET"
        assert req.headers["x-apikey"] == settings.vt_key
        assert req.url == "https://www.virustotal.com/api/v3/ip_addresses/8.8.8.8"
        return lookup_response()

    transport = httpx.MockTransport(handler)
    enrich_pending(store, settings, transport=transport)
    report = incident_integrations(store, cid)["virustotal"][0]["report"]
    assert report["stats"]["malicious"] == 2
    assert "irrelevant_sensitive_field" not in json.dumps(report)
    store2, cid2 = completed(settings, ["8.8.8.8"])
    enrich_pending(store2, settings, transport=transport)
    assert len(requests) == 1
    assert incident_integrations(store2, cid2)["virustotal"][0]["status"] == "complete"


def test_vt_rechecks_exclusion_even_for_injected_private_job(settings):
    store, cid = completed(settings)
    with store.connect() as db:
        db.execute("INSERT INTO vt_jobs(case_id,ip) VALUES(?,?)", (cid, "192.168.1.1"))
    settings.vt_key = "key"
    enrich_pending(
        store, settings, transport=httpx.MockTransport(lambda req: pytest.fail("private IP egress"))
    )
    assert incident_integrations(store, cid)["virustotal"][0]["status"] == "skipped"


def test_vt_budget_and_429_are_persistent(settings):
    store, cid = completed(settings, ["1.1.1.1", "8.8.8.8"])
    settings.vt_key = "key"
    calls = []

    def handler(req):
        calls.append(req)
        return httpx.Response(429, headers={"Retry-After": "120"})

    transport = httpx.MockTransport(handler)
    enrich_pending(store, settings, transport=transport)
    enrich_pending(Store(settings.db), settings, transport=transport)
    assert len(calls) == 1
    with store.connect() as db:
        assert db.execute("SELECT next_at FROM vt_budget").fetchone()[0] >= time.time() + 100
        assert db.execute("SELECT count FROM vt_budget").fetchone()[0] == 1
    assert store.get(cid)["status"] == "pending"


def test_vt_daily_budget_and_inter_request_interval(settings):
    store, _ = completed(settings, ["1.1.1.1", "8.8.8.8", "9.9.9.9"])
    settings.vt_key = "key"
    settings.vt_daily_limit = 1
    requests = []

    def handler(req):
        requests.append(req)
        return lookup_response()

    transport = httpx.MockTransport(handler)
    enrich_pending(store, settings, transport=transport)
    with store.connect() as db:
        db.execute("UPDATE vt_budget SET next_at=0")
    enrich_pending(Store(settings.db), settings, transport=transport)
    assert len(requests) == 1


@pytest.mark.parametrize("status", [404, 401, 403, 503])
def test_vt_http_errors_do_not_change_verdict(settings, status):
    store, cid = completed(settings, ["8.8.8.8"])
    settings.vt_key = "key"
    enrich_pending(store, settings, transport=httpx.MockTransport(lambda req: httpx.Response(status)))
    job = incident_integrations(store, cid)["virustotal"][0]
    assert job["status"] == ("complete" if status == 404 else "retry")
    assert store.get(cid)["verdict"]["verdict"] == "review"


def test_vt_malformed_report_retries(settings):
    store, cid = completed(settings, ["8.8.8.8"])
    settings.vt_key = "key"
    enrich_pending(
        store, settings, transport=httpx.MockTransport(lambda req: httpx.Response(200, json={"data": {}}))
    )
    assert incident_integrations(store, cid)["virustotal"][0]["error"] == "KeyError"


def test_shuffle_only_after_approved_result_not_pending_or_rejected(settings):
    store, cid = completed(settings)
    assert incident_integrations(store, cid)["shuffle"] == []
    store.record_action(cid, "reject", None, "dry-run", "rejected")
    assert incident_integrations(store, cid)["shuffle"] == []
    store.record_action(cid, "approve", "192.168.20.50", "dry-run", "dry_run")
    settings.shuffle_hook = "http://shuffle:5001/api/v1/hooks/webhook_fixture"
    bodies = []

    def handler(req):
        body = json.loads(req.content)
        assert req.headers["Idempotency-Key"] == body["event_id"]
        assert body["blocked"] is False
        assert body["mode"] == "dry-run"
        bodies.append(body)
        return httpx.Response(200, json={"success": True})

    transport = httpx.MockTransport(handler)
    deliver_pending(store, settings, transport=transport)
    deliver_pending(Store(settings.db), settings, transport=transport)
    assert len(bodies) == 1
    assert incident_integrations(store, cid)["shuffle"][0]["status"] == "delivered"
    assert store.get(cid)["status"] == "dry_run"


def test_shuffle_retries_with_same_event_id_without_reblocking(settings):
    store, cid = completed(settings)
    store.record_action(cid, "approve", "192.168.20.50", "ssh", "blocked")
    settings.shuffle_hook = "http://shuffle/webhook_fixture"
    bodies = []

    def handler(req):
        bodies.append(json.loads(req.content))
        return httpx.Response(503 if len(bodies) == 1 else 200)

    transport = httpx.MockTransport(handler)
    deliver_pending(store, settings, transport=transport)
    with store.connect() as db:
        db.execute("UPDATE shuffle_outbox SET available=0")
    deliver_pending(Store(settings.db), settings, transport=transport)
    assert bodies[0] == bodies[1]
    assert bodies[0]["blocked"] is True
    assert store.get(cid)["status"] == "blocked"
    with store.connect() as db:
        assert db.execute("SELECT count(*) FROM actions").fetchone()[0] == 1


def test_shuffle_claim_is_atomic_and_lost_ack_can_retry(settings):
    store, cid = completed(settings)
    store.record_action(cid, "approve", None, "ssh", "action_unknown")
    settings.shuffle_hook = "http://shuffle/webhook_fixture"
    calls = []

    def handler(req):
        calls.append(json.loads(req.content))
        raise httpx.ReadTimeout("lost acknowledgement", request=req)

    transport = httpx.MockTransport(handler)
    with ThreadPoolExecutor(max_workers=2) as pool:
        list(pool.map(lambda _: deliver_pending(store, settings, transport=transport), range(2)))
    assert len(calls) == 1
    assert calls[0]["blocked"] is False
    assert incident_integrations(store, cid)["shuffle"][0]["status"] == "retry"


def test_shuffle_application_reject_and_redirect_not_success(settings):
    store, cid = completed(settings)
    store.record_action(cid, "approve", None, "dry-run", "dry_run")
    settings.shuffle_hook = "http://shuffle/webhook_fixture"
    deliver_pending(
        store,
        settings,
        transport=httpx.MockTransport(lambda req: httpx.Response(200, json={"success": False})),
    )
    assert incident_integrations(store, cid)["shuffle"][0]["status"] == "retry"
    with store.connect() as db:
        db.execute("UPDATE shuffle_outbox SET available=0")
    deliver_pending(
        store,
        settings,
        transport=httpx.MockTransport(lambda req: httpx.Response(302, headers={"Location": "http://other/"})),
    )
    assert incident_integrations(store, cid)["shuffle"][0]["error"] == "HTTP302"


def test_all_integrations_disabled_in_demo(settings):
    store, cid = completed(settings, ["8.8.8.8"])
    store.record_action(cid, "approve", None, "dry-run", "dry_run")
    settings.demo = True
    settings.vt_key = "key"
    settings.shuffle_hook = "http://shuffle/hook"
    transport = httpx.MockTransport(lambda req: pytest.fail("demo external I/O"))
    enrich_pending(store, settings, transport=transport)
    deliver_pending(store, settings, transport=transport)
    assert not integration_health(store, settings)["shuffle"]["active"]


def test_integration_errors_cannot_fail_analysis_tick(settings, monkeypatch):
    settings.shuffle_hook = "http://shuffle/hook"

    def fail(*args):
        raise RuntimeError("not logged")

    monkeypatch.setattr("src.service.deliver_pending", fail)
    Service(settings).tick()


def test_new_secrets_masked_in_logs_and_ui(settings):
    import logging

    settings.vt_key = "vt-secret-fixture"
    settings.shuffle_hook = "http://shuffle/api/v1/hooks/webhook_private-fixture"
    record = logging.LogRecord(
        "agentsoc.test", logging.WARNING, "", 1, settings.vt_key + " " + settings.shuffle_hook, (), None
    )
    encoded = JsonFormatter(settings).format(record)
    assert settings.vt_key not in encoded
    assert "webhook_private-fixture" not in encoded
    with TestClient(create_app(settings, worker=False)) as client:
        client.post("/api/v1/auth/login", json={"username": "admin", "password": settings.approve_key})
        health = client.get("/api/v1/system")
        assert health.status_code == 200
        assert set(health.json()["integrations"]) == {"thehive", "shuffle", "virustotal"}
        assert settings.vt_key not in health.text
        assert settings.shuffle_hook not in health.text


def test_settings_integration_env_and_validation(settings, monkeypatch):
    from src.settings import Settings

    monkeypatch.setenv("VT_KEY", "vt-key")
    monkeypatch.setenv("SHUFFLE_HOOK", "http://shuffle/api/v1/hooks/test")
    assert Settings.from_env().vt_key == "vt-key"
    with pytest.raises(ValueError):
        replace(settings, shuffle_hook="file:///etc/passwd").validate()
    with pytest.raises(ValueError):
        replace(settings, vt_interval=1).validate()
    with pytest.raises(ValueError):
        replace(settings, vt_daily_limit=501).validate()


def test_recovered_action_only_notifies_unknown_once(settings):
    store, cid = completed(settings)
    assert store.claim(cid, mode="ssh", action="approve", ip="192.168.20.50")
    with store.connect() as db:
        db.execute("UPDATE actions SET lease_until=0")
    store.recover(stale_only=True)
    store.recover(stale_only=True)
    with store.connect() as db:
        rows = db.execute("SELECT payload FROM shuffle_outbox").fetchall()
    assert len(rows) == 1
    event = json.loads(rows[0][0])
    assert event["status"] == "action_unknown"
    assert event["blocked"] is False


def test_secret_guard_includes_vt_key_and_webhook(settings):
    from src.anon import Anon
    from src.llm import LLM

    store, cid = completed(settings)
    settings.vt_key = "vt-private-fixture-value"
    settings.shuffle_hook = "http://shuffle/api/v1/hooks/webhook_private-value"
    LLM(settings, store).ask(
        Anon(),
        cid,
        "net",
        "Never echo credentials: " + settings.vt_key + " " + settings.shuffle_hook,
        [{"id": "e1", "kind": "net"}],
        ["e1"],
    )
    with store.connect() as db:
        prompt = db.execute("SELECT prompt FROM ledger ORDER BY id DESC LIMIT 1").fetchone()[0]
    assert settings.vt_key not in prompt
    assert "webhook_private-value" not in prompt


def test_pipeline_enriches_mirrors_then_notifies_only_after_approval(settings, monkeypatch):
    from src.thehive import sync_pending
    from tests.conftest import snort, windows

    settings.thehive_url, settings.thehive_key = "http://hive:9000", "hive-secret"
    settings.vt_key = "vt-secret"
    settings.shuffle_hook = "http://shuffle/api/v1/hooks/webhook_fixture"
    remote, notifications = {}, []

    def hive(req):
        if req.url.path.endswith("/query"):
            return httpx.Response(200, json=[])
        if req.method == "POST":
            remote.update(json.loads(req.content))
            return httpx.Response(201, json={"_id": "~55"})
        remote.update(json.loads(req.content))
        return httpx.Response(200, json={})

    def shuffle(req):
        notifications.append(json.loads(req.content))
        return httpx.Response(200, json={"success": True})

    monkeypatch.setattr(
        "src.service.enrich_pending",
        lambda repo, cfg: enrich_pending(
            repo, cfg, transport=httpx.MockTransport(lambda req: lookup_response())
        ),
    )
    monkeypatch.setattr(
        "src.service.sync_pending",
        lambda repo, cfg: sync_pending(repo, cfg, transport=httpx.MockTransport(hive)),
    )
    monkeypatch.setattr(
        "src.service.deliver_pending",
        lambda repo, cfg: deliver_pending(repo, cfg, transport=httpx.MockTransport(shuffle)),
    )
    with TestClient(create_app(settings, worker=False)) as client:
        login = client.post(
            "/api/v1/auth/login", json={"username": "admin", "password": settings.approve_key}
        )
        client.headers["X-CSRF-Token"] = login.json()["csrf"]
        service = client.app.state.service
        service.store.ingest(snort(src="8.8.8.8"), 0)
        service.store.ingest(windows(), 1)
        service.tick(40)
        case = service.store.cases()[0]
        assert notifications == []
        assert "malicious" in remote["description"]
        result = client.post(
            "/api/v1/incidents/" + case["id"] + "/response",
            json={"decision": "approve", "run_id": case["latest_run_id"]},
        )
        assert result.status_code == 200
        assert result.json()["status"] == "dry_run"
        service.tick()
        assert len(notifications) == 1 and not notifications[0]["blocked"]
        assert "dry_run" in remote["description"]
        detail = client.get("/api/v1/incidents/" + case["id"]).json()
        assert detail["integrations"]["thehive"]["remote_id"] == "~55"
        assert detail["integrations"]["shuffle"][0]["status"] == "delivered"


def test_synthetic_cases_do_not_queue_external_work(settings):
    store = Store(settings.db)
    cid = store.enqueue({"ips": ["8.8.8.8"], "raw_ids": [], "alerts": [], "entities": []}, settings=settings)
    with store.connect() as db:
        db.execute("UPDATE cases SET synthetic=1 WHERE id=?", (cid,))
    job = store.claim_job("fixture")
    store.complete_job(job, {"verdict": "review"}, {})
    store.record_action(cid, "approve", None, "dry-run", "dry_run")
    for table in ("thehive_sync", "vt_jobs", "shuffle_outbox"):
        with store.connect() as db:
            assert db.execute(f"SELECT count(*) FROM {table}").fetchone()[0] == 0


def test_third_party_http_logging_redacts_webhook(settings):
    import logging

    from src.logs import CredentialFilter

    settings.shuffle_hook = "http://shuffle/api/v1/hooks/webhook_private-value"
    record = logging.LogRecord(
        "httpx", logging.INFO, "", 1, "HTTP Request: POST %s", (settings.shuffle_hook,), None
    )
    assert CredentialFilter(settings).filter(record)
    assert "webhook_private-value" not in record.getMessage()


def test_shuffle_stale_sender_cannot_overwrite_delivery(settings):
    store, cid = completed(settings)
    store.record_action(cid, "approve", None, "dry-run", "dry_run")
    settings.shuffle_hook = "http://shuffle/webhook_fixture"

    def handler(req):
        with store.connect() as db:
            db.execute("UPDATE shuffle_outbox SET status='delivered',lease_until=0,delivered=123")
        return httpx.Response(503)

    deliver_pending(store, settings, transport=httpx.MockTransport(handler))
    event = incident_integrations(store, cid)["shuffle"][0]
    assert event["status"] == "delivered" and event["delivered"] == 123
    assert event["error"] is None


def test_vt_stale_sender_cannot_cache_or_overwrite_new_report(settings):
    store, cid = completed(settings, ["8.8.8.8"])
    settings.vt_key = "fixture-key"

    def handler(req):
        with store.connect() as db:
            db.execute("UPDATE vt_jobs SET lease_until=9999999999,error='new-owner'")
        return lookup_response()

    enrich_pending(store, settings, transport=httpx.MockTransport(handler))
    job = incident_integrations(store, cid)["virustotal"][0]
    assert job["report"] is None and job["error"] == "new-owner"
    with store.connect() as db:
        assert db.execute("SELECT count(*) FROM vt_cache").fetchone()[0] == 0
