import io
import json
import sqlite3
import subprocess
import sys
import tarfile
import time
from concurrent.futures import ThreadPoolExecutor

import httpx
import pytest

from src.incident import Grouper
from src.integrations import incident_integrations, integration_health
from src.storage import Store
from src.thehive import sync_pending
from src.virustotal import enrich_pending, sha256_values
from tests.test_external_integrations import lookup_response
from tests.test_sysmon_evidence import HASH, sysmon


def completed_hash(settings, value=HASH):
    store = Store(settings.db)
    alert = sysmon(aid="hash-" + str(time.time_ns()), hashes="MD5=" + "1" * 32 + ",SHA256=" + value)
    store.ingest(alert, 0)
    group = Grouper()
    group.add(alert, 0)
    cid = store.enqueue(group.ready(31)[0], settings=settings)
    job = store.claim_job("hash-fixture")
    store.complete_job(job, {"verdict": "review", "confidence": 0.6, "reason": "fixture"}, {})
    settings.vt_key = "vt-fixture-not-a-live-secret"
    settings.vt_sha256_enabled = True
    return store, cid


@pytest.mark.parametrize(
    "value", ["0" * 63, "z" * 64, "a" * 65, "a" * 64 + "g", "a" * 128, "../../secret", "", "a" * 32]
)
def test_invalid_sha256_never_queues_or_requests(settings, value):
    assert sha256_values([{"hashes": "SHA256=" + value}]) == []
    store, cid = completed_hash(settings, value)
    assert not incident_integrations(store, cid)["virustotal_hashes"]
    enrich_pending(
        store, settings, transport=httpx.MockTransport(lambda req: pytest.fail("Invalid hash egress"))
    )


def test_hash_deduplication_and_supported_field_formats():
    assert sha256_values([{"hashes": "SHA256=" + HASH.upper()}, {"hashes": HASH}, {"sha256": HASH}]) == [HASH]
    assert sha256_values([{"hashes": {"SHA256": HASH}}]) == []
    assert len(sha256_values([{"sha256": str(n) * 64} for n in range(5)])) == 3


def test_file_report_is_get_only_and_cached_across_restart(settings):
    store, cid = completed_hash(settings)
    calls = []

    def handle(req):
        calls.append(req)
        assert req.method == "GET" and not req.content
        assert req.url == "https://www.virustotal.com/api/v3/files/" + HASH
        assert req.headers["x-apikey"] == settings.vt_key
        return lookup_response()

    transport = httpx.MockTransport(handle)
    enrich_pending(store, settings, transport=transport)
    entry = incident_integrations(store, cid)["virustotal_hashes"][0]
    assert entry["sha256"] == HASH and entry["indicator_type"] == "sha256"
    assert entry["report"]["indicator_type"] == "sha256" and entry["report"]["stats"]["malicious"] == 2
    assert "irrelevant_sensitive_field" not in json.dumps(entry)
    restarted, other = completed_hash(settings)
    enrich_pending(restarted, settings, transport=transport)
    assert (
        len(calls) == 1
        and incident_integrations(restarted, other)["virustotal_hashes"][0]["status"] == "complete"
    )
    with store.connect() as db:
        assert db.execute("SELECT expires FROM vt_hash_cache").fetchone()[0] > time.time() + 86300
        assert db.execute("SELECT count FROM vt_budget").fetchone()[0] == 1


def test_sha256_opt_in_demo_and_synthetic_safety(settings):
    store, cid = completed_hash(settings)
    transport = httpx.MockTransport(lambda req: pytest.fail("Disabled/synthetic lookup must not send"))
    settings.vt_sha256_enabled = False
    enrich_pending(store, settings, transport=transport)
    assert not integration_health(store, settings)["virustotal"]["sha256_enabled"]
    settings.vt_sha256_enabled, settings.demo = True, True
    enrich_pending(store, settings, transport=transport)
    settings.demo = False
    with store.connect() as db:
        db.execute("UPDATE cases SET synthetic=1 WHERE id=?", (cid,))
    enrich_pending(store, settings, transport=transport)
    assert incident_integrations(store, cid)["virustotal_hashes"][0]["status"] == "skipped"


def test_ip_and_sha256_share_persistent_interval_and_daily_limit(settings):
    store, cid = completed_hash(settings)
    settings.vt_daily_limit = 1
    with store.connect() as db:
        db.execute("INSERT INTO vt_jobs(case_id,ip) VALUES(?,?)", (cid, "8.8.8.8"))
    calls = []
    transport = httpx.MockTransport(lambda req: calls.append(req) or lookup_response())
    enrich_pending(store, settings, transport=transport)
    enrich_pending(Store(settings.db), settings, transport=transport)
    assert len(calls) == 1 and "/ip_addresses/" in calls[0].url.path
    with store.connect() as db:
        assert db.execute("SELECT next_at FROM vt_budget").fetchone()[0] > time.time()
        db.execute("UPDATE vt_budget SET next_at=0")
        db.execute("UPDATE vt_hash_jobs SET available=0")
    enrich_pending(store, settings, transport=transport)
    assert len(calls) == 1  # Resetting interval cannot reset the durable daily counter.
    settings.vt_daily_limit = 2
    with store.connect() as db:
        db.execute("UPDATE vt_budget SET next_at=0")
        db.execute("UPDATE vt_hash_jobs SET available=0")
    enrich_pending(store, settings, transport=transport)
    assert len(calls) == 2 and "/files/" in calls[1].url.path
    with store.connect() as db:
        assert db.execute("SELECT count FROM vt_budget").fetchone()[0] == 2


@pytest.mark.parametrize("status", [401, 403, 404, 429, 503])
def test_file_failures_preserve_incident_and_do_not_mean_safe(settings, status):
    store, cid = completed_hash(settings)
    before = store.get(cid)
    calls = []

    def handle(req):
        calls.append(req)
        return httpx.Response(
            status, text="PRIVATE RESPONSE BODY " + settings.vt_key, headers={"Retry-After": "120"}
        )

    transport = httpx.MockTransport(handle)
    enrich_pending(store, settings, transport=transport)
    entry = incident_integrations(store, cid)["virustotal_hashes"][0]
    assert store.get(cid) == before
    if status == 404:
        assert entry["status"] == "complete" and entry["report"]["status"] == "not_found"
        assert "stats" not in entry["report"]
    else:
        assert entry["status"] == "retry" and entry["error"] == "HTTP" + str(status)
        assert "PRIVATE RESPONSE" not in json.dumps(entry) and settings.vt_key not in json.dumps(entry)
        if status in (401, 403, 429):
            with store.connect() as db:
                db.execute("INSERT INTO vt_jobs(case_id,ip) VALUES(?,?)", (cid, "8.8.8.8"))
            enrich_pending(store, settings, transport=transport)
            assert len(calls) == 1  # Hash rate-limit/auth failure also cools down IP lookups.


def test_hash_sender_claim_and_stale_lease_fencing(settings):
    store, cid = completed_hash(settings)
    calls = []

    def handler(req):
        calls.append(req)
        with store.connect() as db:
            db.execute("UPDATE vt_hash_jobs SET lease_until=9999999999,error='new-owner'")
        return lookup_response()

    transport = httpx.MockTransport(handler)
    with ThreadPoolExecutor(max_workers=2) as pool:
        list(pool.map(lambda _: enrich_pending(store, settings, transport=transport), range(2)))
    assert len(calls) == 1
    entry = incident_integrations(store, cid)["virustotal_hashes"][0]
    assert entry["report"] is None and entry["error"] == "new-owner"
    with store.connect() as db:
        assert db.execute("SELECT count(*) FROM vt_hash_cache").fetchone()[0] == 0


def test_malformed_hash_report_retries_and_expired_cache_is_refreshed(settings):
    store, cid = completed_hash(settings)
    before = store.get(cid)
    enrich_pending(
        store, settings, transport=httpx.MockTransport(lambda req: httpx.Response(200, json={"data": {}}))
    )
    assert incident_integrations(store, cid)["virustotal_hashes"][0]["error"] == "KeyError"
    assert store.get(cid) == before
    with store.connect() as db:
        db.execute("UPDATE vt_hash_jobs SET available=0")
        db.execute("UPDATE vt_budget SET next_at=0")
    enrich_pending(store, settings, transport=httpx.MockTransport(lambda req: lookup_response()))
    other_store, other = completed_hash(settings)
    with store.connect() as db:
        db.execute("UPDATE vt_hash_cache SET expires=0")
        db.execute("UPDATE vt_budget SET next_at=0")
    calls = []
    enrich_pending(
        other_store,
        settings,
        transport=httpx.MockTransport(lambda req: calls.append(req) or lookup_response()),
    )
    assert (
        len(calls) == 1
        and incident_integrations(store, other)["virustotal_hashes"][0]["status"] == "complete"
    )


def test_file_reputation_is_distinct_in_thehive_and_authenticated_api(console, settings):
    store, cid = completed_hash(settings)
    enrich_pending(store, settings, transport=httpx.MockTransport(lambda req: lookup_response()))
    settings.thehive_url, settings.thehive_key = "https://hive.invalid", "hive-fixture-key"
    bodies = []

    def hive(req):
        if req.url.path.endswith("/query"):
            return httpx.Response(200, json=[])
        bodies.append(json.loads(req.content))
        return httpx.Response(201 if req.method == "POST" else 200, json={"_id": "~file42"})

    sync_pending(store, settings, transport=httpx.MockTransport(hive))
    mirror = json.loads(bodies[0]["description"].split("\n\n", 1)[1])
    assert mirror["virustotal"] == [] and mirror["virustotal_hashes"][0]["sha256"] == HASH
    detail = console.get("/api/v1/incidents/" + cid).json()
    assert detail["integrations"]["virustotal_hashes"][0]["indicator_type"] == "sha256"
    assert detail["integrations"]["virustotal"] == []


def test_v3_upgrade_preserves_existing_ip_budget_and_historical_records(tmp_path):
    root = tmp_path / "historical"
    root.mkdir()
    with tarfile.open(
        fileobj=io.BytesIO(subprocess.check_output(["git", "archive", "24d371b", "src"]))
    ) as archive:
        archive.extractall(root, filter="data")
    path = tmp_path / "v3.db"
    subprocess.run(
        [sys.executable, "-c", "from src.storage import Store; import sys; Store(sys.argv[1])", str(path)],
        cwd=root,
        check=True,
    )
    with sqlite3.connect(path) as db:
        db.execute("INSERT INTO vt_budget VALUES(1,'2026-11-26',17,12345)")
        db.execute("INSERT INTO vt_jobs(case_id,ip) VALUES('legacy','8.8.8.8')")
        db.execute("INSERT INTO vt_cache VALUES('8.8.8.8','{}',12345)")
    store = Store(path)
    Store(path)
    with store.connect() as db:
        assert db.execute("SELECT * FROM vt_budget").fetchone()[:] == (1, "2026-11-26", 17, 12345)
        assert db.execute("SELECT ip,status FROM vt_jobs").fetchone()[:] == ("8.8.8.8", "pending")
        assert db.execute("SELECT count(*) FROM vt_cache").fetchone()[0] == 1
        assert db.execute("SELECT count(*) FROM vt_hash_jobs").fetchone()[0] == 0
        assert {r[0] for r in db.execute("SELECT version FROM schema_migrations")} == {1, 2, 3, 4, 5}
