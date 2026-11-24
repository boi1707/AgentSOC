import json
import threading
from concurrent.futures import ThreadPoolExecutor
from contextlib import contextmanager
from dataclasses import replace
from types import SimpleNamespace

import httpx
import pytest
from fastapi.testclient import TestClient

from src.api.main import create_app
from src.managed_response import CLAIM_SECONDS, MAX_ATTEMPTS, MODE, ClaimLost
from src.response_adapters import ManagedObservation, PermanentMutation, RetryableMutation, UnknownMutation
from src.service import Service
from src.shuffle import deliver_pending
from src.thehive import sync_pending
from tests.conftest import snort
from tests.test_assistant_control import command, signed, telegram_settings

IP = "10.100.27.10"


class Clock:
    now = 1000

    def __call__(self):
        return self.now


class SimulatedFirewall:
    identity = "tests:firewall"

    def __init__(self, clock):
        self.clock = clock
        self.table = ManagedObservation(revision=0)
        self.calls = []
        self.before = lambda _: None
        self.after = lambda _: None

    def observe(self, ip):
        assert ip == IP
        self.before("observe")
        return self.table

    def configure(self, ip, *, revision, owner, deadline):
        assert ip == IP
        self.before("block" if owner else "unblock")
        if revision != self.table.revision or self.clock() >= deadline:
            raise RetryableMutation
        self.table = replace(
            self.table,
            revision=revision + 1,
            configured=owner is not None,
            configured_owner=owner,
            applied=False,
            pending_owner=owner or self.table.configured_owner,
        )
        self.calls.append("block" if owner else "unblock")
        self.after(self.calls[-1])

    def apply(self, ip, *, revision, deadline):
        assert ip == IP
        self.before("apply")
        if revision != self.table.revision or self.clock() >= deadline:
            raise RetryableMutation
        self.table = replace(
            self.table,
            revision=revision + 1,
            applied=True,
            runtime_member=self.table.configured,
            runtime_owner=self.table.configured_owner,
            pending_owner=None,
        )
        self.calls.append("apply")
        self.after("apply")


@pytest.fixture
def lab(settings):
    settings.pfsense_block_ttl = 100
    telegram_settings(settings)
    clock = Clock()
    firewall = SimulatedFirewall(clock)
    with TestClient(
        create_app(settings, worker=False, managed_transport=firewall, managed_clock=clock)
    ) as client:
        logged_in = client.post(
            "/api/v1/auth/login", json={"username": "admin", "password": settings.approve_key}
        )
        assert logged_in.status_code == 200
        client.headers["X-CSRF-Token"] = logged_in.json()["csrf"]
        service = client.app.state.service
        yield SimpleNamespace(
            client=client,
            service=service,
            store=service.store,
            clock=clock,
            firewall=firewall,
            settings=settings,
        )


def proposal(lab, aid="e1", *, src=IP, synthetic=False, run_update=None, verdict_update=None):
    assert lab.store.ingest(snort(aid, src=src), lab.clock(), synthetic=synthetic)
    with lab.store.connect() as db:
        data = json.loads(db.execute("SELECT normalized FROM inbox WHERE id=?", (aid,)).fetchone()[0])
    incident = {"alerts": [data["evidence"]], "raw_ids": [aid], "ips": [src]}
    cid = lab.store.enqueue(incident, settings=lab.settings)
    rid = lab.store.get(cid)["latest_run_id"]
    verdict = {
        "mode": "live",
        "verdict": "attack",
        "confidence": 0.99,
        "grounded": 1,
        "block_ip": src,
        "evidence_ids": [aid],
    }
    verdict.update(verdict_update or {})
    run = {"status": "completed", "mode": "live", "replay": 0, "finished": lab.clock()}
    run.update(run_update or {})
    with lab.store.connect() as db:
        db.execute(
            "UPDATE runs SET status=?,mode=?,replay=?,finished=?,verdict=? WHERE id=?",
            (run["status"], run["mode"], run["replay"], run["finished"], json.dumps(verdict), rid),
        )
        db.execute("UPDATE jobs SET status='completed' WHERE run_id=?", (rid,))
        db.execute(
            "UPDATE cases SET status='pending',workflow_status='review',verdict=? WHERE id=?",
            (json.dumps(verdict), cid),
        )
    return cid, rid


def approve(lab, case):
    return lab.client.post(
        f"/api/v1/incidents/{case[0]}/response", json={"decision": "approve", "run_id": case[1]}
    )


def state(lab, case):
    with lab.store.connect() as db:
        lease = db.execute(
            """SELECT l.*,a.result,a.verification_status FROM managed_block_leases l
               JOIN actions a ON a.id=l.action_id WHERE l.case_id=?""",
            (case[0],),
        ).fetchone()
        return dict(lease) if lease else None


def test_transactional_approval_block_expiry_and_local_notifications(lab, monkeypatch):
    case = proposal(lab)
    queue = lab.store.managed.queue

    def abort(*args):
        queue(*args)
        raise UnknownMutation

    with monkeypatch.context() as patch:
        patch.setattr(lab.store.managed, "queue", abort)
        with pytest.raises(UnknownMutation):
            approve(lab, case)
    assert state(lab, case) is None
    assert lab.store.get(case[0])["status"] == "pending"
    with lab.store.connect() as db:
        assert db.execute("SELECT count(*) FROM actions").fetchone()[0] == 0

    result = approve(lab, case)
    assert result.json() == {
        "status": "pending_execution",
        "verification_status": "not_verified",
        "mode": MODE,
        "blocked": False,
        "simulated": True,
        "traffic_verified": False,
        "proposal_id": case[1],
    }
    assert approve(lab, case).status_code == 409
    initial = state(lab, case)
    assert initial["run_id"] == initial["proposal_id"] == case[1]
    assert initial["approved_by"] == "admin"
    assert lab.firewall.calls == []

    observed_stages = []

    def check_transport_transaction(operation):
        with lab.store.connect() as db:
            db.execute("BEGIN IMMEDIATE")
            observed_stages.append((operation, db.execute("SELECT result FROM actions").fetchone()[0]))

    lab.firewall.before = check_transport_transaction
    assert lab.service.tick_managed()
    assert ("block", "executing") in observed_stages
    assert ("apply", "configured") in observed_stages
    active = state(lab, case)
    assert active["result"] == "runtime_block_verified"
    assert active["verification_status"] == "simulated_runtime_verified"
    assert active["activated_at"] == lab.clock()
    assert active["expires_at"] == lab.clock() + 100
    detail = lab.client.get(f"/api/v1/incidents/{case[0]}").json()
    assert detail["actions"][0]["managed_expires_at"] == active["expires_at"]

    lab.clock.now = active["expires_at"] - 1
    assert not lab.service.tick_managed()
    lab.clock.now += 1
    assert lab.service.tick_managed()
    assert state(lab, case)["result"] == "runtime_unblock_verified"
    assert not lab.firewall.table.runtime_member
    assert not lab.service.tick_managed()
    assert lab.firewall.calls == ["block", "apply", "unblock", "apply"]
    with lab.store.connect() as db:
        events = db.execute(
            "SELECT payload,status FROM shuffle_outbox UNION ALL SELECT payload,status FROM notification_outbox"
        ).fetchall()
        assert {json.loads(row["payload"])["event"] for row in events} == {
            "response.completed",
            "response.expired",
            "response.unblock.completed",
        }
        for row in events:
            payload = json.loads(row["payload"])
            assert row["status"] == "local_only"
            assert payload["simulated"] and not payload["blocked"] and not payload["traffic_verified"]
        for table in ("shuffle_outbox", "notification_outbox"):
            assert not db.execute(f"SELECT 1 FROM {table} WHERE available<=?", (9e15,)).fetchone()
        assert db.execute("SELECT count(*) FROM audit WHERE action='response.managed'").fetchone()[0] >= 5
    lab.settings.shuffle_hook = "https://shuffle.invalid/endpoint"
    deliver_pending(
        lab.store, lab.settings, transport=httpx.MockTransport(lambda _: pytest.fail("simulation leaked"))
    )


def test_web_and_signed_telegram_share_the_managed_intent(lab):
    case = proposal(lab)
    with ThreadPoolExecutor() as workers:
        web = workers.submit(approve, lab, case)
        callback = workers.submit(signed, lab.client, lab.settings, command(f"/approve {case[0]} {case[1]}"))
        web_reply = web.result()
        telegram_reply = callback.result().json()
    if web_reply.status_code == 200:
        assert web_reply.json()["mode"] == MODE and telegram_reply["error"]["code"] == 409
    else:
        assert web_reply.status_code == 409 and telegram_reply["status"] == "pending_execution"
        assert telegram_reply["mode"] == MODE
    with lab.store.connect() as db:
        assert db.execute("SELECT count(*) FROM actions").fetchone()[0] == 1
        assert db.execute("SELECT count(*) FROM managed_block_leases").fetchone()[0] == 1


@pytest.mark.parametrize(
    ("options", "mutation"),
    [
        ({"synthetic": True}, None),
        ({"src": "10.100.27.11"}, None),
        ({"src": "10.8.0.1"}, None),
        ({"run_update": {"mode": "mock"}}, None),
        ({"run_update": {"replay": 1}}, None),
        ({"run_update": {"status": "running"}}, None),
        ({"run_update": {"finished": 1}}, "expire"),
        ({"verdict_update": {"mode": "mock"}}, None),
        ({"verdict_update": {"grounded": 0}}, None),
        ({"verdict_update": {"evidence_ids": ["not-cited"]}}, None),
        ({}, "legacy"),
        ({}, "untrusted-alert"),
        ({}, "disabled-user"),
        ({}, "demo"),
    ],
)
def test_ineligible_or_unauthorized_cannot_create_intent(lab, options, mutation):
    case = proposal(lab, **options)
    if mutation == "demo":
        lab.settings.demo = True
        # A worker with simulation unavailable cannot claim a managed action directly.
        assert not lab.store.managed.accepting
        with pytest.raises(ValueError):
            Service(lab.settings, managed_transport=lab.firewall)
        assert approve(lab, case).json().get("mode") != MODE
    else:
        with lab.store.connect() as db:
            if mutation == "expire":
                lab.clock.now = lab.settings.proposal_ttl + 1
            elif mutation == "legacy":
                db.execute("UPDATE cases SET provenance='legacy_unknown' WHERE id=?", (case[0],))
            elif mutation == "untrusted-alert":
                db.execute("UPDATE inbox SET provenance='legacy_unknown' WHERE id='e1'")
            elif mutation == "disabled-user":
                db.execute("UPDATE users SET disabled=1 WHERE username='admin'")
        assert approve(lab, case).status_code in {400, 401, 403, 409}
    assert state(lab, case) is None
    assert lab.firewall.calls == []


def test_overlapping_leases_and_unmanaged_membership(lab):
    first = proposal(lab)
    assert approve(lab, first).status_code == 200
    assert lab.service.tick_managed()
    lab.clock.now += 40
    second = proposal(lab, "e2")
    assert approve(lab, second).status_code == 200
    assert lab.service.tick_managed()
    assert state(lab, first)["ownership_marker"] == state(lab, second)["ownership_marker"]
    lab.clock.now += 60
    assert lab.service.tick_managed()
    assert state(lab, first)["result"] == "unblock_retained"
    assert lab.firewall.calls == ["block", "apply"]
    lab.clock.now += 40
    assert lab.service.tick_managed()
    assert lab.firewall.calls == ["block", "apply", "unblock", "apply"]
    lab.firewall.table = ManagedObservation(revision=9, configured=True, runtime_member=True)
    third = proposal(lab, "e3")
    assert approve(lab, third).status_code == 200
    assert lab.service.tick_managed()
    assert state(lab, third)["ownership"] == "external"
    lab.clock.now += 100
    assert lab.service.tick_managed()
    assert state(lab, third)["result"] == "unblock_retained"
    assert lab.firewall.table.runtime_member
    assert len(lab.firewall.calls) == 4


@pytest.mark.parametrize("where", ["block", "apply", "unblock"])
def test_timeout_after_side_effect_reconciles_without_repeating_mutation(lab, where):
    case = proposal(lab)
    assert approve(lab, case).status_code == 200
    if where == "unblock":
        assert lab.service.tick_managed()
        lab.clock.now += 100

    def lose_ack(operation):
        if operation == where:
            raise TimeoutError("do not log transport credentials")

    lab.firewall.after = lose_ack
    assert lab.service.tick_managed()
    uncertain = state(lab, case)
    assert uncertain["last_error"] == "action_unknown"
    assert uncertain["result"] == ("unblock_pending" if where == "unblock" else "action_unknown")
    lab.firewall.after = lambda _: None
    lab.clock.now = uncertain["next_retry_at"]
    assert lab.service.tick_managed()
    assert lab.firewall.calls.count(where) == 1
    assert state(lab, case)["result"] == (
        "runtime_unblock_verified" if where == "unblock" else "runtime_block_verified"
    )


def test_restart_and_concurrent_worker_cannot_steal_active_work(lab):
    class SimulatedCrash(BaseException):
        pass

    case = proposal(lab)
    assert approve(lab, case).status_code == 200
    restarted = Service(lab.settings, managed_transport=lab.firewall, managed_clock=lab.clock)
    entered = threading.Event()
    release = threading.Event()

    def crash_after_write(operation):
        if operation == "block":
            entered.set()
            assert release.wait(5)
            raise SimulatedCrash

    lab.firewall.after = crash_after_write
    with ThreadPoolExecutor() as executor:
        first = executor.submit(lab.service.tick_managed)
        try:
            assert entered.wait(5)
            lab.clock.now += CLAIM_SECONDS
            assert not restarted.tick_managed()
        finally:
            release.set()
        with pytest.raises(SimulatedCrash):
            first.result()
    restarted.store.recover(stale_only=True)
    assert state(lab, case)["execution_owner"]
    lab.firewall.after = lambda _: None
    assert restarted.tick_managed()
    assert lab.firewall.calls == ["block", "apply"]
    assert state(lab, case)["result"] == "runtime_block_verified"


def test_disabled_or_expired_execution_never_starts_block_and_active_leases_are_cleaned(lab):
    first = proposal(lab)
    assert approve(lab, first).status_code == 200
    assert lab.service.tick_managed()
    second = proposal(lab, "e2")
    assert approve(lab, second).status_code == 200
    lab.store.managed.enabled = False
    assert lab.service.tick_managed()
    assert state(lab, second)["result"] == "block_failed"
    assert state(lab, second)["last_error"] == "execution_disabled"
    lab.clock.now += 100
    assert lab.service.tick_managed()
    assert state(lab, first)["result"] == "runtime_unblock_verified"
    lab.store.managed.enabled = True
    third = proposal(lab, "e3")
    assert approve(lab, third).status_code == 200
    lab.clock.now += 300
    assert lab.service.tick_managed()
    assert state(lab, third)["last_error"] == "activation_expired"
    assert lab.firewall.calls == ["block", "apply", "unblock", "apply"]


@pytest.mark.parametrize("error", [RetryableMutation, PermanentMutation])
def test_overdue_cleanup_fails_closed_with_bounded_retries(lab, error, capsys):
    case = proposal(lab)
    assert approve(lab, case).status_code == 200
    assert lab.service.tick_managed()
    lab.clock.now += 100

    def fail(operation):
        if operation == "unblock":
            raise error("credential fixture must not escape")

    lab.firewall.before = fail
    expected_attempts = 1 if error is PermanentMutation else MAX_ATTEMPTS
    for attempt in range(expected_attempts):
        assert lab.service.tick_managed()
        lease = state(lab, case)
        assert lease["attempts"] == attempt + 1
        if lease["next_retry_at"] >= 0:
            lab.clock.now = lease["next_retry_at"]
    assert lease["result"] == "unblock_failed"
    assert lease["observed_state"] == "unknown"
    assert lab.firewall.table.runtime_member
    assert not lab.service.tick_managed()
    assert "credential fixture" not in json.dumps(lease) + capsys.readouterr().out


def test_unexpected_configured_runtime_mismatch_is_never_modified(lab):
    case = proposal(lab)
    assert approve(lab, case).status_code == 200
    lab.firewall.table = ManagedObservation(
        revision=1, configured=True, applied=False, pending_owner="external"
    )
    assert lab.service.tick_managed()
    assert not lab.firewall.calls
    assert state(lab, case)["result"] == "block_failed"
    assert state(lab, case)["last_error"] == "unexpected_firewall_state"


def test_expired_uncertain_activation_cleans_only_its_owned_configuration(lab):
    case = proposal(lab)
    assert approve(lab, case).status_code == 200

    def lose_config_ack(operation):
        if operation == "block":
            raise UnknownMutation

    lab.firewall.after = lose_config_ack
    assert lab.service.tick_managed()
    assert lab.firewall.table.configured and not lab.firewall.table.runtime_member
    assert state(lab, case)["result"] == "action_unknown"
    lab.clock.now = state(lab, case)["activation_deadline"]
    lab.firewall.after = lambda _: None
    assert lab.service.tick_managed()
    assert state(lab, case)["result"] == "runtime_unblock_verified"
    assert state(lab, case)["activated_at"] is None
    assert lab.firewall.calls == ["block", "unblock", "apply"]


def test_revoked_approval_before_execution_cancels_intent(lab):
    case = proposal(lab)
    assert approve(lab, case).status_code == 200
    with lab.store.connect() as db:
        db.execute("UPDATE users SET disabled=1 WHERE username='admin'")
    assert lab.service.tick_managed()
    assert state(lab, case)["last_error"] == "eligibility_changed"
    assert lab.firewall.calls == []


def test_cleanup_ticks_while_analysis_lane_is_busy(lab):
    case = proposal(lab)
    assert approve(lab, case).status_code == 200
    assert lab.service.tick_managed()
    lab.clock.now = state(lab, case)["expires_at"]
    with lab.service.lock:
        assert lab.service.tick_managed()
    assert state(lab, case)["result"] == "runtime_unblock_verified"


def test_default_firewall_ttl_starts_at_first_possible_mutation(lab):
    lab.settings.pfsense_block_ttl = 86_400
    case = proposal(lab)
    assert approve(lab, case).status_code == 200
    lab.clock.now += 30
    assert lab.service.tick_managed()
    lease = state(lab, case)
    assert lease["created_at"] + 30 == lease["activated_at"]
    assert lease["expires_at"] == lease["activated_at"] + 86_400


def test_delayed_verification_does_not_extend_firewall_ttl(lab):
    case = proposal(lab)
    assert approve(lab, case).status_code == 200

    def lose_ack(operation):
        if operation == "apply":
            raise TimeoutError

    lab.firewall.after = lose_ack
    assert lab.service.tick_managed()
    requested_at = state(lab, case)["block_requested_at"]
    lab.clock.now += 45
    lab.firewall.after = lambda _: None
    assert lab.service.tick_managed()
    lease = state(lab, case)
    assert lease["activated_at"] == requested_at + 45
    assert lease["expires_at"] == requested_at + 100
    assert lab.firewall.calls == ["block", "apply"]
    lab.clock.now = lease["expires_at"]
    assert lab.service.tick_managed()
    assert state(lab, case)["result"] == "runtime_unblock_verified"


def test_first_possible_mutation_caps_uncertain_activation_even_before_proposal_deadline(lab):
    lab.settings.pfsense_block_ttl = 15
    case = proposal(lab)
    assert approve(lab, case).status_code == 200

    def lose_ack(operation):
        if operation == "apply":
            raise TimeoutError

    lab.firewall.after = lose_ack
    assert lab.service.tick_managed()
    lease = state(lab, case)
    assert lab.firewall.table.runtime_member
    lab.clock.now = lease["block_requested_at"] + 15
    assert lab.clock.now < lease["activation_deadline"]
    lab.firewall.after = lambda _: None
    assert lab.service.tick_managed()
    assert state(lab, case)["activated_at"] is None
    assert state(lab, case)["result"] == "runtime_unblock_verified"


def test_draft_v3_active_lease_without_mutation_timestamp_is_capped_on_restart(lab):
    case = proposal(lab)
    assert approve(lab, case).status_code == 200
    lab.clock.now += 20
    assert lab.service.tick_managed()
    with lab.store.connect() as db:
        db.execute("UPDATE managed_block_leases SET block_requested_at=NULL")
    restarted = Service(lab.settings, managed_transport=lab.firewall, managed_clock=lab.clock)
    lease = state(lab, case)
    assert lease["block_requested_at"] == lease["created_at"]
    lab.clock.now = lease["created_at"] + 100
    assert lab.clock.now < lease["expires_at"]
    detail = lab.client.get(f"/api/v1/incidents/{case[0]}").json()
    assert detail["actions"][0]["managed_expires_at"] == lab.clock.now
    assert restarted.tick_managed()
    assert state(lab, case)["result"] == "runtime_unblock_verified"


def test_expired_and_replaced_claim_cannot_finalize_or_mutate(lab):
    case = proposal(lab)
    assert approve(lab, case).status_code == 200
    worker = lab.store.managed
    first = worker.claim()
    lab.clock.now = first["execution_lease_until"]
    with pytest.raises(ClaimLost):
        worker.failure(first, "action_unknown")
    second = worker.claim()
    assert second["execution_owner"] != first["execution_owner"]
    with pytest.raises(ClaimLost):
        worker.activate(first)
    with pytest.raises(ClaimLost):
        worker.failure(first, "action_unknown")
    assert lab.firewall.calls == []
    assert state(lab, case)["execution_owner"] == second["execution_owner"]
    worker.activate(second)
    assert state(lab, case)["result"] == "runtime_block_verified"


@pytest.mark.parametrize("alteration", ["alias", "external_change", "pending_changes"])
def test_unexpected_alias_state_prevents_further_writes_after_configure(lab, alteration):
    case = proposal(lab)
    assert approve(lab, case).status_code == 200

    def drift(operation):
        if operation == "block":
            changes = {
                "alias": {"alias_identity": "replaced-alias"},
                "external_change": {"unexpected_changes": True},
                "pending_changes": {"pending_owner": "external"},
            }[alteration]
            lab.firewall.table = replace(lab.firewall.table, **changes)

    lab.firewall.after = drift
    assert lab.service.tick_managed()
    assert lab.firewall.calls == ["block"]
    assert state(lab, case)["desired_state"] == "absent"
    assert lab.service.tick_managed()
    assert state(lab, case)["result"] == "unblock_failed"
    assert state(lab, case)["last_error"] == "unexpected_firewall_state"
    assert lab.firewall.calls == ["block"]


def test_runtime_mismatch_does_not_generate_success_or_repeat_apply(lab):
    case = proposal(lab)
    assert approve(lab, case).status_code == 200

    def bad_runtime(operation):
        if operation == "apply":
            lab.firewall.table = replace(lab.firewall.table, runtime_member=False, runtime_owner=None)

    lab.firewall.after = bad_runtime
    assert lab.service.tick_managed()
    assert state(lab, case)["result"] == "action_unknown"
    lab.clock.now = state(lab, case)["next_retry_at"]
    assert lab.service.tick_managed()
    assert lab.firewall.calls == ["block", "apply"]
    with lab.store.connect() as db:
        assert db.execute("SELECT count(*) FROM shuffle_outbox").fetchone()[0] == 0


def test_apply_failure_cleans_only_the_staged_edit(lab):
    case = proposal(lab)
    assert approve(lab, case).status_code == 200

    def fail_activation_apply(operation):
        if operation == "apply":
            raise PermanentMutation

    lab.firewall.before = fail_activation_apply
    assert lab.service.tick_managed()
    assert state(lab, case)["desired_state"] == "absent"
    assert lab.firewall.table.configured and not lab.firewall.table.runtime_member
    lab.firewall.before = lambda _: None
    assert lab.service.tick_managed()
    assert state(lab, case)["result"] == "runtime_unblock_verified"
    assert lab.firewall.calls == ["block", "unblock", "apply"]


def test_shuffle_quarantines_requeued_simulation_payload(lab):
    case = proposal(lab)
    assert approve(lab, case).status_code == 200
    assert lab.service.tick_managed()
    with lab.store.connect() as db:
        db.execute("UPDATE shuffle_outbox SET status='pending', available=0")
    lab.settings.shuffle_hook = "https://shuffle.invalid/endpoint"
    deliver_pending(
        lab.store, lab.settings, transport=httpx.MockTransport(lambda _: pytest.fail("simulation leaked"))
    )
    with lab.store.connect() as db:
        assert db.execute("SELECT status FROM shuffle_outbox").fetchone()[0] == "local_only"


def test_legacy_telegram_notifier_ignores_simulation(lab, monkeypatch):
    case = proposal(lab)
    lab.settings.tg_token = "fixture-telegram-token"
    lab.settings.tg_chat = "fixture-chat"
    monkeypatch.setattr(httpx, "post", lambda *args, **kwargs: pytest.fail("simulation leaked"))
    lab.service.notify(case[0], {"verdict": "attack"})


def test_thehive_snapshot_cannot_publish_simulation_after_sync_claim(lab, monkeypatch):
    case = proposal(lab)
    lab.settings.thehive_url = "https://thehive.invalid"
    lab.settings.thehive_key = "fixture-hive-key"
    with lab.store.connect() as db:
        db.execute("INSERT INTO thehive_sync(case_id) VALUES(?)", (case[0],))
    connect = lab.store.connect
    raced = False

    @contextmanager
    def interleave_approval():
        nonlocal raced
        with connect() as db:
            yield db
        if not raced:
            raced = True
            assert approve(lab, case).status_code == 200
            assert lab.service.tick_managed()

    monkeypatch.setattr(lab.store, "connect", interleave_approval)

    def hive(request):
        if request.url.path.endswith("/query"):
            return httpx.Response(200, json=[])
        assert json.loads(json.loads(request.content)["description"].split("\n\n")[-1])["status"] == "pending"
        return httpx.Response(201, json={"_id": "fixture-remote"})

    sync_pending(lab.store, lab.settings, transport=httpx.MockTransport(hive))
    assert raced and state(lab, case)["result"] == "runtime_block_verified"
