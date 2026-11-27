"""Local ASGI/SQLite with simulated Shuffle and Telegram HTTP. No live deliveries."""

import json
import time
from concurrent.futures import ThreadPoolExecutor

import httpx
import pytest

from integrations.shuffle.agentsoc_bridge import (
    DeliveryLedger,
    notification_requests,
    trusted_callback_request,
)
from src.shuffle import deliver_pending
from src.storage import Store
from src.thehive import sync_pending
from tests.test_upgrade import incident

INGRESS_SECRET = "lab-telegram-ingress-not-a-real-secret"


@pytest.fixture
def flow(console, settings, tmp_path, monkeypatch):
    case = incident(console)
    settings.shuffle_callback_secret = "lab-signing-" + "s" * 32
    settings.telegram_users = {"123": "admin", "456": "second"}
    settings.telegram_notify_chats = ("111", "222")
    settings.shuffle_hook = "https://shuffle.invalid/lab"
    assert (
        console.post(
            "/api/v1/users", json={"username": "second", "password": "p" * 24, "role": "approver"}
        ).status_code
        == 201
    )

    def forbidden(*args, **kwargs):
        pytest.fail("Dry-run must not execute SSH, pfSense, or shell commands")

    monkeypatch.setattr("src.response.subprocess.run", forbidden)
    monkeypatch.setattr("src.response_adapters.PfSenseAdapter.block", forbidden)
    monkeypatch.setattr("src.response_adapters.PfSenseAdapter.remove", forbidden)
    service = console.app.state.service
    service.notify(case["id"], case["verdict"])
    return console, settings, case, service, DeliveryLedger(tmp_path / "shuffle-delivery.db")


def update(case, *, action="a", sender=123, sequence=1):
    return {
        "update_id": sequence,
        "callback_query": {
            "id": "callback-" + str(sequence),
            "from": {"id": sender},
            "data": "as:" + action + ":" + case["latest_run_id"],
            "message": {
                "from": {"id": 999, "is_bot": True},
                "chat": {"id": 111},
                "text": "Untrusted message text must not determine operator identity or proposal",
            },
        },
    }


def callback(flow, telegram_update, *, timestamp=None, headers=None):
    client, settings, *_ = flow
    prepared = trusted_callback_request(
        headers if headers is not None else {"X-Telegram-Bot-Api-Secret-Token": INGRESS_SECRET},
        telegram_update,
        INGRESS_SECRET,
        settings.shuffle_callback_secret,
        now=timestamp,
    )
    return client.post(
        "/api/v1/integrations/telegram", content=prepared["body"].encode(), headers=prepared["headers"]
    )


def assert_single_decision(flow, expected="dry_run", actor=None):
    client, settings, case, service, _ = flow
    assert settings.response_mode == "dry-run"
    detail = client.get("/api/v1/incidents/" + case["id"]).json()
    assert detail["status"] == expected and detail["proposal"]["status"] == expected
    assert len(detail["actions"]) == 1
    action = detail["actions"][0]
    assert action["mode"] == "dry-run" and action["verification_status"] == "not_verified"
    if actor:
        assert action["actor"] == actor
    with service.store.connect() as db:
        assert (
            db.execute(
                "SELECT count(*) FROM audit WHERE action IN ('response.approve','response.reject') AND result='claimed'"
            ).fetchone()[0]
            == 1
        )
        assert (
            db.execute(
                "SELECT actor FROM audit WHERE action IN ('response.approve','response.reject') AND result='claimed'"
            ).fetchone()[0]
            == action["actor"]
        )
        rows = db.execute("SELECT payload FROM shuffle_outbox").fetchall()
        assert len(rows) == 1 and json.loads(rows[0][0])["blocked"] is False


@pytest.mark.parametrize(("decision", "expected"), [("a", "dry_run"), ("i", "rejected")])
def test_signed_decision_updates_same_thehive_case_after_restart(flow, decision, expected):
    _, settings, case, service, _ = flow
    settings.thehive_url = "https://thehive.invalid"
    settings.thehive_key = "h" * 32
    writes = []
    reject_next_patch = False

    def thehive(request):
        nonlocal reject_next_patch
        if request.url.path == "/api/v1/query":
            return httpx.Response(200, json=[])
        description = json.loads(request.content)["description"]
        writes.append((request.method, request.url.path, json.loads(description.split("\n", 1)[1])))
        if request.method == "PATCH" and reject_next_patch:
            reject_next_patch = False
            return httpx.Response(503)
        return (
            httpx.Response(201, json={"_id": "~fixture-42"})
            if request.method == "POST"
            else httpx.Response(204)
        )

    transport = httpx.MockTransport(thehive)
    sync_pending(service.store, settings, transport=transport)
    assert writes[0][:2] == ("POST", "/api/v1/case")
    event = update(case, action=decision)
    result = callback(flow, event)
    assert result.status_code == 200 and result.json()["status"] == expected
    assert callback(flow, event).status_code == 200
    assert_single_decision(flow, expected, actor="admin")
    reject_next_patch = True
    sync_pending(service.store, settings, transport=transport)
    assert writes[-1][:2] == ("PATCH", "/api/v1/case/~fixture-42") and not reject_next_patch
    restarted = Store(settings.db)
    with restarted.connect() as db:
        (pending,) = db.execute("SELECT remote_id,error FROM thehive_sync WHERE case_id=?", (case["id"],))
        assert pending["remote_id"] == "~fixture-42" and pending["error"] == "HTTP503"
        db.execute("UPDATE thehive_sync SET available=0 WHERE case_id=?", (case["id"],))
        (entry,) = db.execute("SELECT action,ip,result FROM actions WHERE case_id=?", (case["id"],))
        assert entry["result"] == expected
        if decision == "i":
            assert entry["action"] == "reject" and entry["ip"] is None
    sync_pending(restarted, settings, transport=transport)
    assert sum(method == "POST" for method, _, _ in writes) == 1
    method, path, mirror = writes[-1]
    assert (method, path) == ("PATCH", "/api/v1/case/~fixture-42")
    assert mirror["agentsoc_case_id"] == case["id"] and mirror["status"] == expected
    assert set(mirror["evidence_ids"]) == set(case["incident"]["raw_ids"])
    with restarted.connect() as db:
        assert (
            db.execute("SELECT error FROM thehive_sync WHERE case_id=?", (case["id"],)).fetchone()[0] is None
        )


def test_proactive_two_chat_inline_buttons_and_signed_approval_round_trip(flow):
    client, settings, case, service, ledger = flow
    sent = []

    def telegram(req):
        body = json.loads(req.content)
        assert "parse_mode" not in body
        if "reply_markup" in body:
            for field in (
                "Severity:",
                "Source:",
                "Explanation (AI):",
                "Evidence:",
                case["id"],
                case["latest_run_id"],
            ):
                assert field in body["text"]
            buttons = body["reply_markup"]["inline_keyboard"][0]
            assert [b["text"] for b in buttons] == ["Approve", "Ignore"]
            assert all(len(b["callback_data"].encode()) <= 64 for b in buttons)
        else:
            assert "Result: dry_run" in body["text"]
            assert "Blocked: False" in body["text"] and "Mode: dry-run" in body["text"]
        sent.append(body)
        return httpx.Response(200, json={"ok": True, "result": {"message_id": len(sent)}})

    def shuffle(req):
        event = json.loads(req.content)
        with httpx.Client(transport=httpx.MockTransport(telegram)) as transport:
            for delivery in notification_requests(event):
                token = ledger.claim(delivery["event_id"], delivery["chat_id"])
                if token:
                    result = transport.post(
                        "https://telegram.invalid/sendMessage", json=delivery["body"]
                    ).json()
                    assert ledger.finish(
                        delivery["event_id"],
                        delivery["chat_id"],
                        token,
                        "delivered",
                        message_id=result["result"]["message_id"],
                    )
        return httpx.Response(200, json={"success": True})

    deliver_pending(service.store, settings, transport=httpx.MockTransport(shuffle))
    deliver_pending(service.store, settings, transport=httpx.MockTransport(shuffle))
    assert [s["chat_id"] for s in sent] == ["111", "222"]
    with service.store.connect() as db:
        legacy_event = json.loads(db.execute("SELECT payload FROM notification_outbox").fetchone()[0])
    legacy_event["proposal"]["run_id"] = None
    assert all("reply_markup" not in d["body"] for d in notification_requests(legacy_event))
    assert client.get("/api/v1/incidents/" + case["id"]).json()["actions"] == []
    result = callback(flow, update(case)).json()
    assert result["status"] == "dry_run" and result["blocked"] is False
    assert result["verification_status"] == "not_verified"
    assert_single_decision(flow, actor="admin")
    deliver_pending(service.store, settings, transport=httpx.MockTransport(shuffle))
    deliver_pending(service.store, settings, transport=httpx.MockTransport(shuffle))
    assert [s["chat_id"] for s in sent] == ["111", "222", "111", "222"]
    assert sum("Result: dry_run" in s["text"] for s in sent) == 2
    assert_single_decision(flow, actor="admin")
    # Telegram reads the same authoritative proposal/result as Web.
    read = {
        "update_id": 2,
        "message": {"from": {"id": 123}, "chat": {"id": 111}, "text": "/incident " + case["id"]},
    }
    assert callback(flow, read).json()["facts"][0]["proposal"]["status"] == "dry_run"


@pytest.mark.parametrize("sender", [999, 111])
def test_unknown_and_notification_only_identity_cannot_approve(flow, sender):
    result = callback(flow, update(flow[2], sender=sender))
    assert result.status_code == 403
    assert flow[3].store.get(flow[2]["id"])["status"] == "pending"


def test_mapped_viewer_cannot_approve_even_with_live_llm_mode(flow):
    client, settings, case, *_ = flow
    client.post("/api/v1/users", json={"username": "viewer", "password": "v" * 24, "role": "viewer"})
    settings.telegram_users["111"] = "viewer"
    settings.llm_mode = "live"  # No provider request is made by a decision endpoint.
    result = callback(flow, update(case, sender=111)).json()
    assert result["error"]["code"] == 403
    approved = callback(flow, update(case, sequence=2)).json()
    assert approved["blocked"] is False and approved["mode"] == "dry-run"


def test_duplicate_inline_callback_and_rebound_update_id(flow):
    original = update(flow[2])
    first, repeated = callback(flow, original), callback(flow, original)
    assert first.json() == repeated.json()
    assert callback(flow, update(flow[2], action="i")).status_code == 409
    assert_single_decision(flow, actor="admin")


@pytest.mark.parametrize("web", [False, True])
def test_two_telegram_approvers_and_web_telegram_http_race(flow, web):
    client, _, case, *_ = flow

    def first():
        return callback(flow, update(case, sender=456, sequence=1)).json()

    def second():
        if web:
            return client.post(
                "/api/v1/incidents/" + case["id"] + "/response",
                json={"decision": "approve", "run_id": case["latest_run_id"]},
            ).json()
        return callback(flow, update(case, sender=123, sequence=2)).json()

    with ThreadPoolExecutor(max_workers=2) as pool:
        a, b = pool.submit(first), pool.submit(second)
        results = [a.result(), b.result()]
    assert sum(r.get("status") == "dry_run" for r in results) == 1
    assert sum(r.get("error", {}).get("code") == 409 for r in results) == 1
    assert_single_decision(flow)


@pytest.mark.parametrize(
    "state,code", [("expired", 409), ("stale", 400), ("protected", 400), ("replay", 400)]
)
def test_inline_button_revalidates_expiration_version_and_policy(flow, state, code):
    _, settings, case, service, _ = flow
    if state == "protected":
        settings.protected = (*settings.protected, "192.168.20.0/24")
    else:
        with service.store.connect() as db:
            if state == "expired":
                db.execute("UPDATE runs SET finished=1")
            elif state == "stale":
                db.execute("UPDATE cases SET latest_run_id=? WHERE id=?", ("f" * 32, case["id"]))
            else:
                db.execute("UPDATE runs SET replay=1")
    assert callback(flow, update(case)).json()["error"]["code"] == code
    with service.store.connect() as db:
        assert db.execute("SELECT count(*) FROM actions").fetchone()[0] == 0


def test_ignore_button_records_operator_and_single_result(flow):
    result = callback(flow, update(flow[2], action="i", sender=456)).json()
    assert result["status"] == "rejected" and result["blocked"] is False
    assert_single_decision(flow, "rejected", "second")


def test_invalid_hmac_expired_timestamp_and_untrusted_telegram_ingress(flow):
    client, settings, case, *_ = flow
    prepared = trusted_callback_request(
        {"X-Telegram-Bot-Api-Secret-Token": INGRESS_SECRET},
        update(case),
        INGRESS_SECRET,
        settings.shuffle_callback_secret,
    )
    prepared["headers"]["X-AgentSOC-Signature"] = "0" * 64
    assert (
        client.post(
            "/api/v1/integrations/telegram", content=prepared["body"], headers=prepared["headers"]
        ).status_code
        == 401
    )
    assert callback(flow, update(case), timestamp=time.time() - 600).status_code == 401
    for headers in ({}, {"X-Telegram-Bot-Api-Secret-Token": "forged"}):
        with pytest.raises(ValueError, match="Untrusted"):
            callback(flow, update(case), headers=headers)
    assert flow[3].store.get(case["id"])["status"] == "pending"


def test_partial_delivery_retry_keeps_two_recipient_identities_and_no_actions(flow):
    _, settings, case, service, ledger = flow
    calls, fail_second = [], True

    def telegram(req):
        body = json.loads(req.content)
        calls.append(body["chat_id"])
        return httpx.Response(
            503 if fail_second and body["chat_id"] == "222" else 200,
            json={"ok": not (fail_second and body["chat_id"] == "222")},
        )

    def shuffle(req):
        event = json.loads(req.content)
        success = True
        with httpx.Client(transport=httpx.MockTransport(telegram)) as client:
            for delivery in notification_requests(event):
                token = ledger.claim(delivery["event_id"], delivery["chat_id"])
                if token:
                    response = client.post("https://telegram.invalid/sendMessage", json=delivery["body"])
                    state = "delivered" if response.status_code == 200 else "retry"
                    ledger.finish(delivery["event_id"], delivery["chat_id"], token, state)
                success &= ledger.status(delivery["event_id"], delivery["chat_id"]) == "delivered"
        return httpx.Response(200 if success else 503, json={"success": success})

    transport = httpx.MockTransport(shuffle)
    deliver_pending(service.store, settings, transport=transport)
    with service.store.connect() as db:
        row = db.execute("SELECT * FROM notification_outbox").fetchone()
        assert row["status"] == "retry" and row["available"] > time.time()
        db.execute("UPDATE notification_outbox SET available=0")
    settings.telegram_notify_chats = ("333",)  # A queued event must not change its recipients on retry.
    fail_second = False
    deliver_pending(service.store, settings, transport=transport)
    assert calls == ["111", "222", "222"]
    with service.store.connect() as db:
        assert db.execute("SELECT status FROM notification_outbox").fetchone()[0] == "delivered"
        assert db.execute("SELECT count(*) FROM actions").fetchone()[0] == 0
    assert ledger.status("proposal:" + case["latest_run_id"], "111") == "delivered"


def test_lost_telegram_ack_is_explicitly_unknown_without_automatic_resend(tmp_path):
    ledger = DeliveryLedger(tmp_path / "ledger.db")
    token = ledger.claim("event", "111")
    assert token and ledger.finish("event", "111", token, "unknown")
    assert ledger.claim("event", "111") is None
    assert ledger.status("event", "111") == "unknown"
    assert ledger.finish("event", "111", "stale-token", "delivered") is False
