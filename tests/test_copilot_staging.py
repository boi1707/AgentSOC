"""Isolated acceptance exercise with real AgentSOC/bridge code and mocked service HTTP."""

import io
import json
import os
import sqlite3
import subprocess
import sys
import tarfile
import time

import httpx
import pytest
from fastapi.testclient import TestClient

from integrations.shuffle.agentsoc_bridge import query_reply, trusted_callback_request
from scripts.migration_lab import V5_TABLES, snapshot
from src.api.main import create_app
from src.shuffle import deliver_pending
from src.thehive import sync_pending
from tests.test_copilot import ask, thread

V4 = "298e5f9f2e42b6702bf7bc0c40785ecc8447b110"
INGRESS = "fixture-telegram-ingress"
CHAT = "123"


def run_previous(db, source, code):
    result = subprocess.run(
        [sys.executable, "-c", "import sqlite3\n" + code, str(db)],
        cwd=source,
        env={**os.environ, "PYTHONPATH": str(source), "PYTHON_DOTENV_DISABLED": "1"},
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        stdin=subprocess.DEVNULL,
    )
    assert result.returncode == 0, result.stderr.decode(errors="replace")[-2000:]


@pytest.fixture
def migrated_lab(tmp_path, settings):
    source = tmp_path / "v4-source"
    source.mkdir()
    archive = subprocess.check_output(["git", "archive", V4, "src"])
    with tarfile.open(fileobj=io.BytesIO(archive)) as bundled:
        bundled.extractall(source, filter="data")
    run_previous(
        settings.db,
        source,
        """
import sys, time
from src.service import Service
from src.settings import Settings
s = Service(Settings(db=sys.argv[1]))
alert = {"id": "lab-observed-source", "rule": {"id": "100010", "level": 8}, "data": {
    "src_addr": "10.100.27.10", "dst_addr": "172.22.50.10", "msg": "lab review fixture", "dst_port": 445}}
assert s.store.ingest(alert)
s.tick(time.time()+40)
case, = s.store.cases()
assert case["verdict"]["verdict"] == "review" and not case["synthetic"]
""",
    )
    before = snapshot(settings.db)
    assert {row[0] for row in before["schema_migrations"]} == {1, 2, 3, 4}
    settings.telegram_users = {CHAT: "admin"}
    settings.shuffle_callback_secret = "acceptance-fixture-signing-secret-only"
    with TestClient(create_app(settings, worker=False)) as client:
        migrated = snapshot(settings.db)
        assert set(migrated) - set(before) == V5_TABLES
        assert {row[0] for row in migrated["schema_migrations"]} == {1, 2, 3, 4, 5}
        for table in ("cases", "runs", "inbox", "incident_alerts", "actions"):
            assert migrated[table] == before[table]
        login = client.post(
            "/api/v1/auth/login", json={"username": "admin", "password": settings.approve_key}
        )
        client.headers["X-CSRF-Token"] = login.json()["csrf"]
        yield client, source


def post_update(client, settings, update, *, now=None, wrong_secret=False):
    packet = trusted_callback_request(
        {"X-Telegram-Bot-Api-Secret-Token": INGRESS},
        update,
        INGRESS,
        settings.shuffle_callback_secret if not wrong_secret else "wrong-fixture-secret",
        now=now,
    )
    return client.post("/api/v1/integrations/telegram", headers=packet["headers"], content=packet["body"])


def command_update(sequence, text):
    return {
        "update_id": sequence,
        "message": {"from": {"id": int(CHAT)}, "chat": {"id": int(CHAT)}, "text": text},
    }


@pytest.mark.parametrize(("decision", "expected"), [("approve", "dry_run"), ("reject", "rejected")])
def test_staging_copilot_v4_upgrade_bridge_delivery_thehive_and_rollback(
    migrated_lab, settings, tmp_path, decision, expected
):
    client, source = migrated_lab
    store = client.app.state.service.store
    (case,) = store.cases()
    assert settings.response_mode == "dry-run" and settings.pfsense_live_enabled is False
    settings.thehive_url = "https://thehive.invalid"
    settings.thehive_key = "disposable-thehive-fixture"
    writes = []

    def thehive(request):
        if request.method == "POST" and request.url.path == "/api/v1/query":
            return httpx.Response(200, json=[])
        body = json.loads(request.content)
        mirror = json.loads(body["description"].split("\n", 1)[1])
        writes.append((request.method, request.url.path, mirror))
        if request.method == "POST":
            return httpx.Response(201, json={"_id": "~staging-case"})
        return httpx.Response(204)

    transport = httpx.MockTransport(thehive)
    sync_pending(store, settings, transport=transport)
    assert [(method, path) for method, path, _ in writes] == [
        ("POST", "/api/v1/case"),
        ("PATCH", "/api/v1/case/~staging-case"),
    ]
    assert writes[-1][2]["status"] == "pending"
    url = thread(client, incident_id=case["id"])
    code = client.post(url + "/telegram-link").json()["code"]
    post_update(client, settings, command_update(1, "/link " + code))
    assert ask(client, url, "Explain this incident").json()["answer"]["facts"][0]["verdict"] == "review"
    bot = post_update(client, settings, command_update(2, "What is its source?")).json()
    assert bot["facts"][0]["incident_id"] == case["id"] and bot["citations"][0]["id"] == "lab-observed-source"
    assert len(client.get(url).json()["messages"]) == 2
    preview = post_update(
        client, settings, command_update(3, "/prepare Review the observed lab network flow")
    ).json()
    aid = preview["copilot_action"]["id"]
    reply = query_reply(preview)

    def telegram_send(request):
        body = json.loads(request.content)
        assert request.method == "POST" and request.url.path.endswith("/sendMessage")
        assert body["chat_id"] == CHAT and "parse_mode" not in body
        assert body["reply_markup"]["inline_keyboard"][0] == [
            {"text": "Approve", "callback_data": "ac:a:" + aid},
            {"text": "Reject", "callback_data": "ac:i:" + aid},
        ]
        return httpx.Response(200, json={"ok": True, "result": {"message_id": 104, **body}})

    with httpx.Client(transport=httpx.MockTransport(telegram_send)) as telegram:
        delivery = telegram.post("https://telegram.invalid/botfixture/sendMessage", json=reply)
        delivery.raise_for_status()
        assert delivery.json()["ok"] is True
        delivered = delivery.json()["result"]["reply_markup"]["inline_keyboard"][0]
    assert "reply_markup" not in query_reply(
        post_update(client, settings, command_update(4, "Approve")).json()
    )
    assert post_update(client, settings, command_update(5, "/select " + aid)).status_code == 200
    requested = post_update(client, settings, command_update(6, decision.title())).json()
    assert requested["confirmation_decision"] == decision
    mark = delivered[0 if decision == "approve" else 1]
    assert query_reply(requested)["reply_markup"] == {"inline_keyboard": [[mark]]}

    with store.connect() as db:
        assert db.execute("SELECT count(*) FROM actions").fetchone()[0] == 0
    button = {
        "update_id": 7,
        "callback_query": {
            "id": "sent-104",
            "from": {"id": int(CHAT)},
            "message": {"chat": {"id": int(CHAT)}},
            "data": mark["callback_data"],
        },
    }
    with pytest.raises(ValueError, match="Untrusted Telegram ingress"):
        trusted_callback_request({}, button, INGRESS, settings.shuffle_callback_secret)
    assert post_update(client, settings, button, now=time.time() - 600).status_code == 401
    assert post_update(client, settings, button, wrong_secret=True).status_code == 401
    callback = post_update(client, settings, button).json()
    assert callback["chat_id"] == CHAT and callback["callback_query_id"] == "sent-104"
    result = callback["copilot_action"]
    assert result["status"] == expected and result["mode"] == "dry-run" and not result["blocked"]
    assert result["verification_status"] == "not_verified"
    assert post_update(client, settings, button).json()["copilot_action"] == result
    assert client.post(url + "/actions/" + aid, json={"decision": "approve"}).json() == result
    assert client.get(url).json()["actions"][0] == result
    sync_pending(store, settings, transport=transport)
    assert [(method, path) for method, path, _ in writes[2:]] == [
        ("PATCH", "/api/v1/case/~staging-case"),
    ]
    assert writes[-1][2]["status"] == expected and writes[-1][2]["verdict"]["verdict"] == "review"
    with store.connect() as db:
        assert db.execute("SELECT count(*) FROM actions").fetchone()[0] == 1
        assert (
            db.execute(
                "SELECT count(*) FROM shuffle_outbox WHERE action_id=?", (result["action_id"],)
            ).fetchone()[0]
            == 1
        )

    settings.shuffle_hook = "https://shuffle.invalid/acceptance"
    settings.telegram_notify_chats = (CHAT,)
    deliveries = []

    def shuffle_receive(request):
        event = json.loads(request.content)
        assert request.headers["Idempotency-Key"] == event["event_id"]
        if event["event"] == "response.completed":
            deliveries.append(event)
        return httpx.Response(200, json={"success": True})

    shuffle = httpx.MockTransport(shuffle_receive)
    deliver_pending(store, settings, transport=shuffle)
    deliver_pending(store, settings, transport=shuffle)
    (delivered_event,) = deliveries
    assert delivered_event["action_id"] == result["action_id"]
    assert delivered_event["notification_recipients"] == [CHAT] and delivered_event["status"] == expected

    rollback_db = tmp_path / "rollback.db"
    with store.connect() as live, sqlite3.connect(rollback_db) as copy:
        live.backup(copy)
    before = snapshot(rollback_db)
    run_previous(
        rollback_db,
        source,
        """
import sys
from fastapi.testclient import TestClient
from src.api.main import create_app
from src.settings import Settings
settings = Settings(db=sys.argv[1], ingest_key='i'*32, approve_key='r'*32)
with TestClient(create_app(settings, worker=False)) as client:
    assert client.get('/live').status_code == 200
    case, = client.app.state.service.store.cases()
    assert case["verdict"]["verdict"] == "review"
    assert case["status"] in {"dry_run", "rejected"}
""",
    )
    after = snapshot(rollback_db)
    for table in {"cases", "actions", "runs", "schema_migrations", *V5_TABLES}:
        assert after[table] == before[table]
