import subprocess
from concurrent.futures import ThreadPoolExecutor

import pytest
from fastapi.testclient import TestClient

from src import response
from src.api.main import create_app
from tests.conftest import snort, windows


@pytest.fixture
def client(settings):
    with TestClient(create_app(settings, worker=False)) as client:
        yield client


def make_case(client):
    service = client.app.state.service
    service.store.ingest(snort(), 0)
    service.store.ingest(windows(), 1)
    service.tick(40)
    return service.store.cases()[0]


def test_auth_and_validation(client, settings):
    assert client.get("/health").status_code == 200
    assert client.get("/cases").status_code == 401
    assert client.post("/ingest", json=snort()).status_code == 401
    headers = {"Authorization": "Bearer " + settings.ingest_key}
    assert client.post("/ingest", json=snort(), headers=headers).json()["accepted"]
    assert not client.post("/ingest", json=snort(), headers=headers).json()["accepted"]
    assert (
        client.post(
            "/ingest", json={"id": "bad", "data": {}, "rule": {"level": "invalid"}}, headers=headers
        ).status_code
        == 422
    )
    assert (
        client.post("/ingest", json=snort("low", level=3), headers=headers).json()["reason"]
        == "below_level_7"
    )
    assert client.post("/ingest", json=snort("bad", level=999), headers=headers).status_code == 422


def test_oversized_body(client):
    assert client.post("/ingest", content=b"x" * 262145).status_code == 413


def test_ui_escapes_evidence_and_no_secret_in_url(client, settings):
    case = make_case(client)
    store = client.app.state.service.store
    case["verdict"]["reason"] = "<script>alert('x')</script>"
    with store.connect() as db:
        import json

        db.execute("UPDATE cases SET verdict=? WHERE id=?", (json.dumps(case["verdict"]), case["id"]))
    page = client.get("/cases", auth=("reviewer", settings.approve_key))
    assert page.status_code == 200 and "&lt;script&gt;" in page.text
    assert settings.approve_key not in page.text and "?k=" not in page.text
    assert "no-store" == page.headers["cache-control"]


def test_review_requires_header_and_never_blocks_before_approval(client, settings, monkeypatch):
    monkeypatch.setattr(subprocess, "run", lambda *a, **k: pytest.fail("Unexpected SSH"))
    case = make_case(client)
    auth = ("reviewer", settings.approve_key)
    assert case["status"] == "pending"
    url = "/approve/" + case["id"]
    assert client.post(url, auth=auth).status_code == 403
    headers = {"X-AgentSOC-Review": "1"}
    result = client.post(url, auth=auth, headers=headers)
    assert result.json()["status"] == "dry_run"
    assert client.post(url, auth=auth, headers=headers).status_code == 409


def test_reject(client, settings):
    case = make_case(client)
    result = client.post(
        "/reject/" + case["id"], auth=("reviewer", settings.approve_key), headers={"X-AgentSOC-Review": "1"}
    )
    assert result.json()["status"] == "rejected"


@pytest.mark.parametrize("target", ["10.8.0.1", "192.168.10.20", "8.8.8.8", "192.168.20.50;id"])
def test_target_policy(client, settings, target):
    case = make_case(client)
    case["verdict"]["block_ip"] = target
    with pytest.raises(ValueError):
        response.candidate(case, settings)


def test_claim_is_atomic(client):
    case = make_case(client)
    with ThreadPoolExecutor(max_workers=4) as pool:
        claimed = list(pool.map(lambda _: client.app.state.service.store.claim(case["id"]), range(4)))
    assert claimed.count(True) == 1


def test_interrupted_action_is_not_retried(client):
    case = make_case(client)
    store = client.app.state.service.store
    assert store.claim(case["id"])
    store.recover()
    assert store.get(case["id"])["status"] == "action_unknown"
    assert not store.claim(case["id"])


def test_mock_cannot_enable_ssh(settings):
    settings.response_mode = "ssh"
    with pytest.raises(ValueError, match="Mock"):
        settings.validate()


def test_old_mock_case_cannot_block_after_switch_to_live(client, settings):
    case = make_case(client)
    settings.llm_mode = "live"
    settings.response_mode = "ssh"
    with pytest.raises(ValueError, match="Only live"):
        response.candidate(case, settings)


def test_ssh_command_pins_host_key(settings, monkeypatch):
    settings.response_mode = "ssh"
    captured = []

    def run(args, **kwargs):
        captured.extend(args)
        return subprocess.CompletedProcess(args, 0)

    monkeypatch.setattr(subprocess, "run", run)
    assert response.execute("192.168.20.50", settings) == "blocked"
    assert "StrictHostKeyChecking=yes" in captured and captured[-1] == "block 192.168.20.50"


def test_api_restores_windows_paths(client, settings):
    make_case(client)
    rows = client.get("/api/cases", auth=("reviewer", settings.approve_key)).json()
    assert len(rows) == 1 and "restore" not in rows[0]
    assert rows[0]["verdict"]["block_ip"] == "192.168.20.50"


def test_lifespan_worker_processes_alert(settings):
    import time

    settings.poll = 0.01
    with TestClient(create_app(settings, worker=True)) as client:
        headers = {"Authorization": "Bearer " + settings.ingest_key}
        assert client.post("/ingest", json=windows(), headers=headers).status_code == 202
        end = time.monotonic() + 3
        while time.monotonic() < end:
            rows = client.app.state.service.store.cases()
            if rows and rows[0]["status"] == "pending":
                break
            time.sleep(0.01)
        assert client.app.state.service.store.cases()[0]["status"] == "pending"
