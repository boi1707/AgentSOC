import json
import socket
import threading
import time
from dataclasses import replace
from pathlib import Path

import uvicorn

from scripts.container_probe import SessionClient, validate_api
from scripts.migration_lab import seed_v1
from scripts.validate_docker import STAGES, advance, container_state, diagnostics, sanitize
from src.api.main import create_app


def test_container_local_probe_preserves_real_cookie_csrf_and_dry_run_http(settings, tmp_path, monkeypatch):
    db = tmp_path / "previous.db"
    seed_v1(db)
    config = replace(settings, db=str(db), poll=0.02)
    monkeypatch.setenv("INGEST_KEY", config.ingest_key)
    monkeypatch.setenv("RESPONSE_MODE", "dry-run")

    def forbidden(*args, **kwargs):
        raise AssertionError("Dry-run probe must not execute mitigation")

    monkeypatch.setattr("src.response.subprocess.run", forbidden)
    monkeypatch.setattr("src.response_adapters.PfSenseAdapter.block", forbidden)
    with socket.socket() as listener:
        listener.bind(("127.0.0.1", 0))
        server = uvicorn.Server(
            uvicorn.Config(create_app(config, worker=True), log_level="error", access_log=False)
        )
        thread = threading.Thread(target=server.run, kwargs={"sockets": [listener]}, daemon=True)
        thread.start()
        try:
            deadline = time.monotonic() + 10
            while not server.started and time.monotonic() < deadline:
                time.sleep(0.02)
            assert server.started
            client = SessionClient("http://127.0.0.1:" + str(listener.getsockname()[1]))
            result = validate_api(client, Path(__file__).resolve().parents[1] / "datasets/demo.jsonl")
            assert set(result.values()) == {"PASS"}
            assert client.csrf
        finally:
            server.should_exit = True
            thread.join(10)
            assert not thread.is_alive()


def test_diagnostics_whitelist_state_ports_and_redact_logs(monkeypatch):
    seen = []
    secret = "private-fixture-credential-1234"

    def docker(*args):
        seen.append(args)
        if args[0] == "inspect":
            assert ".Config.Env" not in args[2] and ".State.Health.Log" not in args[2]
            return json.dumps(
                {
                    "status": "running",
                    "exit_code": 0,
                    "ports": {"8000/tcp": None},
                    "requested_bindings": {"8000/tcp": [{"HostIp": "127.0.0.1", "HostPort": ""}]},
                }
            )
        return "password=" + secret + " Bearer abcdef https://user:password@host/private"

    monkeypatch.setattr("scripts.validate_docker.docker", docker)
    state = container_state("lab")
    assert state["status"] == "running" and state["ports"]["8000/tcp"] is None
    result = diagnostics(["lab"], [secret])
    encoded = json.dumps(result)
    assert secret not in encoded and "abcdef" not in encoded and "user:password" not in encoded
    assert len(seen) == 3


def test_stage_reporting_does_not_pass_unexecuted_checks():
    report = {"stages": dict.fromkeys(STAGES, "NOT RUN")}
    advance(report, "internal_network")
    assert report["stages"]["internal_network"] == "NOT RUN"
    advance(report, "python_312")
    assert report["stages"]["internal_network"] == "PASS"
    assert report["stages"]["historical_image_backend"] == "NOT RUN"
    advance(report)
    assert report["stages"]["python_312"] == "PASS"
    assert "active_stage" not in report


def test_redaction_recurses_and_leaves_nonsecret_status_visible():
    assert sanitize({"status": "PASS", "logs": ["csrf=private-value"]}) == {
        "status": "PASS",
        "logs": ["csrf=[REDACTED]"],
    }
