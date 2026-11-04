"""Real TCP/ASGI application, SQLite, Wazuh integration script and worker. No external services."""

import json
import os
import secrets
import socket
import subprocess
import sys
import time

import httpx

from tests.conftest import snort, windows


def test_real_http_pipeline_and_review(tmp_path):
    with socket.socket() as listener:
        listener.bind(("127.0.0.1", 0))
        port = listener.getsockname()[1]
    key, review = secrets.token_urlsafe(32), secrets.token_urlsafe(32)
    env = {
        **os.environ,
        "INGEST_KEY": key,
        "APPROVE_KEY": review,
        "DB": str(tmp_path / "pipeline.db"),
        "LLM_MODE": "mock",
        "RESPONSE_MODE": "dry-run",
        "POLL_SECONDS": "0.05",
        "TG_TOKEN": "",
        "TG_CHAT": "",
    }
    process = subprocess.Popen(
        [
            sys.executable,
            "-m",
            "uvicorn",
            "src.api.main:app",
            "--host",
            "127.0.0.1",
            "--port",
            str(port),
            "--no-access-log",
        ],
        env=env,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    url = f"http://127.0.0.1:{port}"
    try:
        with httpx.Client(base_url=url, timeout=3, trust_env=False) as client:
            deadline = time.monotonic() + 15
            while True:
                assert process.poll() is None, "ASGI server exited before startup"
                try:
                    if client.get("/health").status_code == 200:
                        break
                except httpx.TransportError:
                    pass
                assert time.monotonic() < deadline, "ASGI server startup timed out"
                time.sleep(0.05)
            assert client.get("/cases").status_code == 401
            # Exercise the exact executable installed on the Wazuh manager.
            for index, alert in enumerate((snort(), windows())):
                path = tmp_path / f"alert-{index}.json"
                path.write_text(json.dumps(alert), encoding="utf-8")
                sent = subprocess.run(
                    [sys.executable, "scripts/custom-agentsoc", str(path), key, url + "/ingest"],
                    capture_output=True,
                    timeout=10,
                )
                assert sent.returncode == 0
            deadline = time.monotonic() + 10
            while True:
                rows = client.get("/api/cases", auth=("reviewer", review)).json()
                if rows and rows[0]["status"] == "pending":
                    break
                assert time.monotonic() < deadline, "Worker did not finish the incident"
                time.sleep(0.05)
            cid = rows[0]["id"]
            assert rows[0]["can_approve"] and rows[0]["verdict"]["mode"] == "mock"
            result = client.post(
                f"/approve/{cid}", auth=("reviewer", review), headers={"X-AgentSOC-Review": "1"}
            )
            assert result.json()["status"] == "dry_run"
            assert (
                client.post(
                    f"/approve/{cid}", auth=("reviewer", review), headers={"X-AgentSOC-Review": "1"}
                ).status_code
                == 409
            )
            metrics = client.get("/metrics", auth=("reviewer", review)).json()
            assert metrics["alerts_received"] == 2 and metrics["llm_calls"] == 3
            logs = (tmp_path / "logs" / "agentsoc.log").read_text(encoding="utf-8")
            events = [json.loads(line)["event"] for line in logs.splitlines()]
            assert {
                "service.started",
                "alert.received",
                "incident.created",
                "llm.started",
                "llm.finished",
                "case.created",
                "review.completed",
            } <= set(events)
            assert key not in logs and review not in logs and "192.168.20.50" not in logs
    finally:
        process.terminate()
        try:
            process.wait(timeout=10)
        except subprocess.TimeoutExpired:
            process.kill()
            process.wait(timeout=5)
