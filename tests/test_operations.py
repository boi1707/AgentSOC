import json
import logging
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from src.anon import Anon
from src.api.main import create_app
from src.llm import Blocked
from src.service import Service
from tests.conftest import snort, windows


def test_operational_metrics_use_persisted_data(settings):
    app = create_app(settings, worker=False)
    headers = {"Authorization": "Bearer " + settings.ingest_key, "Content-Type": "application/json"}
    auth = ("reviewer", settings.approve_key)
    with TestClient(app) as client:
        health = client.get("/health").json()
        assert health["case_count"] == 0 and health["last_alert_at"] is None
        assert health["llm_configured"] is False
        assert client.get("/metrics").status_code == 401
        assert client.post("/ingest", content="{", headers=headers).status_code == 400
        for alert in (snort(), windows()):
            assert client.post("/ingest", json=alert, headers=headers).status_code == 202
        assert client.get("/health").json()["pending_incidents"] == 1
        app.state.service.tick()
        metrics = client.get("/metrics", auth=auth).json()
        assert metrics["alerts_received"] == 2
        assert metrics["incidents"] == 1 and metrics["llm_calls"] == 3
        assert metrics["blocked_egress"] == 0 and metrics["llm_errors"] == 0
        assert metrics["average_analysis_ms"] >= 0
        assert client.get("/health").json()["pending_incidents"] == 0
    # Counters must survive a process restart.
    with TestClient(create_app(settings, worker=False)) as client:
        assert client.get("/metrics", auth=auth).json()["alerts_received"] == 2


def test_blocked_attempt_is_audited_without_the_unsafe_prompt(settings, monkeypatch):
    service = Service(settings)
    monkeypatch.setattr(Anon, "obj", lambda self, obj: obj)
    with pytest.raises(Blocked):
        service.llm.ask(Anon(), "case1", "net", "JSON", {"ip": "10.8.0.3"}, [])
    with service.store.connect() as db:
        row = db.execute("SELECT * FROM ledger").fetchone()
    assert row is not None and row["error"] == "Blocked"
    assert "10.8.0.3" not in row["prompt"]


def test_json_logging_redacts_secrets_and_exception_text(settings):
    from src.logs import configure_logging

    configure_logging(settings)
    log = logging.getLogger("agentsoc.test")
    try:
        raise RuntimeError(settings.llm_key + settings.approve_key + " 10.8.0.3")
    except RuntimeError:
        log.exception("test.failure", extra={"case_id": "test", "details": {"key": settings.ingest_key}})
    path = Path(settings.db).parent / "logs" / "agentsoc.log"
    content = path.read_text(encoding="utf-8")
    assert settings.approve_key not in content and settings.ingest_key not in content
    assert "10.8.0.3" not in content
    row = json.loads(content.splitlines()[-1])
    assert row["event"] == "test.failure" and row["case_id"] == "test"
    assert row["error_type"] == "RuntimeError" and row["traceback"]


@pytest.mark.parametrize(
    "name,value", [("poll", float("nan")), ("quiet", float("inf")), ("cap", 0), ("hi_level", 16)]
)
def test_invalid_operational_configuration(settings, name, value):
    setattr(settings, name, value)
    with pytest.raises(ValueError):
        settings.validate()
