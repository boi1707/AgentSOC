import json
import subprocess
import sys

import pytest

from scripts.audit import load_labels, report
from scripts.replay import delays, load_alerts
from src.service import Service
from tests.conftest import snort, windows


def test_evaluation_uses_labels_and_does_not_score_mock_by_default(settings):
    service = Service(settings)
    service.store.ingest(snort(), 0)
    service.store.ingest(windows(), 1)
    service.tick(40)
    labels = {"n1": "attack", "h1": "benign", "missing": "attack"}
    normal = report(settings.db, labels=labels)
    assert normal["precision"] is None and normal["evaluated_cases"] == 0
    assert normal["labeled_alerts_pending_or_excluded"] == 2
    assert normal["labels_missing_from_inbox"] == 1
    demo = report(settings.db, labels=labels, include_mock=True)
    assert demo["precision"] == 0.5 and demo["recall"] == 1
    assert demo["input_tokens"] is None and demo["estimated_cost_usd"] is None
    assert demo["guard_pattern_matches"] == 0 and demo["mean_groundedness"] == 1


def test_read_only_audit_and_leak_exit_code(tmp_path):
    missing = tmp_path / "missing.db"
    result = subprocess.run(
        [sys.executable, "-m", "scripts.check_leaks", "--db", str(missing)], capture_output=True, text=True
    )
    assert result.returncode == 2 and not missing.exists()


def test_cost_requires_recorded_tokens_and_both_prices(settings):
    service = Service(settings)
    service.store.ingest(windows(), 0)
    service.tick(1)
    with service.store.connect() as db:
        case = service.store.cases()[0]
        case["verdict"]["mode"] = "live"
        db.execute("UPDATE cases SET verdict=?", (json.dumps(case["verdict"]),))
        db.execute(
            "UPDATE ledger SET mode='live',usage=?",
            (json.dumps({"prompt_tokens": 100, "completion_tokens": 20}),),
        )
    measured = report(settings.db, input_price=2, output_price=4)
    assert measured["input_tokens"] == 300 and measured["output_tokens"] == 60
    assert measured["estimated_cost_usd"] == pytest.approx(0.00084)
    assert report(settings.db, input_price=2)["estimated_cost_usd"] is None


def test_leak_scan_fails_without_exposing_sensitive_values(settings):
    service = Service(settings)
    service.store.ingest(windows(), 0)
    service.tick(1)
    with service.store.connect() as db:
        db.execute("UPDATE ledger SET prompt=? WHERE id=1", ('[{"content":"10.8.0.3"}]',))
    result = subprocess.run(
        [sys.executable, "-m", "scripts.check_leaks", "--db", settings.db], capture_output=True, text=True
    )
    assert result.returncode == 1 and "10.8.0.3" not in result.stdout
    assert json.loads(result.stdout)["prompts_with_sensitive_patterns"] == 1


def test_csv_labels_are_validated(tmp_path):
    path = tmp_path / "labels.csv"
    path.write_text("alert_id,label\nn1,attack\nh1,benign\n", encoding="utf-8")
    assert load_labels(path) == {"n1": "attack", "h1": "benign"}
    path.write_text("alert_id,label\nn1,attack\nn1,benign\n", encoding="utf-8")
    with pytest.raises(ValueError):
        load_labels(path)


@pytest.mark.parametrize("form", ["array", "jsonl", "object"])
def test_replay_formats_and_speed(tmp_path, form):
    alerts = [snort(), windows()]
    alerts[0]["timestamp"] = "2026-01-01T00:00:00Z"
    alerts[1]["timestamp"] = "2026-01-01T00:00:10Z"
    text = (
        json.dumps(alerts)
        if form == "array"
        else json.dumps(alerts[0])
        if form == "object"
        else "\n".join(map(json.dumps, alerts))
    )
    path = tmp_path / "alerts.json"
    path.write_text(text, encoding="utf-8")
    loaded = load_alerts(path)
    assert list(delays(loaded, 10)) == ([0] if form == "object" else [0, 1])


@pytest.mark.parametrize("speed", [-1, float("nan"), float("inf")])
def test_invalid_replay_speed(speed):
    with pytest.raises(ValueError):
        list(delays([snort()], speed))
