"""Read-only database reports shared by evaluation and leak checks."""

import csv
import json
import sqlite3
import statistics
from contextlib import closing
from pathlib import Path

from src.anon import Anon


def read_database(path):
    uri = Path(path).resolve().as_uri() + "?mode=ro"
    with closing(sqlite3.connect(uri, uri=True)) as db:
        db.row_factory = sqlite3.Row
        with db:
            inbox = [dict(r) for r in db.execute("SELECT * FROM inbox")]
            cases = [dict(r) for r in db.execute("SELECT * FROM cases")]
            ledger = [dict(r) for r in db.execute("SELECT * FROM ledger")]
    return inbox, cases, ledger


def load_labels(path):
    with open(path, newline="", encoding="utf-8-sig") as file:
        rows = csv.DictReader(file)
        if not {"alert_id", "label"} <= set(rows.fieldnames or []):
            raise ValueError("Ground truth CSV requires alert_id,label columns")
        labels = {}
        for row in rows:
            aid, label = row["alert_id"].strip(), row["label"].strip().lower()
            if not aid or label not in {"attack", "benign"} or aid in labels:
                raise ValueError("Ground truth must have unique IDs and attack/benign labels")
            labels[aid] = label
    return labels


def report(path, *, labels=None, include_mock=False, input_price=None, output_price=None, hosts=()):
    inbox, cases, ledger = read_database(path)
    selected = {
        c["id"]: c
        for c in cases
        if c["status"] != "queued" and (include_mock or json.loads(c["verdict"]).get("mode") == "live")
    }
    calls = [c for c in ledger if c["case_id"] in selected]
    usage = [json.loads(c["usage"]) for c in calls if c["error"] != "Blocked"]
    measured = bool(usage) and all({"prompt_tokens", "completion_tokens"} <= u.keys() for u in usage)
    input_tokens = sum(u["prompt_tokens"] for u in usage) if measured else None
    output_tokens = sum(u["completion_tokens"] for u in usage) if measured else None
    latency = []
    for cid in selected:
        arrived = [a["received"] for a in inbox if a["case_id"] == cid]
        finished = [c["ts"] + c["duration_ms"] / 1000 for c in calls if c["case_id"] == cid]
        if arrived and finished:
            latency.append(max(0, (max(finished) - min(arrived)) * 1000))
    matrix = {"tp": 0, "fp": 0, "tn": 0, "fn": 0}
    labeled = waiting = review = 0
    labels = labels or {}
    seen = set()
    for alert in inbox:
        if alert["id"] not in labels:
            continue
        seen.add(alert["id"])
        if alert["case_id"] not in selected:
            waiting += 1
            continue
        labeled += 1
        verdict = json.loads(selected[alert["case_id"]]["verdict"])["verdict"]
        review += verdict == "review"
        attack = labels[alert["id"]] == "attack"
        matrix[("tp" if attack else "fp") if verdict == "attack" else ("fn" if attack else "tn")] += 1
    precision_den = matrix["tp"] + matrix["fp"]
    recall_den = matrix["tp"] + matrix["fn"]
    grounded = [
        json.loads(c["verdict"])["grounded"]
        for c in selected.values()
        if "grounded" in json.loads(c["verdict"])
    ]
    return {
        "alerts": len(inbox),
        "cases": len(cases),
        "evaluated_cases": len(selected),
        "include_mock": include_mock,
        "labeled_alerts_evaluated": labeled,
        "labeled_alerts_pending_or_excluded": waiting,
        "labels_missing_from_inbox": len(labels.keys() - seen),
        "review_alerts": review,
        "confusion_matrix": matrix,
        "precision": matrix["tp"] / precision_den if precision_den else None,
        "recall": matrix["tp"] / recall_den if recall_den else None,
        "mean_groundedness": statistics.mean(grounded) if grounded else None,
        "consolidation_ratio": 1 - len(cases) / len(inbox) if inbox else None,
        "ledger_attempts": len(ledger),
        "blocked_egress": sum(c["error"] == "Blocked" for c in ledger),
        "llm_errors": sum(c["error"] not in (None, "Blocked") for c in ledger),
        "guard_pattern_matches": sum(bool(Anon(hosts).leaks(c["prompt"])) for c in ledger),
        "mean_call_ms": statistics.mean(c["duration_ms"] for c in calls) if calls else None,
        "mean_end_to_end_ms": statistics.mean(latency) if latency else None,
        "input_tokens": input_tokens,
        "output_tokens": output_tokens,
        "estimated_cost_usd": (input_tokens * input_price + output_tokens * output_price) / 1_000_000
        if measured and input_price is not None and output_price is not None
        else None,
        "note": "Alert-level labels; review counts as non-attack. Pending/excluded cases are not scored. "
        "Mock excluded unless explicitly requested. Null means not measured; consolidation is not FP reduction.",
    }
