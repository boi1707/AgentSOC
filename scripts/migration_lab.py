"""Disposable v1 fixture and data-preservation probes. Never accepts an existing output."""

import argparse
import json
import sqlite3
import time
from contextlib import closing
from pathlib import Path

from src.auth import bootstrap
from src.settings import Settings
from src.storage import Store

BASELINE = "0022d28"
V2_TABLES = {"callback_receipts", "notification_outbox"}
V3_TABLES = {"managed_block_leases"}
V4_TABLES = {"vt_hash_jobs", "vt_hash_cache"}


def snapshot(path):
    with closing(sqlite3.connect(Path(path).resolve().as_uri() + "?mode=ro", uri=True)) as db:
        tables = [
            r[0]
            for r in db.execute(
                "SELECT name FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%' ORDER BY name"
            )
        ]
        return {
            table: sorted(db.execute(f'SELECT * FROM "{table}"').fetchall(), key=repr) for table in tables
        }


def seed_v1(path):
    path = Path(path)
    if path.exists():
        raise ValueError("Refusing to overwrite an existing database")
    path.parent.mkdir(parents=True, exist_ok=True)
    schema = Path(__file__).resolve().parents[1] / "tests/fixtures/schema_v1.sql"
    with closing(sqlite3.connect(path)) as db, db:
        db.executescript(schema.read_text(encoding="utf-8"))
        db.execute("INSERT INTO schema_migrations VALUES(1,?)", (time.time(),))
    # Exercise the existing storage interface against the exact historical schema, without migrating it.
    repo = Store.__new__(Store)
    repo.path = str(path)
    settings = Settings(
        db=str(path), ingest_key="lab-ingest-" + "i" * 32, approve_key="lab-review-" + "r" * 32
    )
    bootstrap(repo, settings)
    for index in range(2):
        net_id, host_id = f"lab-net-{index}", f"lab-host-{index}"
        alerts = [
            {
                "id": net_id,
                "kind": "net",
                "level": 12,
                "rule": "100010",
                "src_ip": "192.168.20.50",
                "dst_ip": "192.168.10.20",
            },
            {"id": host_id, "kind": "host", "level": 12, "rule": "100020"},
        ]
        repo.ingest(
            {
                "id": net_id,
                "rule": {"id": "100010", "level": 12},
                "data": {"src_addr": "192.168.20.50", "dst_addr": "192.168.10.20"},
            }
        )
        repo.ingest(
            {
                "id": host_id,
                "rule": {"id": "100020", "level": 12},
                "agent": {"name": "lab-host"},
                "data": {"win": {"eventdata": {"image": "fixture.exe"}}},
            }
        )
        cid = repo.enqueue(
            {
                "alerts": alerts,
                "raw_ids": [net_id, host_id],
                "ips": ["192.168.20.50", "192.168.10.20"],
                "entities": ["ip:192.168.20.50"],
                "dropped_rows": 0,
            },
            settings=settings,
        )
        job = repo.claim_job("lab-fixture")
        verdict = {
            "verdict": "attack",
            "confidence": 0.95,
            "grounded": 1,
            "mode": "mock",
            "block_ip": "192.168.20.50",
            "evidence_ids": [net_id, host_id],
            "reason": "Disposable historical fixture",
        }
        repo.complete_job(job, verdict, {})
        with repo.connect() as db:
            db.execute(
                "INSERT INTO notes(case_id,actor,created,body) VALUES(?,?,?,?)",
                (cid, "admin", time.time(), "Preserved lab note"),
            )
            db.execute(
                "INSERT INTO ledger(ts,case_id,agent,mode,prompt,response,evidence,usage,duration_ms,run_id) VALUES(?,?,'judge','mock','[]',?,?,'{}',1,?)",
                (time.time(), cid, json.dumps(verdict), json.dumps([net_id, host_id]), job["run_id"]),
            )
        if index == 0:
            repo.claim(cid, actor="admin", mode="dry-run", action="approve", ip="192.168.20.50")
            repo.record_action(cid, "approve", "192.168.20.50", "dry-run", "dry_run", "admin")
    return snapshot(path)


def assert_relationships(path):
    with closing(sqlite3.connect(path)) as db:
        assert db.execute("PRAGMA integrity_check").fetchone()[0] == "ok"
        assert db.execute("PRAGMA foreign_key_check").fetchall() == []
        for query in (
            "SELECT count(*) FROM incident_alerts l LEFT JOIN cases c ON c.id=l.case_id LEFT JOIN inbox i ON i.id=l.alert_id WHERE c.id IS NULL OR i.id IS NULL",
            "SELECT count(*) FROM runs r LEFT JOIN cases c ON c.id=r.case_id WHERE c.id IS NULL",
            "SELECT count(*) FROM actions a LEFT JOIN cases c ON c.id=a.case_id WHERE c.id IS NULL",
            "SELECT count(*) FROM shuffle_outbox o LEFT JOIN actions a ON a.id=o.action_id WHERE a.id IS NULL",
            "SELECT count(*) FROM jobs j LEFT JOIN runs r ON r.id=j.run_id WHERE r.id IS NULL",
        ):
            assert db.execute(query).fetchone()[0] == 0
        indexes = {r[0] for r in db.execute("SELECT name FROM sqlite_master WHERE type='index'")}
        assert {
            "inbox_source_id",
            "inbox_filters",
            "jobs_available",
            "shuffle_due",
            "thehive_due",
            "vt_due",
        } <= indexes


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", required=True)
    args = parser.parse_args()
    seed_v1(args.output)
    assert_relationships(args.output)
    print("Disposable v1 database created; no production input was used.")
