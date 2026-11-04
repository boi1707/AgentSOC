import json
import sqlite3
import time
import uuid
from contextlib import contextmanager
from pathlib import Path

SCHEMA = """
CREATE TABLE IF NOT EXISTS inbox(id TEXT PRIMARY KEY, received REAL NOT NULL, alert TEXT NOT NULL,
                                case_id TEXT);
CREATE TABLE IF NOT EXISTS cases(id TEXT PRIMARY KEY, created REAL NOT NULL, status TEXT NOT NULL,
    incident TEXT NOT NULL, verdict TEXT NOT NULL DEFAULT '{}', restore TEXT NOT NULL DEFAULT '{}');
CREATE TABLE IF NOT EXISTS ledger(id INTEGER PRIMARY KEY, ts REAL NOT NULL, case_id TEXT NOT NULL,
    agent TEXT NOT NULL, mode TEXT NOT NULL, prompt TEXT NOT NULL, response TEXT, evidence TEXT NOT NULL,
    usage TEXT NOT NULL, duration_ms REAL NOT NULL, error TEXT);
CREATE TABLE IF NOT EXISTS actions(id INTEGER PRIMARY KEY, ts REAL NOT NULL, case_id TEXT NOT NULL,
    action TEXT NOT NULL, ip TEXT, mode TEXT NOT NULL, result TEXT NOT NULL);
CREATE INDEX IF NOT EXISTS inbox_pending ON inbox(case_id, received);
"""


class Store:
    def __init__(self, path):
        self.path = path
        Path(path).parent.mkdir(parents=True, exist_ok=True)
        with self.connect() as db:
            db.execute("PRAGMA journal_mode=WAL")
            db.executescript(SCHEMA)
        # Raw evidence and restoration maps are local-only data.
        Path(path).chmod(0o600)

    @contextmanager
    def connect(self):
        db = sqlite3.connect(self.path, timeout=15)
        db.row_factory = sqlite3.Row
        try:
            with db:
                yield db
        finally:
            db.close()

    def ingest(self, alert, received=None):
        with self.connect() as db:
            cur = db.execute(
                "INSERT OR IGNORE INTO inbox VALUES(?,?,?,NULL)",
                (alert["id"], time.time() if received is None else received, json.dumps(alert)),
            )
            return cur.rowcount == 1

    def pending_alerts(self):
        with self.connect() as db:
            return db.execute("SELECT * FROM inbox WHERE case_id IS NULL ORDER BY received,rowid").fetchall()

    def enqueue(self, incident):
        cid = uuid.uuid4().hex
        with self.connect() as db:
            db.execute(
                "INSERT INTO cases(id,created,status,incident) VALUES(?,?,?,?)",
                (cid, time.time(), "queued", json.dumps(incident)),
            )
            db.executemany(
                "UPDATE inbox SET case_id=? WHERE id=? AND case_id IS NULL",
                [(cid, aid) for aid in incident["raw_ids"]],
            )
        return cid

    def get(self, cid):
        with self.connect() as db:
            row = db.execute("SELECT * FROM cases WHERE id=?", (cid,)).fetchone()
        return self.decode(row) if row else None

    @staticmethod
    def decode(row):
        data = dict(row)
        for key in ("incident", "verdict", "restore"):
            data[key] = json.loads(data[key])
        return data

    def cases(self):
        with self.connect() as db:
            return [self.decode(r) for r in db.execute("SELECT * FROM cases ORDER BY created DESC LIMIT 100")]

    def finish(self, cid, verdict, restore):
        with self.connect() as db:
            db.execute(
                "UPDATE cases SET status='pending',verdict=?,restore=? WHERE id=? AND status='queued'",
                (json.dumps(verdict), json.dumps(restore), cid),
            )

    def claim(self, cid):
        with self.connect() as db:
            return (
                db.execute(
                    "UPDATE cases SET status='executing' WHERE id=? AND status='pending'", (cid,)
                ).rowcount
                == 1
            )

    def record_action(self, cid, action, ip, mode, status):
        with self.connect() as db:
            db.execute("UPDATE cases SET status=? WHERE id=?", (status, cid))
            db.execute(
                "INSERT INTO actions(ts,case_id,action,ip,mode,result) VALUES(?,?,?,?,?,?)",
                (time.time(), cid, action, ip, mode, status),
            )

    def recover(self):
        with self.connect() as db:
            db.execute("UPDATE cases SET status='action_unknown' WHERE status='executing'")

    def metrics(self):
        with self.connect() as db:
            alerts, last = db.execute("SELECT count(*),max(received) FROM inbox").fetchone()
            cases = db.execute("SELECT count(*) FROM cases").fetchone()[0]
            calls, blocked, errors, call_ms = db.execute(
                "SELECT count(*),coalesce(sum(error='Blocked'),0),"
                "coalesce(sum(error IS NOT NULL AND error!='Blocked'),0),"
                "avg(CASE WHEN error IS NULL OR error!='Blocked' THEN duration_ms END) FROM ledger"
            ).fetchone()
            analysis_ms = db.execute(
                "SELECT avg(duration) FROM (SELECT sum(duration_ms) AS duration FROM ledger GROUP BY case_id)"
            ).fetchone()[0]
            pending = db.execute("SELECT count(*) FROM inbox WHERE case_id IS NULL").fetchone()[0]
        return {
            "alerts_received": alerts,
            "incidents": cases,
            "unprocessed_alerts": pending,
            "last_alert_at": last,
            "llm_calls": calls - blocked,
            "blocked_egress": blocked,
            "llm_errors": errors,
            "average_call_ms": call_ms,
            "average_analysis_ms": analysis_ms,
        }
