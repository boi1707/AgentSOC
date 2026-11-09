import json
import sqlite3
import time
import uuid
from contextlib import contextmanager
from pathlib import Path

from .adapters.wazuh import normalize
from .migrations import migrate
from .virustotal import public_ips

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
    def __init__(self, path, *, host_ips=None):
        self.path = path
        Path(path).parent.mkdir(parents=True, exist_ok=True)
        with self.connect() as db:
            db.execute("PRAGMA journal_mode=WAL")
            db.executescript(SCHEMA)
            migrate(db, host_ips=host_ips)
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

    def ingest(self, alert, received=None, *, host_ips=None, synthetic=False, source="wazuh"):
        normalized = normalize(alert, host_ips)
        received_at = time.time() if received is None else received
        normalized["received_at"] = received_at
        internal_id = alert["id"] if source == "wazuh" else source + ":" + alert["id"]
        normalized["source"] = source
        normalized["evidence"]["id"] = internal_id
        with self.connect() as db:
            db.execute("BEGIN IMMEDIATE")
            if db.execute(
                "SELECT 1 FROM inbox WHERE source=? AND external_id=?", (source, alert["id"])
            ).fetchone():
                return False
            # Preserve legacy IDs when possible, but never drop a different source's event on a PK collision.
            while db.execute("SELECT 1 FROM inbox WHERE id=?", (internal_id,)).fetchone():
                internal_id = uuid.uuid4().hex
            normalized["evidence"]["id"] = internal_id
            cur = db.execute(
                "INSERT OR IGNORE INTO inbox(id,received,alert,source,external_id,normalized,severity,event_type,synthetic,correlation_status,provenance) VALUES(?,?,?,?,?,?,?,?,?,?,?)",
                (
                    internal_id,
                    received_at,
                    json.dumps(alert),
                    source,
                    alert["id"],
                    json.dumps(normalized),
                    normalized["severity"],
                    normalized["event_type"],
                    int(synthetic),
                    normalized["correlation_status"],
                    "synthetic" if synthetic else "received",
                ),
            )
            if cur.rowcount == 1:
                self.audit("ingestion:" + source, "alert.received", internal_id, "accepted", db=db)
            return cur.rowcount == 1

    def pending_alerts(self):
        with self.connect() as db:
            return db.execute(
                "SELECT * FROM inbox WHERE case_id IS NULL AND correlation_status='pending' ORDER BY received,rowid"
            ).fetchall()

    def enqueue(self, incident, *, db=None, settings=None):
        if db is None:
            with self.connect() as connection:
                connection.execute("BEGIN IMMEDIATE")
                return self.enqueue(incident, db=connection, settings=settings)
        cid = uuid.uuid4().hex
        db.execute(
            "INSERT INTO cases(id,created,status,incident) VALUES(?,?,?,?)",
            (cid, time.time(), "queued", json.dumps(incident)),
        )
        db.executemany(
            "UPDATE inbox SET case_id=?,correlation_status='correlated' WHERE id=? AND case_id IS NULL",
            [(cid, aid) for aid in incident["raw_ids"]],
        )
        db.executemany(
            "INSERT OR IGNORE INTO incident_alerts VALUES(?,?,?)",
            [(cid, aid, "shared entity within received-time window") for aid in incident["raw_ids"]],
        )
        synthetic = db.execute("SELECT max(synthetic) FROM inbox WHERE case_id=?", (cid,)).fetchone()[0] or 0
        unknown = db.execute(
            "SELECT count(*) FROM inbox WHERE case_id=? AND provenance='legacy_unknown'", (cid,)
        ).fetchone()[0]
        db.execute(
            "UPDATE cases SET synthetic=?,provenance=? WHERE id=?",
            (synthetic, "synthetic" if synthetic else "legacy_unknown" if unknown else "received", cid),
        )
        self.new_run(cid, incident, db=db, settings=settings)
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

    def claim(self, cid, *, actor="legacy-reviewer", mode="dry-run", action="approve", ip=None):
        with self.connect() as db:
            db.execute("BEGIN IMMEDIATE")
            changed = db.execute(
                "UPDATE cases SET status='executing' WHERE id=? AND status='pending' AND workflow_status!='closed'",
                (cid,),
            ).rowcount
            if not changed:
                return False
            case = self.decode(db.execute("SELECT * FROM cases WHERE id=?", (cid,)).fetchone())
            run = db.execute("SELECT requested_by FROM runs WHERE id=?", (case["latest_run_id"],)).fetchone()
            db.execute(
                "INSERT INTO actions(ts,case_id,action,ip,mode,result,actor,requested_by,evidence,run_id,lease_until,approved_by,rejected_by) VALUES(?,?,?,?,?,'executing',?,?,?,?,?,?,?)",
                (
                    time.time(),
                    cid,
                    action,
                    ip,
                    mode,
                    actor,
                    run[0] if run else None,
                    json.dumps(case["verdict"].get("evidence_ids", [])),
                    case["latest_run_id"],
                    time.time() + 60,
                    actor if action == "approve" else None,
                    actor if action == "reject" else None,
                ),
            )
            self.audit(actor, "response." + action, cid, "claimed", db=db)
            return True

    def record_action(self, cid, action, ip, mode, status, actor="legacy-reviewer"):
        with self.connect() as db:
            db.execute("BEGIN IMMEDIATE")
            db.execute("UPDATE cases SET status=? WHERE id=?", (status, cid))
            changed = db.execute(
                "UPDATE actions SET result=?,ip=?,mode=?,actor=?,completed_at=? WHERE case_id=? AND result='executing'",
                (status, ip, mode, actor, time.time(), cid),
            ).rowcount
            if not changed:
                db.execute(
                    "INSERT INTO actions(ts,case_id,action,ip,mode,result,actor,completed_at) VALUES(?,?,?,?,?,?,?,?)",
                    (time.time(), cid, action, ip, mode, status, actor, time.time()),
                )
            if action == "approve":
                completed = db.execute(
                    "SELECT * FROM actions WHERE case_id=? AND action='approve' AND result=? ORDER BY id DESC LIMIT 1",
                    (cid, status),
                ).fetchone()
                self.queue_response(db, completed)
            db.execute("UPDATE thehive_sync SET available=0 WHERE case_id=?", (cid,))
            self.audit(actor, "response." + action, cid, status, db=db)

    @staticmethod
    def queue_response(db, action):
        case = db.execute("SELECT synthetic FROM cases WHERE id=?", (action["case_id"],)).fetchone()
        if not case or case["synthetic"]:
            return
        event_id = uuid.uuid4().hex
        event = {
            "schema_version": 1,
            "event_id": event_id,
            "event": "response.completed",
            "case_id": action["case_id"],
            "action_id": action["id"],
            "decision": "approve",
            "ip": action["ip"],
            "status": action["result"],
            "mode": action["mode"],
            "blocked": action["result"] == "blocked" and action["mode"] == "ssh",
            "verification_status": "not_verified",
            "completed_at": action["completed_at"],
        }
        db.execute(
            "INSERT OR IGNORE INTO shuffle_outbox(id,action_id,case_id,payload) VALUES(?,?,?,?)",
            (event_id, action["id"], action["case_id"], json.dumps(event)),
        )

    def recover(self, *, stale_only=False):
        with self.connect() as db:
            db.execute("BEGIN IMMEDIATE")
            recovering = db.execute(
                "SELECT id FROM actions WHERE action='approve' AND result='executing'"
                + (" AND (lease_until IS NULL OR lease_until<?)" if stale_only else ""),
                (time.time(),) if stale_only else (),
            ).fetchall()
            if stale_only:
                db.execute(
                    "UPDATE cases SET status='action_unknown' WHERE status='executing' AND (id IN (SELECT case_id FROM actions WHERE result='executing' AND (lease_until IS NULL OR lease_until<?)) OR NOT EXISTS(SELECT 1 FROM actions a WHERE a.case_id=cases.id AND a.result='executing'))",
                    (time.time(),),
                )
                db.execute(
                    "UPDATE actions SET result='action_unknown' WHERE result='executing' AND (lease_until IS NULL OR lease_until<?)",
                    (time.time(),),
                )
            else:
                db.execute("UPDATE cases SET status='action_unknown' WHERE status='executing'")
                db.execute("UPDATE actions SET result='action_unknown' WHERE result='executing'")
            for row in recovering:
                action = db.execute("SELECT * FROM actions WHERE id=?", (row["id"],)).fetchone()
                if action["result"] == "action_unknown":
                    self.queue_response(db, action)
                    db.execute("UPDATE thehive_sync SET available=0 WHERE case_id=?", (action["case_id"],))

    def metrics(self):
        with self.connect() as db:
            alerts, last = db.execute("SELECT count(*),max(received) FROM inbox").fetchone()
            cases = db.execute("SELECT count(*) FROM cases").fetchone()[0]
            calls, blocked, errors, call_ms = db.execute(
                "SELECT count(*),coalesce(sum(error='Blocked'),0),"
                "coalesce(sum(error IS NOT NULL AND error!='Blocked'),0),"
                "avg(CASE WHEN error IS NULL OR error!='Blocked' THEN duration_ms END) FROM ledger WHERE agent IN ('net','host','judge')"
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

    def audit(self, actor, action, target, result, *, db=None):
        if db is None:
            with self.connect() as connection:
                return self.audit(actor, action, target, result, db=connection)
        db.execute(
            "INSERT INTO audit(ts,actor,action,target,result) VALUES(?,?,?,?,?)",
            (time.time(), actor, action, target, result),
        )

    def new_run(self, cid, snapshot=None, *, parent=None, actor="worker", db=None, settings=None):
        if db is None:
            with self.connect() as connection:
                connection.execute("BEGIN IMMEDIATE")
                return self.new_run(
                    cid, snapshot, parent=parent, actor=actor, db=connection, settings=settings
                )
        case = db.execute("SELECT * FROM cases WHERE id=?", (cid,)).fetchone()
        if not case:
            raise KeyError(cid)
        if parent is not None:
            original = db.execute("SELECT * FROM runs WHERE id=? AND case_id=?", (parent, cid)).fetchone()
            if not original:
                raise ValueError("Replay parent is not an investigation of this incident")
            snapshot, cutoff = json.loads(original["evidence"]), original["cutoff"]
        else:
            snapshot = snapshot or json.loads(case["incident"])
            cutoff = time.time()
        rid = uuid.uuid4().hex
        now = time.time()
        db.execute(
            "INSERT INTO runs(id,case_id,created,status,evidence,cutoff,prompt_version,provider,model,mode,replay,parent_run_id,requested_by) VALUES(?,?,?,'queued',?,?,?,?,?,?,?,?,?)",
            (
                rid,
                cid,
                now,
                json.dumps(snapshot),
                cutoff,
                "net-host-judge-v2",
                None if not settings else "mock" if settings.llm_mode == "mock" else "openai-compatible",
                settings.llm_model if settings and settings.llm_mode == "live" else None,
                settings.llm_mode if settings else "unconfigured",
                int(parent is not None),
                parent,
                actor,
            ),
        )
        db.execute(
            "INSERT INTO jobs(id,kind,run_id,case_id,status,available,created) VALUES(?,'investigate',?,?,'queued',?,?)",
            (uuid.uuid4().hex, rid, cid, now, now),
        )
        db.executemany(
            "INSERT INTO steps(id,run_id,role,status,attempt) VALUES(?,?,?,'queued',0)",
            [(uuid.uuid4().hex, rid, role) for role in ("net", "host", "judge")],
        )
        if parent is None:
            db.execute(
                "UPDATE cases SET latest_run_id=?,workflow_status='investigating' WHERE id=?", (rid, cid)
            )
        self.audit(
            actor, "investigation.queued" if not parent else "investigation.replay", rid, "queued", db=db
        )
        return rid

    def get_run(self, rid):
        with self.connect() as db:
            row = db.execute("SELECT * FROM runs WHERE id=?", (rid,)).fetchone()
        if not row:
            return None
        result = dict(row)
        result["evidence"] = json.loads(result["evidence"])
        result["verdict"] = json.loads(result["verdict"]) if result["verdict"] else None
        result["parameters"] = json.loads(result["parameters"]) if result["parameters"] else None
        return result

    def claim_job(self, owner, *, now=None, lease=120):
        now = time.time() if now is None else now
        with self.connect() as db:
            db.execute("BEGIN IMMEDIATE")
            db.execute(
                "UPDATE jobs SET status='queued',owner=NULL WHERE status='running' AND lease_until<? AND attempts<max_attempts",
                (now,),
            )
            expired = db.execute(
                "SELECT * FROM jobs WHERE status='running' AND lease_until<? AND attempts>=max_attempts",
                (now,),
            ).fetchall()
            for job in expired:
                self._fail_run(db, job, "LeaseExpired")
            job = db.execute(
                "SELECT * FROM jobs WHERE status='queued' AND available<=? ORDER BY available,id LIMIT 1",
                (now,),
            ).fetchone()
            if not job:
                return None
            db.execute(
                "UPDATE jobs SET status='running',owner=?,lease_until=?,attempts=attempts+1 WHERE id=?",
                (owner, now + lease, job["id"]),
            )
            db.execute("UPDATE runs SET status='running' WHERE id=?", (job["run_id"],))
            return dict(db.execute("SELECT * FROM jobs WHERE id=?", (job["id"],)).fetchone())

    def heartbeat(self, owner, job=None, lease=120):
        now = time.time()
        with self.connect() as db:
            db.execute(
                "INSERT INTO workers VALUES(?,?,?) ON CONFLICT(id) DO UPDATE SET last_seen=excluded.last_seen,current_job=excluded.current_job",
                (owner, now, job),
            )
            if job:
                db.execute(
                    "UPDATE jobs SET lease_until=? WHERE id=? AND owner=? AND status='running'",
                    (now + lease, job, owner),
                )

    @staticmethod
    def queue_integrations(db, cid):
        row = db.execute("SELECT incident,synthetic FROM cases WHERE id=?", (cid,)).fetchone()
        if not row or row["synthetic"]:
            return
        db.execute("INSERT OR IGNORE INTO thehive_sync(case_id) VALUES(?)", (cid,))
        for ip in public_ips(json.loads(row["incident"]).get("ips", [])):
            db.execute("INSERT OR IGNORE INTO vt_jobs(case_id,ip) VALUES(?,?)", (cid, ip))

    def complete_job(self, job, verdict, restore):
        with self.connect() as db:
            db.execute("BEGIN IMMEDIATE")
            current = db.execute(
                "SELECT * FROM jobs WHERE id=? AND owner=? AND status='running'", (job["id"], job["owner"])
            ).fetchone()
            if not current:
                return False
            run = db.execute("SELECT replay FROM runs WHERE id=?", (job["run_id"],)).fetchone()
            db.execute(
                "UPDATE runs SET status='completed',finished=?,verdict=?,error=NULL WHERE id=?",
                (time.time(), json.dumps(verdict), job["run_id"]),
            )
            db.execute(
                "UPDATE jobs SET status='completed',lease_until=NULL,error=NULL WHERE id=?", (job["id"],)
            )
            if not run["replay"]:
                Store.queue_integrations(db, job["case_id"])
                db.execute(
                    "UPDATE cases SET status='pending',workflow_status='review',verdict=?,restore=? WHERE id=?",
                    (json.dumps(verdict), json.dumps(restore), job["case_id"]),
                )
            self.audit(job["owner"], "investigation.completed", job["run_id"], "completed", db=db)
            return True

    def fail_job(self, job, error, retryable):
        with self.connect() as db:
            db.execute("BEGIN IMMEDIATE")
            current = db.execute(
                "SELECT * FROM jobs WHERE id=? AND owner=? AND status='running'", (job["id"], job["owner"])
            ).fetchone()
            if not current:
                return
            if retryable and current["attempts"] < current["max_attempts"]:
                db.execute(
                    "UPDATE jobs SET status='queued',available=?,error=?,owner=NULL,lease_until=NULL WHERE id=?",
                    (time.time() + min(60, 2 ** current["attempts"]), error, job["id"]),
                )
                db.execute("UPDATE runs SET status='queued',error=? WHERE id=?", (error, job["run_id"]))
            else:
                self._fail_run(db, current, error)

    @staticmethod
    def _fail_run(db, job, error):
        db.execute("UPDATE steps SET status='skipped' WHERE run_id=? AND status='queued'", (job["run_id"],))
        db.execute(
            "UPDATE jobs SET status='dead_letter',error=?,lease_until=NULL WHERE id=?", (error, job["id"])
        )
        db.execute(
            "UPDATE runs SET status='failed',error=?,finished=? WHERE id=?",
            (error, time.time(), job["run_id"]),
        )
        run = db.execute("SELECT replay,mode FROM runs WHERE id=?", (job["run_id"],)).fetchone()
        if not run["replay"]:
            Store.queue_integrations(db, job["case_id"])
            verdict = {
                "verdict": "review",
                "confidence": 0,
                "block_ip": None,
                "evidence_ids": [],
                "grounded": 0,
                "mode": run["mode"],
                "reason": "Analysis unavailable: " + error,
                "review_reason": error,
            }
            db.execute(
                "UPDATE cases SET status='pending',workflow_status='review',verdict=? WHERE id=?",
                (json.dumps(verdict), job["case_id"]),
            )
