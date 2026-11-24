"""Additive, transactional upgrades; no existing tables or evidence are dropped."""

import json
import time

from .adapters.wazuh import normalize

SQL = """
CREATE TABLE IF NOT EXISTS callback_receipts(id TEXT PRIMARY KEY,created REAL NOT NULL,digest TEXT NOT NULL,result TEXT);
CREATE TABLE IF NOT EXISTS notification_outbox(id TEXT PRIMARY KEY,case_id TEXT NOT NULL,
 payload TEXT NOT NULL,status TEXT NOT NULL DEFAULT 'pending',attempts INTEGER NOT NULL DEFAULT 0,
 available REAL NOT NULL DEFAULT 0,lease_until REAL NOT NULL DEFAULT 0,error TEXT,delivered REAL);
CREATE TABLE IF NOT EXISTS shuffle_outbox(id TEXT PRIMARY KEY,action_id INTEGER NOT NULL UNIQUE,case_id TEXT NOT NULL,
 payload TEXT NOT NULL,status TEXT NOT NULL DEFAULT 'pending',attempts INTEGER NOT NULL DEFAULT 0,
 available REAL NOT NULL DEFAULT 0,lease_until REAL NOT NULL DEFAULT 0,error TEXT,delivered REAL);
CREATE TABLE IF NOT EXISTS vt_jobs(case_id TEXT NOT NULL,ip TEXT NOT NULL,status TEXT NOT NULL DEFAULT 'pending',
 available REAL NOT NULL DEFAULT 0,lease_until REAL NOT NULL DEFAULT 0,error TEXT,report TEXT,
 PRIMARY KEY(case_id,ip));
CREATE TABLE IF NOT EXISTS vt_cache(ip TEXT PRIMARY KEY,report TEXT NOT NULL,expires REAL NOT NULL);
CREATE TABLE IF NOT EXISTS vt_budget(id INTEGER PRIMARY KEY CHECK(id=1),day TEXT NOT NULL,count INTEGER NOT NULL,next_at REAL NOT NULL);

CREATE TABLE IF NOT EXISTS thehive_sync(case_id TEXT PRIMARY KEY,remote_id TEXT,payload_hash TEXT,
 state TEXT NOT NULL DEFAULT 'pending',available REAL NOT NULL DEFAULT 0,lease_until REAL NOT NULL DEFAULT 0,error TEXT);
CREATE INDEX IF NOT EXISTS thehive_due ON thehive_sync(available,lease_until);
CREATE INDEX IF NOT EXISTS shuffle_due ON shuffle_outbox(status,available,lease_until);
CREATE INDEX IF NOT EXISTS vt_due ON vt_jobs(status,available,lease_until);
CREATE TABLE IF NOT EXISTS schema_migrations(version INTEGER PRIMARY KEY, applied REAL NOT NULL);
CREATE TABLE IF NOT EXISTS incident_alerts(case_id TEXT NOT NULL,alert_id TEXT NOT NULL,reason TEXT NOT NULL,PRIMARY KEY(case_id,alert_id));
CREATE TABLE IF NOT EXISTS runs(id TEXT PRIMARY KEY,case_id TEXT NOT NULL,created REAL NOT NULL,finished REAL,status TEXT NOT NULL,
 evidence TEXT NOT NULL,cutoff REAL NOT NULL,prompt_version TEXT NOT NULL,provider TEXT,model TEXT,mode TEXT NOT NULL,
 replay INTEGER NOT NULL DEFAULT 0,parent_run_id TEXT,verdict TEXT,error TEXT,requested_by TEXT NOT NULL,parameters TEXT);
CREATE TABLE IF NOT EXISTS jobs(id TEXT PRIMARY KEY,kind TEXT NOT NULL,run_id TEXT NOT NULL UNIQUE,case_id TEXT NOT NULL,
 status TEXT NOT NULL,attempts INTEGER NOT NULL DEFAULT 0,max_attempts INTEGER NOT NULL DEFAULT 3,
 available REAL NOT NULL,created REAL NOT NULL,owner TEXT,lease_until REAL,error TEXT);
CREATE INDEX IF NOT EXISTS jobs_available ON jobs(status,available);
CREATE TABLE IF NOT EXISTS workers(id TEXT PRIMARY KEY,last_seen REAL NOT NULL,current_job TEXT);
CREATE TABLE IF NOT EXISTS audit(id INTEGER PRIMARY KEY,ts REAL NOT NULL,actor TEXT NOT NULL,action TEXT NOT NULL,target TEXT,result TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS notes(id INTEGER PRIMARY KEY,case_id TEXT NOT NULL,actor TEXT NOT NULL,created REAL NOT NULL,body TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS users(username TEXT PRIMARY KEY,password_hash TEXT NOT NULL,role TEXT NOT NULL,created REAL NOT NULL,disabled INTEGER NOT NULL DEFAULT 0);
CREATE TABLE IF NOT EXISTS sessions(token_hash TEXT PRIMARY KEY,username TEXT NOT NULL,csrf TEXT NOT NULL,expires REAL NOT NULL);
CREATE TABLE IF NOT EXISTS steps(id TEXT PRIMARY KEY,run_id TEXT NOT NULL,role TEXT NOT NULL,status TEXT NOT NULL,attempt INTEGER NOT NULL,started REAL,finished REAL,error TEXT);
"""

V3_STATEMENTS = (
    """CREATE TABLE IF NOT EXISTS managed_block_leases(
      id TEXT PRIMARY KEY,
      proposal_id TEXT NOT NULL UNIQUE,
      run_id TEXT NOT NULL REFERENCES runs(id),
      case_id TEXT NOT NULL REFERENCES cases(id),
      action_id INTEGER NOT NULL UNIQUE REFERENCES actions(id),
      firewall_identity TEXT NOT NULL,
      alias_identity TEXT NOT NULL,
      source_ip TEXT NOT NULL,
      approved_by TEXT NOT NULL,
      created_at REAL NOT NULL,
      activated_at REAL,
      expires_at REAL,
      desired_state TEXT NOT NULL CHECK(desired_state IN ('present', 'absent')),
      observed_state TEXT NOT NULL DEFAULT 'unknown' CHECK(observed_state IN ('present', 'absent', 'unknown')),
      ownership TEXT NOT NULL DEFAULT 'unknown' CHECK(ownership IN ('managed', 'external', 'unknown')),
      ownership_marker TEXT,
      execution_owner TEXT,
      execution_lease_until REAL,
      attempts INTEGER NOT NULL DEFAULT 0,
      next_retry_at REAL NOT NULL,
      last_error TEXT,
      last_verified_at REAL,
      CHECK ((activated_at IS NULL AND expires_at IS NULL) OR
             (activated_at IS NOT NULL AND expires_at IS NOT NULL AND expires_at > activated_at))
    )""",
    "CREATE INDEX IF NOT EXISTS managed_blocks_due ON managed_block_leases(desired_state, next_retry_at, expires_at)",
    """CREATE INDEX IF NOT EXISTS managed_blocks_membership
       ON managed_block_leases(firewall_identity, alias_identity, source_ip, expires_at)""",
)


def migrate(db, *, host_ips=None):
    try:
        _apply(db, host_ips=host_ips)
    except BaseException:
        # Standalone callers receive the same rollback guarantee as Store.connect callers.
        db.rollback()
        raise


def _apply(db, *, host_ips=None):
    # executescript starts its own transaction; keep extension DDL and data upgrades together.
    db.executescript("BEGIN IMMEDIATE;\n" + SQL)
    additions = {
        "inbox": {
            "provenance": "TEXT NOT NULL DEFAULT 'legacy_unknown'",
            "source": "TEXT NOT NULL DEFAULT 'wazuh'",
            "external_id": "TEXT",
            "normalized": "TEXT",
            "severity": "TEXT",
            "event_type": "TEXT",
            "synthetic": "INTEGER NOT NULL DEFAULT 0",
            "correlation_status": "TEXT NOT NULL DEFAULT 'pending'",
        },
        "cases": {
            "provenance": "TEXT NOT NULL DEFAULT 'legacy_unknown'",
            "workflow_status": "TEXT NOT NULL DEFAULT 'open'",
            "latest_run_id": "TEXT",
            "synthetic": "INTEGER NOT NULL DEFAULT 0",
        },
        "ledger": {
            "parameters": "TEXT",
            "model_source": "TEXT",
            "run_id": "TEXT",
            "step_id": "TEXT",
            "provider": "TEXT",
            "model": "TEXT",
            "prompt_version": "TEXT",
            "attempt": "INTEGER",
            "tool_name": "TEXT",
        },
        "actions": {
            "approved_by": "TEXT",
            "rejected_by": "TEXT",
            "action_type": "TEXT NOT NULL DEFAULT 'block_ip'",
            "completed_at": "REAL",
            "lease_until": "REAL",
            "actor": "TEXT",
            "requested_by": "TEXT",
            "evidence": "TEXT",
            "verification_status": "TEXT NOT NULL DEFAULT 'not_verified'",
            "run_id": "TEXT",
        },
        "runs": {"parameters": "TEXT"},
    }
    for table, columns in additions.items():
        existing = {r[1] for r in db.execute(f"PRAGMA table_info({table})")}
        for name, definition in columns.items():
            if name not in existing:
                db.execute(f"ALTER TABLE {table} ADD COLUMN {name} {definition}")
                if table == "cases" and name == "workflow_status":
                    db.execute(
                        "UPDATE cases SET workflow_status=CASE WHEN status='queued' THEN 'investigating' WHEN status IN ('pending','executing','action_unknown') THEN 'review' ELSE 'open' END"
                    )
    for row in db.execute("SELECT id,alert,received,case_id FROM inbox WHERE normalized IS NULL").fetchall():
        try:
            value = normalize(json.loads(row["alert"]), host_ips)
        except (ValueError, TypeError, KeyError):
            value = {
                "schema_version": 0,
                "entities": [],
                "evidence": {},
                "severity": "info",
                "event_type": "legacy_unknown",
                "correlation_status": "uncorrelated",
            }
        value["received_at"] = row["received"]
        value["backfilled"] = True
        db.execute(
            "UPDATE inbox SET external_id=id,normalized=?,severity=?,event_type=?,correlation_status=? WHERE id=?",
            (
                json.dumps(value),
                value["severity"],
                value["event_type"],
                "correlated" if row["case_id"] else value["correlation_status"],
                row["id"],
            ),
        )
    db.execute("CREATE UNIQUE INDEX IF NOT EXISTS inbox_source_id ON inbox(source,external_id)")
    db.execute("CREATE INDEX IF NOT EXISTS inbox_filters ON inbox(received,severity,event_type)")
    # Preserve old evidence links; old runs/steps remain explicitly unavailable rather than invented.
    for row in db.execute("SELECT id,incident FROM cases").fetchall():
        for aid in json.loads(row["incident"]).get("raw_ids", []):
            db.execute(
                "INSERT OR IGNORE INTO incident_alerts VALUES(?,?,?)",
                (row["id"], aid, "legacy correlation; original rationale unavailable"),
            )
    db.execute("INSERT OR IGNORE INTO schema_migrations VALUES(1,?)", (time.time(),))
    db.execute("INSERT OR IGNORE INTO schema_migrations VALUES(2,?)", (time.time(),))
    for statement in V3_STATEMENTS:
        db.execute(statement)
    lease_columns = {row[1] for row in db.execute("PRAGMA table_info(managed_block_leases)")}
    for name, definition in {
        "activation_deadline": "REAL",
        "block_ttl_seconds": "INTEGER",
        "block_requested_at": "REAL",
    }.items():
        if name not in lease_columns:
            db.execute(f"ALTER TABLE managed_block_leases ADD COLUMN {name} {definition}")
    # An earlier development build could have sent a write once its own marker was saved.
    db.execute(
        """UPDATE managed_block_leases SET block_requested_at=created_at
           WHERE block_requested_at IS NULL AND ownership_marker=id"""
    )
    db.execute("INSERT OR IGNORE INTO schema_migrations VALUES(3,?)", (time.time(),))
    db.commit()
