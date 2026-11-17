import io
import os
import sqlite3
import subprocess
import sys
import tarfile
from contextlib import closing
from dataclasses import replace
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from scripts.migration_lab import BASELINE, V2_TABLES, assert_relationships, seed_v1, snapshot
from src.api.main import create_app
from src.migrations import migrate
from src.service import Service
from src.storage import Store


def backup(source, target):
    with closing(sqlite3.connect(Path(source).resolve().as_uri() + "?mode=ro", uri=True)) as src:
        with closing(sqlite3.connect(target)) as dst:
            src.backup(dst)


def test_v1_migration_preserves_every_record_twice_and_relationships(tmp_path):
    path = tmp_path / "previous.db"
    before = seed_v1(path)
    assert V2_TABLES.isdisjoint(before)
    Store(path)
    first = snapshot(path)
    assert set(first) == set(before) | V2_TABLES
    for table, rows in before.items():
        if table == "schema_migrations":
            assert rows[0] in first[table] and {r[0] for r in first[table]} == {1, 2}
        else:
            assert first[table] == rows, table
    Store(path)
    assert snapshot(path) == first
    assert_relationships(path)
    # The historical schema has no declared foreign keys. Audit actual relationships too.
    with sqlite3.connect(path) as db:
        assert db.execute("PRAGMA foreign_key_list(incident_alerts)").fetchall() == []


def test_migrated_database_new_backend_and_worker(settings, tmp_path):
    path = tmp_path / "previous.db"
    seed_v1(path)
    config = replace(settings, db=str(path))
    worker = Service(config)
    worker.tick()
    with TestClient(create_app(config, worker=False)) as client:
        login = client.post(
            "/api/v1/auth/login", json={"username": "admin", "password": "lab-review-" + "r" * 32}
        )
        client.headers["X-CSRF-Token"] = login.json()["csrf"]
        assert client.get("/ready").status_code == 200
        assert client.get("/api/v1/incidents").json()["total"] == 2
        assert client.post("/api/v1/assistant/query", json={"message": "pending"}).json()["facts"]
    assert_relationships(path)


def test_migration_sql_failure_rolls_back_without_caller_transaction(tmp_path):
    path = tmp_path / "previous.db"
    before = seed_v1(path)

    class FailingConnection(sqlite3.Connection):
        def execute(self, statement, *args, **kwargs):
            if statement.startswith("CREATE UNIQUE INDEX"):
                raise sqlite3.OperationalError("Injected migration failure")
            return super().execute(statement, *args, **kwargs)

    with closing(sqlite3.connect(path, factory=FailingConnection)) as db:
        db.row_factory = sqlite3.Row
        with pytest.raises(sqlite3.OperationalError, match="Injected"):
            migrate(db)
        assert not db.in_transaction
    assert snapshot(path) == before
    Store(path)
    assert_relationships(path)


def test_abrupt_process_exit_before_migration_commit_is_recoverable(tmp_path):
    path = tmp_path / "interrupted.db"
    before = seed_v1(path)
    code = """
import os, sqlite3, sys
from src.migrations import migrate
db=sqlite3.connect(sys.argv[1]); db.row_factory=sqlite3.Row
def stop(sql):
    if sql.startswith('INSERT OR IGNORE INTO schema_migrations VALUES(2,'):
        os._exit(77)
db.set_trace_callback(stop)
migrate(db)
"""
    result = subprocess.run([sys.executable, "-c", code, str(path)], stdin=subprocess.DEVNULL, check=False)
    assert result.returncode == 77
    assert snapshot(path) == before
    Store(path)
    assert_relationships(path)


def test_consistent_wal_backup_restore_and_previous_application_compatibility(tmp_path):
    path, protected_backup, restored = (tmp_path / name for name in ("v1.db", "protected.db", "restored.db"))
    before = seed_v1(path)
    backup(path, protected_backup)
    Store(path)
    migrated = snapshot(path)
    old = tmp_path / "previous-source"
    old.mkdir()
    archive = subprocess.check_output(["git", "archive", BASELINE, "src"], stdin=subprocess.DEVNULL)
    with tarfile.open(fileobj=io.BytesIO(archive)) as source:
        source.extractall(old, filter="data")
    code = """
import sys
from fastapi.testclient import TestClient
from src.api.main import create_app
from src.service import Service
from src.settings import Settings
config=Settings(db=sys.argv[1], ingest_key='i'*32, approve_key='r'*32)
service=Service(config); service.tick()
assert len(service.store.cases())==2
with TestClient(create_app(config,worker=False)) as client:
    assert client.get('/live').status_code==200
    login=client.post('/api/v1/auth/login',json={'username':'admin','password':'lab-review-'+'r'*32})
    assert login.status_code==200
    assert client.get('/api/v1/incidents').json()['total']==2
"""
    env = {**os.environ, "PYTHON_DOTENV_DISABLED": "1", "PYTHONPATH": str(old)}
    result = subprocess.run(
        [sys.executable, "-c", code, str(path)],
        cwd=old,
        env=env,
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
    )
    assert result.returncode == 0, result.stderr.decode(errors="replace")[-1500:]
    after = snapshot(path)
    for table in ("cases", "runs", "actions", "inbox", "incident_alerts", "shuffle_outbox"):
        assert after[table] == migrated[table]
    # Protected pre-upgrade backup remains unchanged; restoration uses SQLite backup, not WAL file copies.
    assert snapshot(protected_backup) == before
    backup(protected_backup, restored)
    assert snapshot(restored) == before
    assert_relationships(restored)


def test_online_backup_includes_committed_wal_and_excludes_inflight_transaction(tmp_path):
    path, copied = tmp_path / "wal.db", tmp_path / "copy.db"
    seed_v1(path)
    with closing(sqlite3.connect(path)) as writer:
        writer.execute("PRAGMA journal_mode=WAL")
        writer.execute(
            "INSERT INTO notes(case_id,actor,created,body) SELECT id,'lab',1,'committed WAL' FROM cases LIMIT 1"
        )
        writer.commit()
        committed = snapshot(path)
        writer.execute(
            "INSERT INTO notes(case_id,actor,created,body) SELECT id,'lab',2,'not committed' FROM cases LIMIT 1"
        )
        backup(path, copied)
        assert snapshot(copied) == committed
        writer.rollback()
    assert_relationships(copied)
