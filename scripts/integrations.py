"""Inspect durable integration queues or explicitly enqueue one existing case."""

import argparse
import json
import sqlite3
from contextlib import closing
from pathlib import Path


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--db", default="data/agentsoc.db")
    parser.add_argument("--case")
    parser.add_argument(
        "--queue-case",
        action="store_true",
        help="Explicitly queue --case for TheHive/VT; a running worker may send it",
    )
    args = parser.parse_args()
    if args.queue_case and not args.case:
        parser.error("--queue-case requires --case")
    path = Path(args.db).resolve()
    if not path.is_file():
        parser.error("Database does not exist")
    if args.queue_case:
        from src.storage import Store

        store = Store(path)
        case = store.get(args.case)
        if case and case.get("synthetic"):
            parser.error("Synthetic cases cannot be queued for external integrations")
        if not case or case["status"] == "queued" or not case["verdict"]:
            parser.error("Case must exist and have a completed verdict")
        with store.connect() as db:
            db.execute("BEGIN IMMEDIATE")
            Store.queue_integrations(db, args.case)
        print("Case queued; no response action or Shuffle event was executed.")
    with closing(sqlite3.connect(path.as_uri() + "?mode=ro", uri=True)) as db:
        db.row_factory = sqlite3.Row
        result = {}
        for table, columns in (
            ("thehive_sync", "case_id,remote_id,state,error"),
            ("vt_jobs", "case_id,ip,status,error"),
            ("shuffle_outbox", "id,case_id,status,attempts,error"),
        ):
            sql = f"SELECT {columns} FROM {table}" + (" WHERE case_id=?" if args.case else "") + " LIMIT 100"
            result[table] = [dict(row) for row in db.execute(sql, (args.case,) if args.case else ())]
        print(json.dumps(result, indent=2))


if __name__ == "__main__":
    main()
