"""Read-only integration status for the SOC console; never includes credentials."""

import json


def incident_integrations(store, cid):
    with store.connect() as db:
        hive = db.execute(
            "SELECT remote_id,state,error,available FROM thehive_sync WHERE case_id=?", (cid,)
        ).fetchone()
        vt = db.execute(
            "SELECT ip,status,error,report FROM vt_jobs WHERE case_id=? ORDER BY ip", (cid,)
        ).fetchall()
        events = db.execute(
            "SELECT id,status,attempts,error,delivered FROM shuffle_outbox WHERE case_id=? ORDER BY rowid DESC",
            (cid,),
        ).fetchall()
    return {
        "thehive": dict(hive) if hive else None,
        "virustotal": [
            {**dict(row), "report": json.loads(row["report"]) if row["report"] else None} for row in vt
        ],
        "shuffle": [dict(row) for row in events],
    }


def integration_health(store, settings):
    with store.connect() as db:
        result = {}
        for name, table, column, enabled in (
            ("thehive", "thehive_sync", "state", bool(settings.thehive_url and settings.thehive_key)),
            ("shuffle", "shuffle_outbox", "status", bool(settings.shuffle_hook)),
            ("virustotal", "vt_jobs", "status", bool(settings.vt_key)),
        ):
            counts = dict(db.execute(f"SELECT {column},count(*) FROM {table} GROUP BY {column}"))
            errors = db.execute(f"SELECT count(*) FROM {table} WHERE error IS NOT NULL").fetchone()[0]
            result[name] = {
                "configured": enabled,
                "active": enabled and not settings.demo,
                "states": counts,
                "errors": errors,
            }
    return result
