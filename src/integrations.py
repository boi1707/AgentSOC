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
        hashes = db.execute(
            "SELECT sha256,status,error,report FROM vt_hash_jobs WHERE case_id=? ORDER BY sha256", (cid,)
        ).fetchall()
        events = db.execute(
            "SELECT id,status,attempts,error,delivered FROM shuffle_outbox WHERE case_id=? "
            "UNION ALL SELECT id,status,attempts,error,delivered FROM notification_outbox WHERE case_id=?",
            (cid, cid),
        ).fetchall()
    return {
        "thehive": dict(hive) if hive else None,
        "virustotal": [
            {
                **dict(row),
                "indicator_type": "ip",
                "report": json.loads(row["report"]) if row["report"] else None,
            }
            for row in vt
        ],
        "virustotal_hashes": [
            {
                **dict(row),
                "indicator_type": "sha256",
                "report": json.loads(row["report"]) if row["report"] else None,
            }
            for row in hashes
        ],
        "shuffle": [dict(row) for row in events],
    }


def integration_health(store, settings):
    with store.connect() as db:
        result = {}
        for name, table, column, enabled in (
            ("thehive", "thehive_sync", "state", bool(settings.thehive_url and settings.thehive_key)),
            ("shuffle", "shuffle_outbox", "status", bool(settings.shuffle_hook)),
            ("proposal_notifications", "notification_outbox", "status", bool(settings.shuffle_hook)),
            ("virustotal", "vt_jobs", "status", bool(settings.vt_key)),
        ):
            counts = dict(db.execute(f"SELECT {column},count(*) FROM {table} GROUP BY {column}"))
            errors = db.execute(f"SELECT count(*) FROM {table} WHERE error IS NOT NULL").fetchone()[0]
            if name == "virustotal":
                for state, count in db.execute("SELECT status,count(*) FROM vt_hash_jobs GROUP BY status"):
                    counts[state] = counts.get(state, 0) + count
                errors += db.execute("SELECT count(*) FROM vt_hash_jobs WHERE error IS NOT NULL").fetchone()[
                    0
                ]
            result[name] = {
                "configured": enabled,
                "active": enabled and not settings.demo,
                "states": counts,
                "errors": errors,
            }
            if name == "virustotal":
                result[name]["sha256_enabled"] = enabled and settings.vt_sha256_enabled and not settings.demo
    return result
