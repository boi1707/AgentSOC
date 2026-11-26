"""Optional IP/SHA256 reputation GETs; never uploads files, URLs or raw alerts."""

import ipaddress
import json
import logging
import re
import time
from datetime import UTC, datetime

import httpx

log = logging.getLogger("agentsoc.virustotal")
STATS = ("malicious", "suspicious", "harmless", "undetected", "timeout")


def sha256_values(alerts):
    values = set()
    for alert in alerts:
        if not isinstance(alert, dict):
            continue
        for field in ("hashes", "sha256"):
            raw = alert.get(field)
            if not isinstance(raw, str):
                continue
            if re.fullmatch(r"[a-fA-F0-9]{64}", raw):
                values.add(raw.lower())
            if field == "hashes":
                values.update(
                    v.lower() for v in re.findall(r"(?i)\bSHA256\s*[:=]\s*([a-f0-9]{64})(?=$|[,;\s])", raw)
                )
    return sorted(values)[:3]


def public_ips(values, excluded=()):
    excluded = {str(ipaddress.ip_address(v)) for v in excluded}
    result = set()
    for value in values:
        try:
            ip = ipaddress.ip_address(value)
        except (ValueError, TypeError):
            continue
        if (
            ip.is_global
            and not ip.is_multicast
            and not ip.is_reserved
            and not ip.is_unspecified
            and str(ip) not in excluded
        ):
            result.add(str(ip))
    return sorted(result)[:3]


def _report(response, indicator_type="ip"):
    attributes = response.json()["data"]["attributes"]
    stats = attributes.get("last_analysis_stats")
    if not isinstance(stats, dict):
        raise ValueError("InvalidStatistics")
    result = {}
    for key in STATS:
        value = stats.get(key, 0)
        if type(value) is not int or not 0 <= value <= 100000:
            raise ValueError("InvalidStatistics")
        result[key] = value
    return {
        "source": "virustotal",
        "indicator_type": indicator_type,
        "status": "reported",
        "stats": result,
        "queried_at": time.time(),
    }


def enrich_pending(store, settings, *, transport=None):
    if not settings.vt_key or settings.demo:
        return
    now = time.time()
    lease = now + 60
    with store.connect() as db:
        db.execute("BEGIN IMMEDIATE")
        row = db.execute(
            "SELECT case_id,ip AS indicator,'ip' AS kind,available FROM vt_jobs "
            "WHERE status IN ('pending','retry') AND available<=? AND lease_until<=? "
            "UNION ALL SELECT case_id,sha256 AS indicator,'sha256' AS kind,available FROM vt_hash_jobs "
            "WHERE status IN ('pending','retry') AND available<=? AND lease_until<=? AND ?=1 "
            "ORDER BY available,case_id,kind,indicator LIMIT 1",
            (now, now, now, now, int(settings.vt_sha256_enabled)),
        ).fetchone()
        if not row:
            return
        cid, value, kind = row["case_id"], row["indicator"], row["kind"]
        # All interpolated SQL identifiers below are chosen from these fixed constants.
        table, cache_table, column = (
            ("vt_jobs", "vt_cache", "ip") if kind == "ip" else ("vt_hash_jobs", "vt_hash_cache", "sha256")
        )
        valid = (
            bool(public_ips([value], settings.vt_exclude_ips))
            if kind == "ip"
            else bool(re.fullmatch(r"[a-f0-9]{64}", value))
        )
        case = db.execute("SELECT synthetic FROM cases WHERE id=?", (cid,)).fetchone()
        if not valid or not case or case["synthetic"]:
            db.execute(
                f"UPDATE {table} SET status='skipped',error=? WHERE case_id=? AND {column}=?",
                ("ExcludedIP" if kind == "ip" else "InvalidOrSyntheticHash", cid, value),
            )
            return
        cache = db.execute(
            f"SELECT report FROM {cache_table} WHERE {column}=? AND expires>?", (value, now)
        ).fetchone()
        if cache:
            db.execute(
                f"UPDATE {table} SET status='complete',report=?,error=NULL,lease_until=0 WHERE case_id=? AND {column}=?",
                (cache[0], cid, value),
            )
            db.execute("UPDATE thehive_sync SET available=0 WHERE case_id=?", (cid,))
            return
        # One durable reservation/budget for both lookup types, including after restart.
        day = datetime.fromtimestamp(now, UTC).date().isoformat()
        db.execute("INSERT OR IGNORE INTO vt_budget VALUES(1,?,0,0)", (day,))
        budget = db.execute("SELECT * FROM vt_budget WHERE id=1").fetchone()
        count = budget["count"] if budget["day"] == day else 0
        if budget["next_at"] > now or count >= settings.vt_daily_limit:
            next_at = budget["next_at"]
            if count >= settings.vt_daily_limit:
                next_at = max(next_at, (int(now) // 86400 + 1) * 86400)
            db.execute(
                f"UPDATE {table} SET available=? WHERE case_id=? AND {column}=?", (next_at, cid, value)
            )
            return
        db.execute(
            "UPDATE vt_budget SET day=?,count=?,next_at=? WHERE id=1",
            (day, count + 1, now + settings.vt_interval),
        )
        db.execute(f"UPDATE {table} SET lease_until=? WHERE case_id=? AND {column}=?", (lease, cid, value))
    report, error, delay = None, None, 60
    try:
        path = "ip_addresses/" if kind == "ip" else "files/"
        with httpx.Client(timeout=5, transport=transport, follow_redirects=False) as client:
            response = client.get(
                "https://www.virustotal.com/api/v3/" + path + value,
                headers={"x-apikey": settings.vt_key},
            )
        if response.status_code == 404:
            report = {
                "source": "virustotal",
                "indicator_type": kind,
                "status": "not_found",
                "queried_at": time.time(),
            }
        else:
            response.raise_for_status()
            report = _report(response, kind)
    except Exception as exc:
        error = (
            "HTTP" + str(exc.response.status_code)
            if isinstance(exc, httpx.HTTPStatusError)
            else type(exc).__name__
        )
        if isinstance(exc, httpx.HTTPStatusError) and exc.response.status_code in (401, 403, 429):
            delay = 3600 if exc.response.status_code in (401, 403) else 60
            retry_after = exc.response.headers.get("Retry-After", "")
            if retry_after.isdigit():
                delay = max(delay, min(86400, int(retry_after)))
            with store.connect() as db:
                db.execute("UPDATE vt_budget SET next_at=max(next_at,?) WHERE id=1", (time.time() + delay,))
        log.warning(
            "virustotal.lookup_failed",
            extra={"case_id": cid, "details": {"code": error, "indicator_type": kind}},
        )
    with store.connect() as db:
        db.execute("BEGIN IMMEDIATE")
        if not db.execute(
            f"SELECT 1 FROM {table} WHERE case_id=? AND {column}=? AND lease_until=? AND lease_until>?",
            (cid, value, lease, time.time()),
        ).fetchone():
            return
        if report is not None:
            encoded = json.dumps(report)
            db.execute(
                f"INSERT INTO {cache_table} VALUES(?,?,?) ON CONFLICT({column}) DO UPDATE SET report=excluded.report,expires=excluded.expires",
                (value, encoded, time.time() + 86400),
            )
            db.execute(
                f"UPDATE {table} SET status='complete',report=?,error=NULL,lease_until=0 WHERE case_id=? AND {column}=?",
                (encoded, cid, value),
            )
            db.execute("UPDATE thehive_sync SET available=0 WHERE case_id=?", (cid,))
        else:
            db.execute(
                f"UPDATE {table} SET status='retry',error=?,available=?,lease_until=0 WHERE case_id=? AND {column}=?",
                (error, time.time() + delay, cid, value),
            )
