"""Optional public-IP reputation lookup; never uploads files, URLs or raw alerts."""

import ipaddress
import json
import logging
import time
from datetime import UTC, datetime

import httpx

log = logging.getLogger("agentsoc.virustotal")
STATS = ("malicious", "suspicious", "harmless", "undetected", "timeout")


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


def _report(response):
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
    return {"source": "virustotal", "status": "reported", "stats": result, "queried_at": time.time()}


def enrich_pending(store, settings, *, transport=None):
    if not settings.vt_key or settings.demo:
        return
    now = time.time()
    lease = now + 60
    with store.connect() as db:
        db.execute("BEGIN IMMEDIATE")
        row = db.execute(
            "SELECT * FROM vt_jobs WHERE status IN ('pending','retry') AND available<=? "
            "AND lease_until<=? ORDER BY available,case_id,ip LIMIT 1",
            (now, now),
        ).fetchone()
        if not row:
            return
        cid, ip = row["case_id"], row["ip"]
        if not public_ips([ip], settings.vt_exclude_ips):
            db.execute(
                "UPDATE vt_jobs SET status='skipped',error='ExcludedIP' WHERE case_id=? AND ip=?", (cid, ip)
            )
            return
        cache = db.execute("SELECT report FROM vt_cache WHERE ip=? AND expires>?", (ip, now)).fetchone()
        if cache:
            db.execute(
                "UPDATE vt_jobs SET status='complete',report=?,error=NULL WHERE case_id=? AND ip=?",
                (cache[0], cid, ip),
            )
            db.execute("UPDATE thehive_sync SET available=0 WHERE case_id=?", (cid,))
            return
        day = datetime.fromtimestamp(now, UTC).date().isoformat()
        db.execute("INSERT OR IGNORE INTO vt_budget VALUES(1,?,0,0)", (day,))
        budget = db.execute("SELECT * FROM vt_budget WHERE id=1").fetchone()
        count = budget["count"] if budget["day"] == day else 0
        if budget["next_at"] > now or count >= settings.vt_daily_limit:
            next_at = budget["next_at"]
            if count >= settings.vt_daily_limit:
                next_at = max(next_at, (int(now) // 86400 + 1) * 86400)
            db.execute("UPDATE vt_jobs SET available=? WHERE case_id=? AND ip=?", (next_at, cid, ip))
            return
        db.execute(
            "UPDATE vt_budget SET day=?,count=?,next_at=? WHERE id=1",
            (day, count + 1, now + settings.vt_interval),
        )
        db.execute("UPDATE vt_jobs SET lease_until=? WHERE case_id=? AND ip=?", (lease, cid, ip))
    report, error, delay = None, None, 60
    try:
        with httpx.Client(timeout=5, transport=transport, follow_redirects=False) as client:
            response = client.get(
                "https://www.virustotal.com/api/v3/ip_addresses/" + ip,
                headers={"x-apikey": settings.vt_key},
            )
        if response.status_code == 404:
            report = {"source": "virustotal", "status": "not_found", "queried_at": time.time()}
        else:
            response.raise_for_status()
            report = _report(response)
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
        log.warning("virustotal.lookup_failed", extra={"case_id": cid, "details": {"code": error}})
    with store.connect() as db:
        db.execute("BEGIN IMMEDIATE")
        if not db.execute(
            "SELECT 1 FROM vt_jobs WHERE case_id=? AND ip=? AND lease_until=? AND lease_until>?",
            (cid, ip, lease, time.time()),
        ).fetchone():
            return
        if report is not None:
            encoded = json.dumps(report)
            db.execute(
                "INSERT INTO vt_cache VALUES(?,?,?) ON CONFLICT(ip) DO UPDATE SET report=excluded.report,expires=excluded.expires",
                (ip, encoded, time.time() + 86400),
            )
            db.execute(
                "UPDATE vt_jobs SET status='complete',report=?,error=NULL,lease_until=0 WHERE case_id=? AND ip=?",
                (encoded, cid, ip),
            )
            db.execute("UPDATE thehive_sync SET available=0 WHERE case_id=?", (cid,))
        else:
            db.execute(
                "UPDATE vt_jobs SET status='retry',error=?,available=?,lease_until=0 WHERE case_id=? AND ip=?",
                (error, time.time() + delay, cid, ip),
            )
