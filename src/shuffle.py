"""Durable outbound response notifications. Delivery is at least once."""

import json
import logging
import time

import httpx

log = logging.getLogger("agentsoc.shuffle")


def deliver_pending(store, settings, *, transport=None):
    if not settings.shuffle_hook or settings.demo:
        return
    now = time.time()
    lease = now + 60
    with store.connect() as db:
        db.execute("BEGIN IMMEDIATE")
        row = db.execute(
            "SELECT * FROM shuffle_outbox WHERE status!='delivered' AND available<=? "
            "AND lease_until<=? ORDER BY available,id LIMIT 1",
            (now, now),
        ).fetchone()
        if not row:
            return
        db.execute(
            "UPDATE shuffle_outbox SET status='sending',lease_until=?,attempts=attempts+1 WHERE id=?",
            (lease, row["id"]),
        )
    error = None
    try:
        with httpx.Client(timeout=5, transport=transport, follow_redirects=False) as client:
            response = client.post(
                settings.shuffle_hook,
                json=json.loads(row["payload"]),
                headers={"Idempotency-Key": row["id"], "X-AgentSOC-Event-ID": row["id"]},
            )
            response.raise_for_status()
            # Some webhook receivers report application errors with HTTP 200.
            try:
                body = response.json()
            except ValueError:
                body = None
            if isinstance(body, dict) and body.get("success") is False:
                raise ValueError("WebhookRejected")
    except Exception as exc:
        error = (
            "HTTP" + str(exc.response.status_code)
            if isinstance(exc, httpx.HTTPStatusError)
            else type(exc).__name__
        )
        log.warning("shuffle.delivery_failed", extra={"case_id": row["case_id"], "details": {"code": error}})
    with store.connect() as db:
        if error:
            db.execute(
                "UPDATE shuffle_outbox SET status='retry',error=?,available=?,lease_until=0 WHERE id=? AND lease_until=? AND lease_until>?",
                (
                    error,
                    time.time() + min(3600, 30 * 2 ** min(row["attempts"], 7)),
                    row["id"],
                    lease,
                    time.time(),
                ),
            )
        else:
            db.execute(
                "UPDATE shuffle_outbox SET status='delivered',error=NULL,delivered=?,lease_until=0 WHERE id=? AND lease_until=? AND lease_until>?",
                (time.time(), row["id"], lease, time.time()),
            )
