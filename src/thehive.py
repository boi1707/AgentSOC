"""Durable, best-effort case mirror. Never executes a response action."""

import hashlib
import json
import logging
import re
import time

import httpx

log = logging.getLogger("agentsoc.thehive")


class ReconciliationRequired(Exception):
    pass


class CreateOutcomeUnknown(Exception):
    pass


def payload(case, settings):
    verdict = case["verdict"]
    content = {
        "agentsoc_case_id": case["id"],
        "status": case["status"],
        "workflow_status": case.get("workflow_status"),
        "verdict": verdict,
        "virustotal": case.get("virustotal", []),
        "evidence_ids": case["incident"].get("raw_ids", []),
    }
    restore = case.get("restore", {})
    secrets = (
        *settings.integration_secrets,
        settings.ingest_key,
        settings.approve_key,
        settings.llm_key,
        settings.tg_token,
        settings.admin_password,
    )
    secrets = tuple(v for v in (*secrets, *(v for k, v in restore.items() if k.startswith("SECRET_"))) if v)

    def redact(text):
        for secret in secrets:
            text = text.replace(secret, "[REDACTED]")
        return text

    def clean(value):
        if isinstance(value, str):
            # Restore before serialization so quotes and Windows paths stay valid JSON.
            return redact(
                re.sub(
                    r"\b(?:INT_IP|HOST|USER|MAIL|SECRET)_\d{4,}\b",
                    lambda m: "[REDACTED]" if m[0].startswith("SECRET_") else restore.get(m[0], m[0]),
                    redact(value),
                )
            )
        if isinstance(value, dict):
            return {clean(k): clean(v) for k, v in value.items()}
        if isinstance(value, list):
            return [clean(v) for v in value]
        return value

    description = json.dumps(clean(content), ensure_ascii=False, indent=2)
    return {
        "title": "AgentSOC #" + case["id"],
        "description": "AgentSOC mirror (response approval remains in AgentSOC).\n\n" + description,
        "severity": {"attack": 3, "review": 2}.get(verdict.get("verdict"), 1),
        "tlp": 2,
        "pap": 2,
        "tags": ["agentsoc", "agentsoc-id:" + case["id"]],
    }


def sync_pending(store, settings, *, transport=None):
    if not settings.thehive_url or not settings.thehive_key or settings.demo:
        return
    now = time.time()
    lease = now + 120
    with store.connect() as db:
        db.execute("BEGIN IMMEDIATE")
        rows = db.execute(
            "SELECT case_id FROM thehive_sync WHERE available<=? AND lease_until<=? "
            "ORDER BY available,case_id LIMIT 1",
            (now, now),
        ).fetchall()
        if not rows:
            return
        row = rows[0]
        cid = row["case_id"]
        db.execute("UPDATE thehive_sync SET lease_until=? WHERE case_id=?", (lease, cid))
        state = dict(db.execute("SELECT * FROM thehive_sync WHERE case_id=?", (cid,)).fetchone())
    case = store.get(cid)
    from .integrations import incident_integrations

    case["virustotal"] = incident_integrations(store, cid)["virustotal"]
    body = payload(case, settings)
    digest = hashlib.sha256(json.dumps(body, sort_keys=True).encode()).hexdigest()
    remote_id = state["remote_id"]
    error = None
    phase = state["state"]
    creating_request = False
    try:
        with httpx.Client(
            base_url=settings.thehive_url + "/",
            timeout=5,
            transport=transport,
            headers={"Authorization": "Bearer " + settings.thehive_key},
            follow_redirects=False,
        ) as client:
            if not remote_id:
                # Read before create; reconcile if POST succeeded but its response was lost.
                response = client.post(
                    "api/v1/query",
                    json={
                        "query": [
                            {"_name": "listCase"},
                            {"_name": "filter", "_eq": {"_field": "tags", "_value": body["tags"][1]}},
                            {"_name": "page", "from": 0, "to": 2},
                        ]
                    },
                )
                response.raise_for_status()
                matches = response.json()
                if not isinstance(matches, list) or len(matches) > 1:
                    raise ReconciliationRequired()
                if matches:
                    remote_id = matches[0]["_id"]
                elif phase == "creating":
                    # Never repeat an ambiguous create automatically.
                    raise CreateOutcomeUnknown()
                else:
                    with store.connect() as db:
                        if not db.execute(
                            "UPDATE thehive_sync SET state='creating' WHERE case_id=? AND lease_until=? AND lease_until>?",
                            (cid, lease, time.time()),
                        ).rowcount:
                            return
                    phase = "creating"
                    creating_request = True
                    response = client.post("api/v1/case", json=body)
                    response.raise_for_status()
                    remote_id = response.json()["_id"]
                    creating_request = False
                if not isinstance(remote_id, str) or not re.fullmatch(r"[A-Za-z0-9_~.-]{1,256}", remote_id):
                    raise ValueError("InvalidRemoteID")
                with store.connect() as db:
                    if not db.execute(
                        "UPDATE thehive_sync SET remote_id=? WHERE case_id=? AND lease_until=? AND lease_until>?",
                        (remote_id, cid, lease, time.time()),
                    ).rowcount:
                        return
            if digest != state["payload_hash"]:
                response = client.patch(
                    "api/v1/case/" + remote_id,
                    json={
                        "description": body["description"],
                        "severity": body["severity"],
                    },
                )
                response.raise_for_status()
        phase = "synced"
    except Exception as exc:
        if (
            isinstance(exc, httpx.HTTPStatusError)
            and creating_request
            and not remote_id
            and 400 <= exc.response.status_code < 500
            and exc.response.status_code != 408
        ):
            phase = "pending"
        # Never persist/log exception strings, response bodies, or Authorization headers.
        error = (
            "HTTP" + str(exc.response.status_code)
            if isinstance(exc, httpx.HTTPStatusError)
            else type(exc).__name__
        )
        log.warning("thehive.sync_failed", extra={"case_id": cid, "details": {"code": error}})
    finally:
        with store.connect() as db:
            db.execute(
                "UPDATE thehive_sync SET state=?,payload_hash=?,available=?,lease_until=0,error=? WHERE case_id=? AND lease_until=? AND lease_until>?",
                (
                    phase,
                    state["payload_hash"] if error else digest,
                    time.time() + 60,
                    error,
                    cid,
                    lease,
                    time.time(),
                ),
            )
