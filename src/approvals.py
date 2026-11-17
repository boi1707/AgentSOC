"""One response policy for browser sessions, legacy review, and signed callbacks."""

import logging
import subprocess
import time

from fastapi import HTTPException

from . import response


def validate(case, run, expected_run, decision, settings):
    if case["latest_run_id"] != expected_run:
        raise HTTPException(400, "Response must reference the current non-replay proposal run")
    if run and (run["replay"] or run["status"] != "completed"):
        raise HTTPException(400, "Replay or incomplete run cannot execute a response")
    created = (run.get("finished") or run["created"]) if run else case["created"]
    if time.time() >= created + settings.proposal_ttl:
        raise HTTPException(409, "Proposal expired; a new investigation is required")
    if case["status"] != "pending" or case["workflow_status"] == "closed":
        raise HTTPException(409, "Case is no longer pending")
    if decision == "approve":
        try:
            return response.candidate(case, settings)
        except (ValueError, KeyError):
            raise HTTPException(400, "Case is not eligible under server response policy") from None
    return None


def proposal(store, settings, case, *, run=None):
    run = run or (store.get_run(case["latest_run_id"]) if case["latest_run_id"] else None)
    created = (run.get("finished") or run["created"]) if run else case["created"]
    target, eligible, reason = None, False, None
    try:
        target = validate(case, run, case["latest_run_id"], "approve", settings)
        eligible = True
    except HTTPException as exc:
        reason = exc.detail
    return {
        "id": case["latest_run_id"] or case["id"],
        "incident_id": case["id"],
        "run_id": case["latest_run_id"],
        "action": "block_ip",
        "source_ip": target,
        "evidence_ids": case["verdict"].get("evidence_ids", []),
        "created": created,
        "expires": created + settings.proposal_ttl,
        "eligible": eligible,
        "ineligibility_reason": reason,
        "status": case["status"],
        "mode": settings.response_mode,
        "blocked": case["status"] == "blocked",
    }


def decide(store, settings, cid, decision, run_id, actor):
    try:
        return _decide(store, settings, cid, decision, run_id, actor)
    except HTTPException as exc:
        store.audit(actor, "response.denied", cid, str(exc.status_code))
        raise


def _decide(store, settings, cid, decision, run_id, actor):
    if decision not in {"approve", "reject"}:
        raise HTTPException(422, "Invalid decision")
    case = store.get(cid)
    if not case:
        raise HTTPException(404, "Incident not found")
    run = store.get_run(case["latest_run_id"]) if case["latest_run_id"] else None
    ip = validate(case, run, run_id, decision, settings)
    # Repeat every policy check under the same write lock as the state transition.
    if not store.claim(
        cid,
        actor=actor,
        mode=settings.response_mode,
        action=decision,
        ip=ip,
        expected_run=run_id,
        settings=settings,
    ):
        raise HTTPException(409, "Case is no longer pending")
    status = "rejected"
    if decision == "approve":
        try:
            status = response.execute(ip, settings)
        except (OSError, TimeoutError, subprocess.TimeoutExpired):
            status = "action_unknown"
    store.record_action(cid, decision, ip, settings.response_mode, status, actor)
    logging.getLogger("agentsoc.api").info(
        "review.completed",
        extra={
            "case_id": cid,
            "details": {"action": decision, "mode": settings.response_mode, "status": status},
        },
    )
    return {
        "status": status,
        "verification_status": "not_verified",
        "mode": settings.response_mode,
        "blocked": status == "blocked",
        "proposal_id": run_id or cid,
    }
