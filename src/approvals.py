"""One response policy for browser sessions, legacy review, and signed callbacks."""

import logging
import subprocess
import time

from fastapi import HTTPException

from . import response
from .managed_response import MODE as MANAGED_MODE


def validate(case, run, expected_run, decision, settings, *, now=None):
    if case["latest_run_id"] != expected_run:
        raise HTTPException(400, "Response must reference the current non-replay proposal run")
    if run and (run["replay"] or run["status"] != "completed"):
        raise HTTPException(400, "Replay or incomplete run cannot execute a response")
    created = (run.get("finished") or run["created"]) if run else case["created"]
    if (time.time() if now is None else now) >= created + settings.proposal_ttl:
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
    managed = store.managed
    simulation = managed is not None and managed.accepting
    try:
        target = validate(
            case, run, case["latest_run_id"], "approve", settings, now=managed.clock() if simulation else None
        )
        if simulation:
            with store.connect() as db:
                managed.validate_evidence(db, case, run, target)
        eligible = True
    except HTTPException as exc:
        reason = exc.detail
    except (ValueError, KeyError, TypeError, IndexError, AttributeError):
        target, reason = None, "Case is not eligible under managed response policy"
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
        "mode": MANAGED_MODE if simulation else settings.response_mode,
        "blocked": case["status"] == "blocked",
    }


def decide(store, settings, cid, decision, run_id, actor, *, authenticated=False):
    try:
        return _decide(store, settings, cid, decision, run_id, actor, authenticated=authenticated)
    except HTTPException as exc:
        store.audit(actor, "response.denied", cid, str(exc.status_code))
        raise


def _decide(store, settings, cid, decision, run_id, actor, *, authenticated):
    if decision not in {"approve", "reject"}:
        raise HTTPException(422, "Invalid decision")
    case = store.get(cid)
    if not case:
        raise HTTPException(404, "Incident not found")
    run = store.get_run(case["latest_run_id"]) if case["latest_run_id"] else None
    managed = store.managed
    simulation = decision == "approve" and managed is not None and managed.accepting
    ip = validate(case, run, run_id, decision, settings, now=managed.clock() if simulation else None)
    # Repeat every policy check under the same write lock as the state transition.
    if not store.claim(
        cid,
        actor=actor,
        mode=MANAGED_MODE if simulation else settings.response_mode,
        action=decision,
        ip=ip,
        expected_run=run_id,
        settings=settings,
        authenticated=authenticated,
    ):
        raise HTTPException(409, "Case is no longer pending")
    if simulation:
        return {
            "status": "pending_execution",
            "verification_status": "not_verified",
            "mode": MANAGED_MODE,
            "blocked": False,
            "simulated": True,
            "traffic_verified": False,
            "proposal_id": run_id,
        }
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
