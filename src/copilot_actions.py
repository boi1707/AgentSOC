"""Explicit human confirmation for transactional, dry-run-only Copilot intents."""

import ipaddress
import json
import time
from uuid import uuid4

from fastapi import HTTPException

from . import approvals, auth
from .copilot import owned, redact
from .response_adapters import BlockPlan, DryRunAdapter, PfSenseAdapter


def preview(row):
    value = dict(row)
    value["evidence_ids"] = json.loads(value.pop("evidence"))
    value["original_judge_verdict"] = value.pop("judge")
    value["approval_policy"] = value.pop("policy")
    if value["status"] == "prepared" and value["expires"] <= time.time():
        value["status"] = "expired"
    value.update(
        mode="dry-run",
        blocked=False,
        verification_status="not_verified",
        action="block_ip",
        decision_source="human",
        evidence_gaps=["The stored investigation did not establish an attack"]
        if value["approval_policy"] == "manual_analyst"
        else [],
    )
    return value


def authorized(db, owner):
    user = db.execute("SELECT role FROM users WHERE username=? AND disabled=0", (owner,)).fetchone()
    if not user or auth.ROLES.get(user["role"], -1) < auth.ROLES["approver"]:
        raise HTTPException(403, "Approver or administrator required")


def context(db, store, settings, cid, now):
    if (
        settings.response_mode != "dry-run"
        or settings.pfsense_live_enabled
        or (store.managed and store.managed.accepting)
    ):
        raise HTTPException(409, "Copilot confirmations require standard dry-run mode")
    row = db.execute("SELECT * FROM cases WHERE id=?", (cid,)).fetchone()
    if not row:
        raise HTTPException(404, "Incident not found")
    case = store.decode(row)
    run = db.execute("SELECT * FROM runs WHERE id=? AND case_id=?", (case["latest_run_id"], cid)).fetchone()
    if not run or not run["finished"]:
        raise HTTPException(409, "A completed current investigation is required")
    run = dict(run)
    approvals.validate(case, run, run["id"], "reject", settings, now=now)
    return case, run


def policy_evidence(db, case, run, settings, policy):
    if policy == "standard":
        ip = approvals.validate(case, run, run["id"], "approve", settings)
        return ip, sorted(set(case["verdict"]["evidence_ids"]))
    if (
        case["verdict"].get("verdict") != "review"
        or case["synthetic"]
        or settings.demo
        or case["provenance"] != "received"
        or json.loads(run["verdict"]) != case["verdict"]
    ):
        raise HTTPException(409, "Manual containment requires a current review with received evidence")
    snapshot = json.loads(run["evidence"])["alerts"]
    originals = {
        row["id"]: json.loads(row["normalized"])["evidence"]
        for row in db.execute(
            """SELECT i.id,i.normalized FROM inbox i JOIN incident_alerts l ON l.alert_id=i.id
               WHERE l.case_id=? AND i.source=? AND i.synthetic=0 AND i.provenance='received'""",
            (case["id"], settings.wazuh_source),
        )
    }
    network = [alert for alert in snapshot if alert.get("kind") == "net"]
    sources = {alert.get("src_ip") for alert in network}
    if len(sources) != 1:
        raise HTTPException(409, "Manual containment requires one unambiguous current network source")
    source = next(iter(sources))
    try:
        ip = str(PfSenseAdapter(settings).validate_target(source))
    except ValueError:
        raise HTTPException(
            409, "Manual containment source is protected, invalid or outside the lab scope"
        ) from None
    evidence = []
    for alert in network:
        original = originals.get(alert.get("id"), {})
        destination = alert.get("dst_ip")
        try:
            valid_destination = bool(destination and str(ipaddress.ip_address(destination)) != ip)
        except ValueError:
            valid_destination = False
        if (
            not valid_destination
            or original.get("kind") != "net"
            or original.get("src_ip") != ip
            or original.get("dst_ip") != destination
        ):
            raise HTTPException(409, "Current network direction must match the original received evidence")
        evidence.append(alert["id"])
    return ip, sorted(set(evidence))


def prepare(store, settings, owner, tid, *, cid=None, policy="standard", justification="", ttl=86400):
    if policy not in {"standard", "manual_analyst"} or not 1 <= ttl <= 86400:
        raise HTTPException(422, "Invalid approval policy or duration")
    if policy == "manual_analyst" and len(justification.strip()) < 8:
        raise HTTPException(422, "A human-written justification is required")
    justification = redact(justification.strip(), settings)[:1000]
    now = time.time()
    with store.connect() as db:
        db.execute("BEGIN IMMEDIATE")
        authorized(db, owner)
        thread = owned(db, owner, tid, active=True)
        cid = cid or thread["incident_id"]
        if not cid:
            raise HTTPException(422, "Select an incident before preparing a response")
        case, run = context(db, store, settings, cid, now)
        ip, evidence = policy_evidence(db, case, run, settings, policy)
        existing = db.execute(
            "SELECT * FROM assistant_action_intents WHERE thread_id=? AND run_id=?", (tid, run["id"])
        ).fetchone()
        if existing:
            if (
                existing["policy"] != policy
                or existing["ttl"] != ttl
                or existing["justification"] != justification
            ):
                raise HTTPException(409, "An intent already exists for this run in the conversation")
            return preview(existing)
        iid = uuid4().hex
        expires = min(now + 900, run["finished"] + settings.proposal_ttl)
        db.execute(
            """INSERT INTO assistant_action_intents
               (id,thread_id,case_id,run_id,target,evidence,judge,policy,justification,created,expires,ttl,status)
               VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?)""",
            (
                iid,
                tid,
                cid,
                run["id"],
                ip,
                json.dumps(evidence),
                case["verdict"]["verdict"],
                policy,
                justification,
                now,
                expires,
                ttl,
                "prepared",
            ),
        )
        store.audit(owner, "copilot.prepared", iid, policy, db=db)
        return preview(db.execute("SELECT * FROM assistant_action_intents WHERE id=?", (iid,)).fetchone())


def confirm(store, settings, owner, tid, iid, decision):
    if decision not in {"approve", "reject"}:
        raise HTTPException(422, "Explicit approval or rejection required")
    try:
        return _confirm(store, settings, owner, tid, iid, decision)
    except HTTPException as exc:
        store.audit(owner, "copilot.confirmation_denied", iid, str(exc.status_code))
        raise


def _confirm(store, settings, owner, tid, iid, decision):
    now = time.time()
    with store.connect() as db:
        db.execute("BEGIN IMMEDIATE")
        authorized(db, owner)
        owned(db, owner, tid, active=True)
        row = db.execute(
            "SELECT * FROM assistant_action_intents WHERE id=? AND thread_id=?", (iid, tid)
        ).fetchone()
        if not row:
            raise HTTPException(404, "Response intent not found")
        if row["status"] != "prepared":
            return preview(row)
        if row["expires"] <= now:
            raise HTTPException(409, "Response intent has expired")
        case, run = context(db, store, settings, row["case_id"], now)
        if run["id"] != row["run_id"] or case["verdict"].get("verdict") != row["judge"]:
            raise HTTPException(409, "Response intent is stale")
        ip, evidence = policy_evidence(db, case, run, settings, row["policy"])
        if ip != row["target"] or evidence != json.loads(row["evidence"]):
            raise HTTPException(409, "Response intent evidence changed")
        result = (
            DryRunAdapter().block(BlockPlan(iid, ip, now + row["ttl"], settings.protected))
            if decision == "approve"
            else "rejected"
        )
        # The pure dry-run adapter has no external side effects. The result, audit and outbox commit together.
        db.execute("UPDATE cases SET status=? WHERE id=?", (result, case["id"]))
        action_id = db.execute(
            """INSERT INTO actions(ts,case_id,action,ip,mode,result,actor,requested_by,evidence,run_id,
               completed_at,approved_by,rejected_by) VALUES(?,?,?,?,'dry-run',?,?,?,?,?,?,?,?)""",
            (
                now,
                case["id"],
                decision,
                ip if decision == "approve" else None,
                result,
                owner,
                run["requested_by"],
                row["evidence"],
                run["id"],
                now,
                owner if decision == "approve" else None,
                owner if decision == "reject" else None,
            ),
        ).lastrowid
        db.execute(
            "UPDATE assistant_action_intents SET status=?,action_id=? WHERE id=?", (result, action_id, iid)
        )
        store.queue_response(db, db.execute("SELECT * FROM actions WHERE id=?", (action_id,)).fetchone())
        db.execute("UPDATE thehive_sync SET available=0 WHERE case_id=?", (case["id"],))
        store.audit(owner, "response." + decision, case["id"], result, db=db)
        store.audit(owner, "copilot.confirmed", iid, row["policy"], db=db)
        return preview(db.execute("SELECT * FROM assistant_action_intents WHERE id=?", (iid,)).fetchone())
