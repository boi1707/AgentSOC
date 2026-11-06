import json
import secrets
import subprocess
import time
from typing import Literal

from fastapi import APIRouter, Depends, HTTPException, Query, Request, Response
from pydantic import BaseModel, ConfigDict, Field

from src import auth, response
from src.anon import Anon
from src.api.schemas import (
    AlertDetail,
    AlertSummary,
    AuditEvent,
    IncidentDetail,
    IncidentSummary,
    LedgerStep,
    Page,
)

router = APIRouter(prefix="/api/v1")


class Login(BaseModel):
    username: str = Field(min_length=1, max_length=80)
    password: str = Field(min_length=1, max_length=256)


class NewUser(Login):
    role: Literal["viewer", "analyst", "approver", "admin"]


class Note(BaseModel):
    body: str = Field(min_length=1, max_length=8000)


class Replay(BaseModel):
    parent_run_id: str = Field(min_length=1, max_length=64)


class Review(BaseModel):
    model_config = ConfigDict(extra="forbid")
    decision: Literal["approve", "reject"]
    run_id: str | None = None


class Workflow(BaseModel):
    status: Literal["open", "investigating", "review", "closed"]


def store(request):
    return request.app.state.service.store


def scrub(value, settings):
    if isinstance(value, str):
        for secret in (
            settings.ingest_key,
            settings.approve_key,
            settings.admin_password,
            settings.llm_key,
            settings.tg_token,
        ):
            if secret:
                value = value.replace(secret, "[REDACTED]")
        return value
    if isinstance(value, dict):
        return {k: scrub(v, settings) for k, v in value.items()}
    if isinstance(value, list):
        return [scrub(v, settings) for v in value]
    return value


def safe(request, value):
    return scrub(value, request.app.state.settings)


@router.post("/auth/login")
def login(payload: Login, request: Request, result: Response):
    repo = store(request)
    with repo.connect() as db:
        failures = db.execute(
            "SELECT count(*) FROM audit WHERE actor=? AND action='login' AND result='denied' AND ts>?",
            (payload.username, time.time() - 60),
        ).fetchone()[0]
        if failures >= 10:
            raise HTTPException(429, "Too many login attempts; wait one minute")
        user = db.execute(
            "SELECT * FROM users WHERE username=? AND disabled=0", (payload.username,)
        ).fetchone()
    if not user or not auth.check_password(payload.password, user["password_hash"]):
        repo.audit(payload.username, "login", None, "denied")
        raise HTTPException(401, "Invalid username or password")
    token, csrf = secrets.token_urlsafe(32), secrets.token_urlsafe(32)
    with repo.connect() as db:
        db.execute("DELETE FROM sessions WHERE expires<?", (time.time(),))
        db.execute(
            "INSERT INTO sessions VALUES(?,?,?,?)",
            (auth.token_hash(token), user["username"], csrf, time.time() + 28800),
        )
    result.set_cookie(
        "agentsoc_session",
        token,
        httponly=True,
        secure=request.app.state.settings.secure_cookie,
        samesite="strict",
        max_age=28800,
        path="/",
    )
    repo.audit(user["username"], "login", None, "success")
    return {"username": user["username"], "role": user["role"], "csrf": csrf}


@router.get("/auth/me")
def me(actor=Depends(auth.principal)):
    return {"username": actor.username, "role": actor.role, "csrf": actor.csrf}


@router.post("/auth/logout")
def logout(request: Request, result: Response, actor=Depends(auth.principal)):
    with store(request).connect() as db:
        db.execute(
            "DELETE FROM sessions WHERE token_hash=?",
            (auth.token_hash(request.cookies.get("agentsoc_session", "")),),
        )
    result.delete_cookie("agentsoc_session", path="/")
    store(request).audit(actor.username, "logout", None, "success")
    return {"ok": True}


@router.post("/users", status_code=201)
def create_user(payload: NewUser, request: Request, actor=Depends(auth.require("admin"))):
    if len(payload.password) < 16:
        raise HTTPException(422, "Password must have at least 16 characters")
    with store(request).connect() as db:
        if db.execute("SELECT 1 FROM users WHERE username=?", (payload.username,)).fetchone():
            raise HTTPException(409, "Username already exists")
        db.execute(
            "INSERT INTO users(username,password_hash,role,created) VALUES(?,?,?,?)",
            (payload.username, auth.password_hash(payload.password), payload.role, time.time()),
        )
        store(request).audit(actor.username, "user.created", payload.username, payload.role, db=db)
    return {"username": payload.username, "role": payload.role}


def page_query(request, table, *, limit, offset, order, where, values, time_column):
    direction = "ASC" if order == "oldest" else "DESC"
    with store(request).connect() as db:
        total = db.execute(f"SELECT count(*) FROM {table} WHERE {where}", values).fetchone()[0]
        rows = db.execute(
            f"SELECT * FROM {table} WHERE {where} ORDER BY {time_column} {direction},id {direction} LIMIT ? OFFSET ?",
            (*values, limit, offset),
        ).fetchall()
    return total, [dict(r) for r in rows]


@router.get("/alerts", dependencies=[Depends(auth.principal)], response_model=Page[AlertSummary])
def alerts(
    request: Request,
    limit: int = Query(25, ge=1, le=100),
    offset: int = Query(0, ge=0),
    order: Literal["newest", "oldest"] = "newest",
    severity: str | None = None,
    source: str | None = None,
    entity: str | None = None,
    status: str | None = None,
    since: float | None = None,
    until: float | None = None,
    q: str = Query("", max_length=200),
):
    clauses, values = ["1=1"], []
    for column, value in (("severity", severity), ("source", source), ("correlation_status", status)):
        if value:
            clauses.append(column + "=?")
            values.append(value)
    if entity:
        clauses.append("EXISTS(SELECT 1 FROM json_each(inbox.normalized,'$.entities') WHERE value=?)")
        values.append(entity)
    for sign, value in ((">=", since), ("<=", until)):
        if value is not None:
            clauses.append("received" + sign + "?")
            values.append(value)
    if q:
        clauses.append("(external_id LIKE ? OR normalized LIKE ?)")
        values.extend(["%" + q + "%"] * 2)
    where = " AND ".join(clauses)
    total, rows = page_query(
        request,
        "inbox",
        limit=limit,
        offset=offset,
        order=order,
        where=where,
        values=values,
        time_column="received",
    )
    with store(request).connect() as db:
        counts = {
            r[0]: r[1]
            for r in db.execute(
                "SELECT severity,count(*) FROM inbox WHERE " + where + " GROUP BY severity", values
            )
        }
    for row in rows:
        row.pop("alert")
        row["normalized"] = json.loads(row["normalized"])
    return safe(
        request, {"items": rows, "total": total, "limit": limit, "offset": offset, "severity_counts": counts}
    )


@router.get("/alerts/{aid:path}", dependencies=[Depends(auth.principal)], response_model=AlertDetail)
def alert_detail(aid: str, request: Request):
    with store(request).connect() as db:
        row = db.execute("SELECT * FROM inbox WHERE id=?", (aid,)).fetchone()
    if not row:
        raise HTTPException(404, "Alert not found")
    result = dict(row)
    result["raw_event"], result["normalized"] = (
        json.loads(result.pop("alert")),
        json.loads(result["normalized"]),
    )
    return safe(request, result)


def incident_view(request, case):
    anon = Anon(request.app.state.settings.hosts)
    anon.rev = case["restore"]
    result = {k: v for k, v in case.items() if k != "restore"}
    result["response_mode"] = request.app.state.settings.response_mode
    level = max((int(a.get("level", 0)) for a in case["incident"].get("alerts", [])), default=0)
    result["severity"] = next(
        label
        for minimum, label in ((15, "critical"), (12, "high"), (8, "medium"), (4, "low"), (0, "info"))
        if level >= minimum
    )

    def restore(value):
        if isinstance(value, str):
            return anon.restore(value)
        if isinstance(value, list):
            return [restore(v) for v in value]
        if isinstance(value, dict):
            return {k: restore(v) for k, v in value.items()}
        return value

    result["verdict"] = restore(result["verdict"])
    result["can_approve"] = False
    try:
        result["target"] = response.candidate(case, request.app.state.settings)
        result["can_approve"] = case["status"] == "pending" and case["workflow_status"] != "closed"
    except ValueError:
        result["target"] = None
    return result


@router.get("/incidents", dependencies=[Depends(auth.principal)], response_model=Page[IncidentSummary])
def incidents(
    request: Request,
    limit: int = Query(25, ge=1, le=100),
    offset: int = Query(0, ge=0),
    order: Literal["newest", "oldest"] = "newest",
    status: str | None = None,
    severity: str | None = None,
    source: str | None = None,
    response_status: str | None = None,
    entity: str | None = None,
    since: float | None = None,
    until: float | None = None,
):
    clauses, values = ["1=1"], []
    if status:
        clauses.append("workflow_status=?")
        values.append(status)
    if source:
        clauses.append("EXISTS(SELECT 1 FROM inbox WHERE case_id=cases.id AND source=?)")
        values.append(source)
    if response_status:
        clauses.append("status=?")
        values.append(response_status)
    if severity:
        bands = {"info": (0, 3), "low": (4, 7), "medium": (8, 11), "high": (12, 14), "critical": (15, 100)}
        if severity not in bands:
            raise HTTPException(422, "Invalid severity filter")
        clauses.append(
            "coalesce((SELECT max(cast(json_extract(value,'$.level') AS INTEGER)) FROM json_each(cases.incident,'$.alerts')),0) BETWEEN ? AND ?"
        )
        values.extend(bands[severity])
    if entity:
        clauses.append(
            "EXISTS(SELECT 1 FROM inbox WHERE case_id=cases.id AND EXISTS(SELECT 1 FROM json_each(inbox.normalized,'$.entities') WHERE value=?))"
        )
        values.append(entity)
    for sign, value in ((">=", since), ("<=", until)):
        if value is not None:
            clauses.append("created" + sign + "?")
            values.append(value)
    total, rows = page_query(
        request,
        "cases",
        limit=limit,
        offset=offset,
        order=order,
        where=" AND ".join(clauses),
        values=values,
        time_column="created",
    )
    return safe(
        request,
        {
            "items": [incident_view(request, store(request).decode(r)) for r in rows],
            "total": total,
            "limit": limit,
            "offset": offset,
        },
    )


@router.get("/incidents/{cid}", dependencies=[Depends(auth.principal)], response_model=IncidentDetail)
def incident_detail(cid: str, request: Request):
    repo = store(request)
    case = repo.get(cid)
    if not case:
        raise HTTPException(404, "Incident not found")
    result = incident_view(request, case)
    with repo.connect() as db:
        result["evidence"] = [
            dict(r)
            for r in db.execute(
                "SELECT i.id,i.normalized,i.received,i.synthetic,l.reason FROM incident_alerts l JOIN inbox i ON i.id=l.alert_id WHERE l.case_id=? ORDER BY i.received,i.id",
                (cid,),
            )
        ]
        result["runs"] = [
            dict(r)
            for r in db.execute(
                "SELECT id,status,created,finished,replay,parent_run_id,provider,model,mode,error,prompt_version FROM runs WHERE case_id=? ORDER BY created DESC,id",
                (cid,),
            )
        ]
        result["notes"] = [
            dict(r) for r in db.execute("SELECT * FROM notes WHERE case_id=? ORDER BY created,id", (cid,))
        ]
        result["actions"] = [
            dict(r) for r in db.execute("SELECT * FROM actions WHERE case_id=? ORDER BY ts DESC,id", (cid,))
        ]
        result["jobs"] = [
            dict(r)
            for r in db.execute(
                "SELECT id,run_id,status,attempts,max_attempts,error,available FROM jobs WHERE case_id=? ORDER BY created DESC",
                (cid,),
            )
        ]
    for row in result["evidence"]:
        row["normalized"] = json.loads(row["normalized"])
    for action in result["actions"]:
        action["target"] = action["ip"]
        action["evidence"] = json.loads(action["evidence"]) if action["evidence"] else None
    return safe(request, result)


@router.post("/incidents/{cid}/notes", status_code=201)
def add_note(cid: str, payload: Note, request: Request, actor=Depends(auth.require("analyst"))):
    if not store(request).get(cid):
        raise HTTPException(404, "Incident not found")
    with store(request).connect() as db:
        db.execute(
            "INSERT INTO notes(case_id,actor,created,body) VALUES(?,?,?,?)",
            (cid, actor.username, time.time(), payload.body),
        )
        store(request).audit(actor.username, "incident.note", cid, "created", db=db)
    return {"ok": True}


@router.patch("/incidents/{cid}/workflow")
def workflow(cid: str, payload: Workflow, request: Request, actor=Depends(auth.require("analyst"))):
    if not store(request).get(cid):
        raise HTTPException(404, "Incident not found")
    with store(request).connect() as db:
        db.execute("UPDATE cases SET workflow_status=? WHERE id=?", (payload.status, cid))
        store(request).audit(actor.username, "incident.workflow", cid, payload.status, db=db)
    return {"status": payload.status}


@router.post("/incidents/{cid}/replay", status_code=202)
def replay(cid: str, payload: Replay, request: Request, actor=Depends(auth.require("analyst"))):
    try:
        rid = store(request).new_run(
            cid, parent=payload.parent_run_id, actor=actor.username, settings=request.app.state.settings
        )
    except KeyError:
        raise HTTPException(404, "Incident not found") from None
    except ValueError:
        raise HTTPException(400, "Replay requires a parent run from this incident") from None
    return {"run_id": rid, "response_allowed": False}


@router.get("/runs/{rid}", dependencies=[Depends(auth.principal)])
def run_detail(rid: str, request: Request):
    run = store(request).get_run(rid)
    if not run:
        raise HTTPException(404, "Run not found")
    with store(request).connect() as db:
        run["planned_steps"] = [
            dict(r)
            for r in db.execute(
                "SELECT * FROM steps WHERE run_id=? ORDER BY started IS NOT NULL,started,rowid", (rid,)
            )
        ]
        run["steps"] = [
            decode_step(dict(r))
            for r in db.execute("SELECT * FROM ledger WHERE run_id=? ORDER BY ts,id", (rid,))
        ]
    return safe(request, run)


def decode_step(row):
    for key in ("prompt", "response", "evidence", "usage", "parameters"):
        try:
            row[key] = json.loads(row[key]) if row[key] is not None else None
        except (ValueError, TypeError):
            pass
    row["status"] = "failed" if row["error"] else "completed"
    return row


@router.get("/ledger", dependencies=[Depends(auth.principal)], response_model=Page[LedgerStep])
def ledger(
    request: Request,
    limit: int = Query(25, ge=1, le=100),
    offset: int = Query(0, ge=0),
    run_id: str | None = None,
    case_id: str | None = None,
    role: str | None = None,
    order: Literal["newest", "oldest"] = "newest",
):
    clauses, values = ["1=1"], []
    for column, value in (("run_id", run_id), ("case_id", case_id), ("agent", role)):
        if value:
            clauses.append(column + "=?")
            values.append(value)
    total, rows = page_query(
        request,
        "ledger",
        limit=limit,
        offset=offset,
        order=order,
        where=" AND ".join(clauses),
        values=values,
        time_column="ts",
    )
    return safe(
        request, {"items": [decode_step(r) for r in rows], "total": total, "limit": limit, "offset": offset}
    )


@router.get("/ledger/{step_id}", dependencies=[Depends(auth.principal)], response_model=LedgerStep)
def ledger_detail(step_id: int, request: Request):
    with store(request).connect() as db:
        row = db.execute("SELECT * FROM ledger WHERE id=?", (step_id,)).fetchone()
    if not row:
        raise HTTPException(404, "Ledger step not found")
    return safe(request, decode_step(dict(row)))


@router.post("/incidents/{cid}/response")
def review(cid: str, payload: Review, request: Request, actor=Depends(auth.require("approver"))):
    repo, config = store(request), request.app.state.settings
    case = repo.get(cid)
    if not case:
        raise HTTPException(404, "Incident not found")
    if case["latest_run_id"] and payload.run_id != case["latest_run_id"]:
        raise HTTPException(400, "Response must reference the current non-replay proposal run")
    if payload.run_id:
        run = repo.get_run(payload.run_id)
        if not run or run["case_id"] != cid or run["replay"] or run["id"] != case["latest_run_id"]:
            raise HTTPException(400, "Replay or stale run cannot execute a response")
    if case["status"] != "pending":
        raise HTTPException(409, "Case is no longer pending")
    ip = None
    if payload.decision == "approve":
        try:
            ip = response.candidate(case, config)
        except ValueError:
            raise HTTPException(400, "Case is not eligible under server response policy") from None
    if not repo.claim(cid, actor=actor.username, mode=config.response_mode, action=payload.decision, ip=ip):
        raise HTTPException(409, "Case is no longer pending")
    status = "rejected"
    if payload.decision == "approve":
        try:
            status = response.execute(ip, config)
        except (OSError, TimeoutError, subprocess.TimeoutExpired):
            status = "action_unknown"
    repo.record_action(cid, payload.decision, ip, config.response_mode, status, actor.username)
    return {"status": status, "verification_status": "not_verified", "mode": config.response_mode}


@router.get("/audit", dependencies=[Depends(auth.principal)], response_model=Page[AuditEvent])
def audit(
    request: Request,
    limit: int = Query(25, ge=1, le=100),
    offset: int = Query(0, ge=0),
    actor: str | None = None,
    action: str | None = None,
):
    clauses, values = ["1=1"], []
    for column, value in (("actor", actor), ("action", action)):
        if value:
            clauses.append(column + "=?")
            values.append(value)
    total, rows = page_query(
        request,
        "audit",
        limit=limit,
        offset=offset,
        order="newest",
        where=" AND ".join(clauses),
        values=values,
        time_column="ts",
    )
    return safe(request, {"items": rows, "total": total, "limit": limit, "offset": offset})


def health_snapshot(repo, config):
    with repo.connect() as db:
        db.execute("SELECT 1")
        workers = [
            dict(r)
            for r in db.execute(
                "SELECT * FROM workers WHERE last_seen>? ORDER BY last_seen DESC", (time.time() - 86400,)
            )
        ]
        backlog, oldest = db.execute(
            "SELECT count(*),min(created) FROM jobs WHERE status IN ('queued','running')"
        ).fetchone()
        dead = db.execute("SELECT count(*) FROM jobs WHERE status='dead_letter'").fetchone()[0]
        last = db.execute("SELECT max(received) FROM inbox").fetchone()[0]
        latest_call = db.execute(
            "SELECT ts,error,mode,provider,model FROM ledger WHERE agent IN ('net','host','judge') ORDER BY ts DESC,id DESC LIMIT 1"
        ).fetchone()
    fresh = any(time.time() - w["last_seen"] < max(30, config.poll * 3) for w in workers)
    return {
        "database": "ready",
        "worker_fresh": fresh,
        "workers": workers,
        "backlog": backlog,
        "oldest_job_age_seconds": max(0, time.time() - oldest) if oldest else None,
        "dead_letters": dead,
        "last_alert_at": last,
        "wazuh_connection": "not_probed",
        "source": "wazuh" if last else None,
        "provider": {
            "mode": config.llm_mode,
            "name": "mock" if config.llm_mode == "mock" else "openai-compatible",
            "model": config.llm_model if config.llm_mode == "live" else None,
            "configured": bool(config.llm_url and config.llm_key and config.llm_model),
            "reachable": None,
            "last_call": dict(latest_call) if latest_call else None,
        },
        "demo": config.demo,
        "response_mode": config.response_mode,
    }


@router.get("/system", dependencies=[Depends(auth.principal)])
def system(request: Request):
    return safe(request, health_snapshot(store(request), request.app.state.settings))


@router.get("/overview", dependencies=[Depends(auth.principal)])
def overview(request: Request):
    repo = store(request)
    with repo.connect() as db:
        severity = {r[0]: r[1] for r in db.execute("SELECT severity,count(*) FROM inbox GROUP BY severity")}
        statuses = {
            r[0]: r[1]
            for r in db.execute("SELECT workflow_status,count(*) FROM cases GROUP BY workflow_status")
        }
        bins = {
            int(r[0]): r[1]
            for r in db.execute(
                "SELECT cast(received/3600 as integer)*3600,count(*) FROM inbox WHERE received>=? GROUP BY 1",
                (time.time() - 86400,),
            )
        }
        hour = int(time.time() // 3600) * 3600
        series = [{"ts": hour - n * 3600, "count": bins.get(hour - n * 3600, 0)} for n in reversed(range(24))]
        recent = [repo.decode(r) for r in db.execute("SELECT * FROM cases ORDER BY created DESC,id LIMIT 6")]
        synthetic = db.execute("SELECT count(*) FROM inbox WHERE synthetic=1").fetchone()[0]
        review_pending = db.execute(
            "SELECT count(*) FROM cases WHERE workflow_status='review' AND status='pending'"
        ).fetchone()[0]
    return safe(
        request,
        {
            "metrics": repo.metrics(),
            "severity": severity,
            "workflow": statuses,
            "series": series,
            "recent": [incident_view(request, c) for c in recent],
            "system": health_snapshot(repo, request.app.state.settings),
            "synthetic_alerts": synthetic,
            "review_pending": review_pending,
        },
    )
