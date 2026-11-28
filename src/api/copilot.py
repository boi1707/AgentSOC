"""Authenticated Web adapter for the shared Copilot."""

from fastapi import APIRouter, Depends, HTTPException, Query, Request
from pydantic import BaseModel, ConfigDict, Field

from src import auth, copilot, copilot_actions
from src.api.v1 import safe, store
from src.assistant import Question

router = APIRouter(prefix="/api/v1/assistant/threads")


class ThreadEdit(BaseModel):
    model_config = ConfigDict(extra="forbid")
    title: str | None = Field(default=None, min_length=1, max_length=100)
    incident_id: str | None = Field(default=None, max_length=64)
    archived: bool | None = None


class Exchange(Question):
    request_key: str = Field(pattern=r"^[a-zA-Z0-9_-]{1,100}$")


class Prepare(BaseModel):
    model_config = ConfigDict(extra="forbid")
    incident_id: str | None = Field(default=None, max_length=64)
    policy: str = "standard"
    justification: str = Field(default="", max_length=1000)
    ttl: int = Field(default=86400, ge=1, le=86400)


class Confirm(BaseModel):
    model_config = ConfigDict(extra="forbid")
    decision: str = Field(pattern=r"^(approve|reject)$")


@router.get("")
def listing(
    request: Request,
    limit: int = Query(30, ge=1, le=50),
    offset: int = Query(0, ge=0, le=100),
    actor=Depends(auth.principal),
):
    return safe(request, copilot.list_threads(store(request), actor.username, limit, offset))


@router.post("", status_code=201)
def new_thread(payload: ThreadEdit, request: Request, actor=Depends(auth.principal)):
    settings = request.app.state.settings
    with store(request).connect() as db:
        db.execute("BEGIN IMMEDIATE")
        return safe(
            request,
            copilot.create(
                db,
                actor.username,
                copilot.redact(payload.title or "Investigation", settings)[:100],
                payload.incident_id,
            ),
        )


@router.get("/{tid}")
def get_thread(
    tid: str,
    request: Request,
    limit: int = Query(50, ge=1, le=100),
    before: int | None = Query(None, ge=1),
    actor=Depends(auth.principal),
):
    return safe(request, copilot.history(store(request), actor.username, tid, limit, before))


@router.patch("/{tid}")
def update_thread(tid: str, payload: ThreadEdit, request: Request, actor=Depends(auth.principal)):
    fields = payload.model_dump(exclude_unset=True)
    if "title" in fields:
        if not fields["title"] or not fields["title"].strip():
            raise HTTPException(422, "Title required")
        fields["title"] = copilot.redact(fields["title"], request.app.state.settings)[:100]
    if "archived" in fields and fields["archived"] is None:
        raise HTTPException(422, "Archive state required")
    with store(request).connect() as db:
        db.execute("BEGIN IMMEDIATE")
        row = dict(copilot.owned(db, actor.username, tid))
        copilot.incident_exists(db, fields.get("incident_id"))
        row.update(fields)
        db.execute(
            "UPDATE assistant_threads SET title=?,incident_id=?,archived=? WHERE id=?",
            (row["title"], row["incident_id"], row["archived"], tid),
        )
        return safe(request, dict(copilot.owned(db, actor.username, tid)))


@router.delete("/{tid}")
def delete_thread(tid: str, request: Request, actor=Depends(auth.principal)):
    with store(request).connect() as db:
        db.execute("BEGIN IMMEDIATE")
        copilot.owned(db, actor.username, tid)
        if db.execute("SELECT 1 FROM assistant_action_intents WHERE thread_id=?", (tid,)).fetchone():
            raise HTTPException(409, "Archive conversations that have response audit history")
        db.execute("DELETE FROM assistant_channel_links WHERE thread_id=?", (tid,))
        db.execute("DELETE FROM assistant_link_tokens WHERE thread_id=?", (tid,))
        db.execute("DELETE FROM assistant_messages WHERE thread_id=?", (tid,))
        db.execute("DELETE FROM assistant_threads WHERE id=?", (tid,))
        return {"deleted": True}


@router.post("/{tid}/messages")
def send(tid: str, payload: Exchange, request: Request, actor=Depends(auth.principal)):
    question = Question(**payload.model_dump(exclude={"request_key", "history"}))
    return safe(
        request,
        copilot.ask(
            store(request), request.app.state.settings, actor.username, tid, payload.request_key, question
        ),
    )


@router.post("/{tid}/telegram-link")
def issue_link(tid: str, request: Request, actor=Depends(auth.principal)):
    return {"code": copilot.issue_link(store(request), actor.username, tid), "expires_in": 300}


@router.post("/{tid}/actions")
def prepare(tid: str, payload: Prepare, request: Request, actor=Depends(auth.require("approver"))):
    return safe(
        request,
        copilot_actions.prepare(
            store(request),
            request.app.state.settings,
            actor.username,
            tid,
            cid=payload.incident_id,
            policy=payload.policy,
            justification=payload.justification,
            ttl=payload.ttl,
        ),
    )


@router.post("/{tid}/actions/{iid}")
def confirm(tid: str, iid: str, payload: Confirm, request: Request, actor=Depends(auth.require("approver"))):
    return safe(
        request,
        copilot_actions.confirm(
            store(request),
            request.app.state.settings,
            actor.username,
            tid,
            iid,
            payload.decision,
        ),
    )
