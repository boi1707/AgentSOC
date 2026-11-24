"""Session-protected retrieval and authenticated Shuffle ingress."""

import asyncio
import hashlib
import hmac
import json
import re
import time

from fastapi import APIRouter, Depends, HTTPException, Request
from pydantic import BaseModel, ConfigDict, Field

from src import auth
from src.api.v1 import safe, store
from src.approvals import decide, proposal
from src.assistant import Question, answer

router = APIRouter(prefix="/api/v1")


@router.post("/assistant/query")
def query(payload: Question, request: Request, actor=Depends(auth.principal)):
    if any(len(item) > 2000 for item in payload.history):
        raise HTTPException(422, "History exceeds budget")
    return safe(request, answer(store(request), request.app.state.settings, payload))


@router.get("/proposals")
def proposals(request: Request, actor=Depends(auth.principal)):
    repo = store(request)
    with repo.connect() as db:
        rows = db.execute(
            "SELECT * FROM cases WHERE status='pending' ORDER BY created DESC LIMIT 100"
        ).fetchall()
    return safe(
        request, {"items": [proposal(repo, request.app.state.settings, repo.decode(r)) for r in rows]}
    )


class TelegramCommand(BaseModel):
    model_config = ConfigDict(extra="forbid")
    update_id: str = Field(min_length=1, max_length=100)
    user_id: str = Field(pattern="^[0-9]+$", max_length=30)
    chat_id: str = Field(pattern="^-?[0-9]+$", max_length=30)
    command: str = Field(min_length=1, max_length=2000)
    language: str = Field(default="en", pattern="^(en|vi)$")
    callback_data: str | None = Field(default=None, max_length=64)
    callback_query_id: str | None = Field(default=None, max_length=128)


@router.post("/integrations/telegram")
async def telegram(request: Request):
    repo, settings = store(request), request.app.state.settings
    raw = await request.body()
    timestamp = request.headers.get("X-AgentSOC-Timestamp", "")
    signature = request.headers.get("X-AgentSOC-Signature", "")
    try:
        fresh = abs(time.time() - int(timestamp)) <= 300
    except ValueError:
        fresh = False
    expected = hmac.new(
        settings.shuffle_callback_secret.encode(), timestamp.encode() + b"." + raw, hashlib.sha256
    ).hexdigest()
    if (
        not settings.shuffle_callback_secret
        or not fresh
        or not hmac.compare_digest(signature.encode(), expected.encode())
    ):
        repo.audit("shuffle", "telegram.signature", None, "denied")
        raise HTTPException(401, "Invalid or expired callback signature")
    try:
        payload = TelegramCommand.model_validate_json(raw)
    except ValueError:
        raise HTTPException(422, "Invalid Telegram command") from None
    username = settings.telegram_users.get(payload.user_id)
    with repo.connect() as db:
        user = db.execute("SELECT * FROM users WHERE username=? AND disabled=0", (username,)).fetchone()
    if not user:
        repo.audit("telegram:" + payload.user_id, "telegram.authorization", None, "denied")
        raise HTTPException(403, "Telegram user is not an authorized operator")
    digest = hashlib.sha256(raw).hexdigest()
    # Reserve before dispatch. A crash leaves a visible in-progress receipt; it never re-executes.
    with repo.connect() as db:
        db.execute("BEGIN IMMEDIATE")
        prior = db.execute("SELECT * FROM callback_receipts WHERE id=?", (payload.update_id,)).fetchone()
        if prior:
            if prior["digest"] != digest:
                raise HTTPException(409, "Update ID reused with different content")
            if not prior["result"]:
                raise HTTPException(409, "Callback already processing; inspect authoritative incident state")
            return json.loads(prior["result"])
        db.execute(
            "INSERT INTO callback_receipts VALUES(?,?,?,NULL)", (payload.update_id, time.time(), digest)
        )
    try:
        result = await asyncio.to_thread(dispatch, repo, settings, payload, dict(user))
    except HTTPException as exc:
        result = {"error": {"code": exc.status_code, "message": exc.detail}}
    result = safe(
        request,
        {
            "update_id": payload.update_id,
            "chat_id": payload.chat_id,
            "callback_query_id": payload.callback_query_id,
            **result,
        },
    )
    with repo.connect() as db:
        db.execute(
            "UPDATE callback_receipts SET result=? WHERE id=?", (json.dumps(result), payload.update_id)
        )
        repo.audit(
            user["username"],
            "telegram.command",
            payload.update_id,
            "denied" if "error" in result else "completed",
            db=db,
        )
    return result


def dispatch(repo, settings, payload, user):
    if payload.callback_data is not None:
        match = re.fullmatch(r"as:([ai]):([a-f0-9]{32})", payload.callback_data)
        if payload.command != "/callback" or not payload.callback_query_id or not match:
            raise HTTPException(422, "Invalid proposal button")
        if auth.ROLES.get(user["role"], -1) < auth.ROLES["approver"]:
            raise HTTPException(403, "Insufficient permissions")
        run = repo.get_run(match[2])
        if not run:
            raise HTTPException(404, "Proposal not found")
        return decide(
            repo,
            settings,
            run["case_id"],
            "approve" if match[1] == "a" else "reject",
            run["id"],
            user["username"],
            authenticated=True,
        )
    parts = payload.command.split()
    if not parts:
        raise HTTPException(422, "Command required")
    command = parts[0].split("@")[0].lower()
    if command in {"/approve", "/ignore", "/reject"}:
        if auth.ROLES.get(user["role"], -1) < auth.ROLES["approver"]:
            raise HTTPException(403, "Insufficient permissions")
        if len(parts) != 3:
            raise HTTPException(422, "Use /approve|ignore <incident_id> <proposal_id>")
        return decide(
            repo,
            settings,
            parts[1],
            "approve" if command == "/approve" else "reject",
            parts[2],
            user["username"],
            authenticated=True,
        )
    if command == "/status":
        from src.api.v1 import health_snapshot

        return {"system": health_snapshot(repo, settings)}
    if command not in {"/incidents", "/pending", "/review", "/incident", "/why"}:
        raise HTTPException(
            422, "Supported: /status /incidents /pending /review 24h /incident /why /approve /ignore"
        )
    if command in {"/incident", "/why"} and len(parts) != 2:
        raise HTTPException(422, "Incident ID required")
    if command == "/review" and parts[1:] not in ([], ["24h"]):
        raise HTTPException(422, "Supported review window: 24h")
    return answer(
        repo,
        settings,
        Question(
            message=payload.command,
            language=payload.language,
            incident_id=parts[1] if command in {"/incident", "/why"} else None,
        ),
    )
