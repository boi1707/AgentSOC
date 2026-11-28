"""Session-protected retrieval and authenticated Shuffle ingress."""

import asyncio
import hashlib
import hmac
import json
import re
import time

from fastapi import APIRouter, Depends, HTTPException, Request
from pydantic import BaseModel, ConfigDict, Field

from src import auth, copilot, copilot_actions
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
    owner = user["username"]
    if payload.callback_data is not None:
        match = re.fullmatch(r"(as|ac):([ai]):([a-f0-9]{32})", payload.callback_data)
        if payload.command != "/callback" or not payload.callback_query_id or not match:
            raise HTTPException(422, "Invalid proposal button")
        if auth.ROLES.get(user["role"], -1) < auth.ROLES["approver"]:
            raise HTTPException(403, "Insufficient permissions")
        if match[1] == "ac":
            tid = copilot.telegram_thread(repo, owner, payload)
            return {
                "copilot_action": copilot_actions.confirm(
                    repo, settings, owner, tid, match[3], "approve" if match[2] == "a" else "reject"
                )
            }
        run = repo.get_run(match[3])
        if not run:
            raise HTTPException(404, "Proposal not found")
        return decide(
            repo,
            settings,
            run["case_id"],
            "approve" if match[2] == "a" else "reject",
            run["id"],
            user["username"],
            authenticated=True,
        )
    parts = payload.command.split()
    if not parts:
        raise HTTPException(422, "Command required")
    command = parts[0].split("@")[0].lower()
    if payload.chat_id == payload.user_id:
        result = conversation_command(repo, settings, payload, owner, command, parts)
        if result is not None:
            return result
    elif command in {"/start", "/help"}:
        return {"copilot_text": "Open a private chat with the bot to investigate or continue a conversation."}
    elif command not in {"/status", "/approve", "/reject", "/ignore"}:
        raise HTTPException(403, "Use a private bot chat for conversation history or actions")
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

        return {"system": health_snapshot(repo, settings), "language": payload.language}
    raise HTTPException(422, "Unsupported Telegram command. Use /help in a private bot chat.")


def conversation_command(repo, settings, payload, owner, command, parts):
    if command in {"/start", "/help"}:
        return {
            "copilot_text": "AgentSOC Copilot: /analyze <incident>, /history, /new, /use <thread>, "
            "/link <code>, /evidence <incident>, /prepare <justification>, /proposals, /select <intent>, "
            "/confirm <intent> approve|reject. Use /clear to archive the current conversation."
        }
    if command in {"/link", "/use"}:
        if len(parts) != 2:
            raise HTTPException(422, "A link code or conversation ID is required")
        args = {"code": parts[1]} if command == "/link" else {"select": parts[1]}
        tid = copilot.telegram_thread(repo, owner, payload, **args)
        return {"copilot_text": "Selected conversation " + tid}
    if command == "/history":
        items = copilot.list_threads(repo, owner, limit=15)["items"]
        return {
            "copilot_text": "\n".join(
                ["Conversations · /use <id>"]
                + [row["id"] + " " + row["title"] for row in items if not row["archived"]]
            )
        }
    if command in {"/new", "/clear"}:
        if command == "/clear":
            tid = copilot.telegram_thread(repo, owner, payload)
            with repo.connect() as db:
                db.execute("UPDATE assistant_threads SET archived=1 WHERE id=? AND owner=?", (tid, owner))
        tid = copilot.telegram_thread(repo, owner, payload, create_new=True)
        return {"copilot_text": "New conversation " + tid}
    if command in {"/prepare", "/proposals", "/confirm", "/select"}:
        tid = copilot.telegram_thread(repo, owner, payload)
        if command == "/select":
            if len(parts) != 2 or not re.fullmatch(r"[a-f0-9]{32}", parts[1]):
                raise HTTPException(422, "Use /select <intent ID>")
            copilot.telegram_intent(repo, owner, payload, tid, parts[1])
            return {
                "copilot_text": "Selected intent "
                + parts[1]
                + ". Say Approve or Reject to see its confirmation."
            }
        if command == "/confirm":
            if len(parts) != 3:
                raise HTTPException(422, "Use /confirm <intent> approve|reject")
            return {"copilot_action": copilot_actions.confirm(repo, settings, owner, tid, parts[1], parts[2])}
        if command == "/proposals":
            actions = copilot.history(repo, owner, tid, limit=1)["actions"]
            return {
                "copilot_text": "\n".join(
                    ["Response intents in this conversation"]
                    + [row["id"] + " " + row["status"] for row in actions]
                )
            }
        policy = "manual_analyst" if len(parts) > 1 else "standard"
        return {
            "copilot_action": copilot_actions.prepare(
                repo, settings, owner, tid, policy=policy, justification=" ".join(parts[1:])[:1000]
            )
        }
    if command.startswith("/") and command not in {
        "/ask",
        "/incident",
        "/why",
        "/analyze",
        "/evidence",
        "/incidents",
        "/pending",
        "/dangerous",
        "/review",
    }:
        return None
    if command in {"/incident", "/why", "/analyze", "/evidence"} and len(parts) != 2:
        raise HTTPException(422, "Incident ID required")
    if command == "/review" and parts[1:] not in ([], ["24h"]):
        raise HTTPException(422, "Supported review window: 24h")
    message = " ".join(parts[1:]) if command == "/ask" else payload.command
    if not message.strip():
        raise HTTPException(422, "Question required")
    tid = copilot.telegram_thread(repo, owner, payload)
    question = Question(
        message=message,
        language=payload.language,
        incident_id=parts[1] if command in {"/incident", "/why", "/analyze", "/evidence"} else None,
    )
    exchange = copilot.ask(
        repo,
        settings,
        owner,
        tid,
        "tg-" + payload.update_id,
        question,
        selected_intent_id=copilot.telegram_intent(repo, owner, payload, tid),
    )
    result = exchange["answer"]
    if result and result.get("confirmation"):
        confirmation = result["confirmation"]
        action = copilot_actions.confirmation_preview(repo, owner, tid, confirmation["intent_id"])
        return {"copilot_action": action, "confirmation_decision": confirmation["decision"]}
    if result and result.get("action_intent_id"):
        with repo.connect() as db:
            row = db.execute(
                "SELECT * FROM assistant_action_intents WHERE id=? AND thread_id=?",
                (result["action_intent_id"], tid),
            ).fetchone()
        if row:
            return {"copilot_action": copilot_actions.preview(row)}
    return result or {"copilot_text": "Conversation request is still processing."}
