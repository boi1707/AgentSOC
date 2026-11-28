"""Persistent, owner-scoped investigation using the existing evidence assistant."""

import hashlib
import json
import re
import secrets
import time
from uuid import uuid4

from fastapi import HTTPException

from .anon import IPV4, IPV6, Anon
from .assistant import Question, answer, folded, intent
from .tools import ToolBlocked, ToolRequest, execute

SCHEMA = (
    """CREATE TABLE IF NOT EXISTS assistant_threads(
        id TEXT PRIMARY KEY,owner TEXT NOT NULL,title TEXT NOT NULL,incident_id TEXT,
        created REAL NOT NULL,updated REAL NOT NULL,archived INTEGER NOT NULL DEFAULT 0)""",
    "CREATE INDEX IF NOT EXISTS assistant_threads_owner ON assistant_threads(owner,updated DESC,id)",
    """CREATE TABLE IF NOT EXISTS assistant_messages(
        id TEXT PRIMARY KEY,thread_id TEXT NOT NULL,request_key TEXT NOT NULL,digest TEXT NOT NULL,
        content TEXT NOT NULL,incident_id TEXT,created REAL NOT NULL,lease REAL NOT NULL,claim TEXT NOT NULL,
        status TEXT NOT NULL,result TEXT,UNIQUE(thread_id,request_key))""",
    """CREATE TABLE IF NOT EXISTS assistant_channel_links(
        owner TEXT NOT NULL,user_id TEXT NOT NULL,chat_id TEXT NOT NULL,thread_id TEXT NOT NULL,
        PRIMARY KEY(owner,user_id,chat_id))""",
    """CREATE TABLE IF NOT EXISTS assistant_link_tokens(
        digest TEXT PRIMARY KEY,owner TEXT NOT NULL,thread_id TEXT NOT NULL,expires REAL NOT NULL)""",
    """CREATE TABLE IF NOT EXISTS assistant_action_intents(
        id TEXT PRIMARY KEY,thread_id TEXT NOT NULL,case_id TEXT NOT NULL,run_id TEXT NOT NULL,
        target TEXT NOT NULL,evidence TEXT NOT NULL,judge TEXT NOT NULL,policy TEXT NOT NULL,
        justification TEXT NOT NULL,created REAL NOT NULL,expires REAL NOT NULL,ttl INTEGER NOT NULL,
        status TEXT NOT NULL,action_id INTEGER,UNIQUE(thread_id,run_id))""",
    """CREATE TABLE IF NOT EXISTS assistant_drafts(
        thread_id TEXT PRIMARY KEY,content TEXT NOT NULL,revision INTEGER NOT NULL)""",
    """CREATE TABLE IF NOT EXISTS assistant_channel_intents(
        owner TEXT NOT NULL,user_id TEXT NOT NULL,chat_id TEXT NOT NULL,thread_id TEXT NOT NULL,
        intent_id TEXT NOT NULL,PRIMARY KEY(owner,user_id,chat_id))""",
)
MAX_THREADS = 100
MAX_MESSAGES = 120
LEASE = 120


def prepare_requested(value):
    return bool(
        re.match(
            r"^(?:prepare (?:a )?(?:manual )?(?:containment|response|block)|i want to block|chu[aâ]n bi chan)",
            folded(value).strip(),
        )
    )


def prepare_from_message(store, settings, owner, tid, cid, raw, content, language):
    from .copilot_actions import prepare

    result = clarification(language)
    if IPV4.search(raw) or IPV6.search(raw):
        result["summary"] = (
            "Hãy chọn sự cố và kiểm tra địa chỉ nguồn trong biểu mẫu phản ứng."
            if language == "vi"
            else "Select the incident and verify the source address in the response form."
        )
        return result
    reason = re.split(r"\b(?:because|vì|lý do)\b\s*:?\s*", content, maxsplit=1, flags=re.I)
    justification = reason[1].strip() if len(reason) == 2 else ""
    try:
        if not cid:
            return result
        duration = re.search(r"\b(\d{1,4})\s*(?:hours?|gio|h)\b", folded(raw))
        ttl = int(duration[1]) * 3600 if duration else 86400
        case = store.get(cid)
        manual = justification and case and case["verdict"].get("verdict") == "review"
        action = prepare(
            store,
            settings,
            owner,
            tid,
            cid=cid,
            policy="manual_analyst" if manual else "standard",
            justification=justification,
            ttl=ttl,
        )
        result["action_intent_id"] = action["id"]
        result["summary"] = (
            "Hãy kiểm tra bản xem trước và xác nhận rõ quyết định."
            if language == "vi"
            else "Review the response preview and explicitly confirm your decision."
        )
    except HTTPException as exc:
        result["summary"] = exc.detail
        result["notice"] = (
            "Nếu kết luận là review, hãy nhập lý do của bạn để xem trước."
            if language == "vi"
            else "For a review verdict, enter your own justification to prepare a manual preview."
        )
    return result


def redact(value, settings):
    from .api.v1 import scrub

    configured = (
        settings.ingest_key,
        settings.approve_key,
        settings.admin_password,
        settings.llm_key,
        settings.tg_token,
        *settings.integration_secrets,
    )
    anon = Anon(settings.hosts, secrets=configured)
    return anon.clean(scrub(value, settings))


def owned(db, owner, tid, *, active=False):
    row = db.execute("SELECT * FROM assistant_threads WHERE id=? AND owner=?", (tid, owner)).fetchone()
    if not row:
        raise HTTPException(404, "Conversation not found")
    if active and row["archived"]:
        raise HTTPException(409, "Conversation is archived")
    return row


def incident_exists(db, cid):
    if cid and not db.execute("SELECT 1 FROM cases WHERE id=?", (cid,)).fetchone():
        raise HTTPException(404, "Incident not found")


def create(db, owner, title="Investigation", incident_id=None):
    if (
        db.execute("SELECT count(*) FROM assistant_threads WHERE owner=?", (owner,)).fetchone()[0]
        >= MAX_THREADS
    ):
        raise HTTPException(429, "Conversation limit reached; delete an old conversation")
    incident_exists(db, incident_id)
    tid, now = uuid4().hex, time.time()
    db.execute(
        "INSERT INTO assistant_threads VALUES(?,?,?,?,?,?,0)",
        (tid, owner, title, incident_id, now, now),
    )
    return dict(owned(db, owner, tid))


def list_threads(store, owner, limit=30, offset=0):
    with store.connect() as db:
        rows = db.execute(
            "SELECT * FROM assistant_threads WHERE owner=? ORDER BY updated DESC,id LIMIT ? OFFSET ?",
            (owner, limit + 1, offset),
        ).fetchall()
    return {"items": [dict(row) for row in rows[:limit]], "more": len(rows) > limit}


def history(store, owner, tid, limit=50, before=None):
    from .copilot_actions import preview

    with store.connect() as db:
        thread = dict(owned(db, owner, tid))
        rows = db.execute(
            """SELECT rowid,* FROM assistant_messages WHERE thread_id=? AND rowid<?
               ORDER BY rowid DESC LIMIT ?""",
            (tid, before if before is not None else 2**63 - 1, limit + 1),
        ).fetchall()
        actions = db.execute(
            "SELECT * FROM assistant_action_intents WHERE thread_id=? ORDER BY created DESC LIMIT 20",
            (tid,),
        ).fetchall()
        draft = db.execute(
            "SELECT content,revision FROM assistant_drafts WHERE thread_id=?", (tid,)
        ).fetchone()
    return {
        "thread": thread,
        "messages": [message(row) for row in reversed(rows[:limit])],
        "before": rows[limit - 1]["rowid"] if len(rows) > limit else None,
        "actions": [preview(row) for row in actions],
        "draft": dict(draft) if draft else {"content": "", "revision": 0},
    }


def save_draft(store, settings, owner, tid, content, revision):
    content = redact(content, settings)[:2000]
    with store.connect() as db:
        db.execute("BEGIN IMMEDIATE")
        owned(db, owner, tid, active=True)
        db.execute(
            """INSERT INTO assistant_drafts VALUES(?,?,?)
               ON CONFLICT(thread_id) DO UPDATE SET content=excluded.content,revision=excluded.revision
               WHERE excluded.revision>assistant_drafts.revision""",
            (tid, content, revision),
        )
        return dict(
            db.execute("SELECT content,revision FROM assistant_drafts WHERE thread_id=?", (tid,)).fetchone()
        )


def message(row):
    status = "failed" if row["status"] == "pending" and row["lease"] <= time.time() else row["status"]
    return {
        "id": row["id"],
        "request_key": row["request_key"],
        "question": row["content"],
        "incident_id": row["incident_id"],
        "created": row["created"],
        "status": status,
        "answer": json.loads(row["result"]) if row["result"] else None,
    }


def compact_answer(value, settings):
    from .api.v1 import scrub

    facts = value["facts"][:10]
    for fact in facts:
        fact["rules"] = [
            {k: row[k] for k in ("evidence_id", "rule_id", "level", "protocol")} for row in fact["rules"][:12]
        ]
    result = {
        **{
            k: value[k]
            for k in (
                "language",
                "summary",
                "notice",
                "interpretation",
                "model_status",
                "model_attempts",
                "model_error",
                "fallback",
                "truncated",
            )
        },
        "facts": facts,
        "citations": [
            {k: row[k] for k in ("id", "source", "incident_id")} for row in value["citations"][:40]
        ],
        "analysis": [
            {**row, "reason": redact(str(row.get("reason", "")), settings)[:600]}
            for row in value["analysis"][:10]
        ],
    }
    for key in ("interpretation",):
        if result[key]:
            result[key] = redact(result[key], settings)[:2400]
    if result["fallback"]:
        result["fallback"]["text"] = redact(result["fallback"]["text"], settings)[:2400]
    return scrub(result, settings)


def related_context(store, settings, cid, owner):
    case = store.get(cid)
    run = store.get_run(case["latest_run_id"]) if case and case["latest_run_id"] else None
    if not run or run["status"] != "completed":
        return []
    anon = Anon(
        settings.hosts,
        secrets=(
            settings.ingest_key,
            settings.approve_key,
            settings.admin_password,
            settings.llm_key,
            settings.tg_token,
            *settings.integration_secrets,
        ),
    )
    try:
        historical = execute(
            store,
            ToolRequest(name="previous_investigations", run_id=run["id"], limit=8),
            anon,
            incident_id=cid,
            actor=owner,
        )
    except ToolBlocked:
        return []
    items = []
    for row in historical.items:
        related = store.get_run(row["id"])
        if related and related["case_id"] != cid:
            items.append(
                {"incident_id": related["case_id"], "run_id": related["id"], "status": related["status"]}
            )
    return items


def ask(store, settings, owner, tid, key, question, *, selected_intent_id=None):
    if not question.message.strip():
        raise HTTPException(422, "Question required")
    command = folded(question.message)
    decision = {
        "approve": "approve",
        "phe duyet": "approve",
        "reject": "reject",
        "tu choi": "reject",
    }.get(command.strip(" .!?"))
    selected_intent_id = selected_intent_id if decision else None
    body = question.model_dump_json()
    if selected_intent_id:
        body += ":" + selected_intent_id
    digest = hashlib.sha256(body.encode()).hexdigest()
    content = redact(question.message, settings)
    kind, specified = intent(question.model_copy(update={"incident_id": None}))
    now, claim = time.time(), uuid4().hex
    with store.connect() as db:
        db.execute("BEGIN IMMEDIATE")
        thread = owned(db, owner, tid, active=True)
        previous = db.execute(
            "SELECT * FROM assistant_messages WHERE thread_id=? AND request_key=?", (tid, key)
        ).fetchone()
        if previous and previous["digest"] != digest:
            raise HTTPException(409, "Request key already used")
        if previous and (
            previous["status"] == "completed" or (previous["status"] == "pending" and previous["lease"] > now)
        ):
            return message(previous)
        cid = previous["incident_id"] if previous else specified
        if not previous and not cid:
            if re.search(r"\b(?:latest incident|incident moi nhat|su co moi nhat)\b", command):
                latest = db.execute("SELECT id FROM cases ORDER BY created DESC,id LIMIT 1").fetchone()
                cid = latest["id"] if latest else None
            elif kind not in {"pending_approvals", "most_dangerous"} and not command.startswith(
                ("/incidents", "/review", "/dangerous", "/pending", "/proposals")
            ):
                cid = question.incident_id or thread["incident_id"]
        incident_exists(db, cid)
        if (
            db.execute(
                """SELECT count(*) FROM assistant_messages m JOIN assistant_threads t ON m.thread_id=t.id
               WHERE t.owner=? AND m.created>?""",
                (owner, now - 60),
            ).fetchone()[0]
            >= 12
        ):
            raise HTTPException(429, "Conversation message rate limit reached")
        if db.execute(
            "SELECT 1 FROM assistant_messages WHERE thread_id=? AND status='pending' AND lease>?",
            (tid, now),
        ).fetchone():
            raise HTTPException(409, "Another message is processing in this conversation")
        if previous:
            mid = previous["id"]
            db.execute(
                "UPDATE assistant_messages SET status='pending',lease=?,claim=? WHERE id=?",
                (now + LEASE, claim, mid),
            )
        else:
            if (
                db.execute("SELECT count(*) FROM assistant_messages WHERE thread_id=?", (tid,)).fetchone()[0]
                >= MAX_MESSAGES
            ):
                raise HTTPException(429, "Conversation is full; start a new conversation")
            mid = uuid4().hex
            db.execute(
                "INSERT INTO assistant_messages VALUES(?,?,?,?,?,?,?,?,?,'pending',NULL)",
                (mid, tid, key, digest, content, cid, now, now + LEASE, claim),
            )
        prior = db.execute(
            """SELECT content FROM assistant_messages WHERE thread_id=? AND id!=? AND status='completed'
               AND incident_id IS ? ORDER BY rowid DESC LIMIT 4""",
            (tid, mid, cid),
        ).fetchall()
        db.execute(
            "UPDATE assistant_threads SET updated=?,incident_id=COALESCE(?,incident_id) WHERE id=?",
            (now, cid, tid),
        )
    try:
        if decision or command.strip(" .!?") in {"confirm", "xac nhan"}:
            result = clarification(question.language)
            result["summary"] = (
                "Hãy chọn một đề xuất đang chờ rồi xác nhận trên thẻ phản ứng."
                if question.language == "vi"
                else "Select a prepared intent, then use its confirmation control."
            )
            if selected_intent_id:
                from .copilot_actions import confirmation_preview

                try:
                    confirmation_preview(store, owner, tid, selected_intent_id)
                except HTTPException as exc:
                    result["summary"] = exc.detail
                else:
                    result["confirmation"] = {"intent_id": selected_intent_id, "decision": decision}
                    result["summary"] = (
                        "Hãy kiểm tra đề xuất đã chọn và xác nhận quyết định."
                        if question.language == "vi"
                        else "Review the selected intent and confirm your decision."
                    )
        elif prepare_requested(content):
            result = prepare_from_message(
                store, settings, owner, tid, cid, question.message, content, question.language
            )
        elif not cid and re.search(
            r"\b(?:this incident|its source|that ip|su co nay|dia chi nay)\b", command
        ):
            result = clarification(question.language)
        else:
            grounded = Question(
                message=content,
                language=question.language,
                incident_id=cid,
                history=[row["content"] for row in reversed(prior)],
            )
            result = compact_answer(answer(store, settings, grounded), settings)
            if cid and re.search(
                r"\b(?:related incidents|investigate further|investigate.*more deeply|su co lien quan)\b",
                command,
            ):
                result["related"] = related_context(store, settings, cid, owner)
    except Exception:
        with store.connect() as db:
            db.execute("UPDATE assistant_messages SET status='failed' WHERE id=? AND claim=?", (mid, claim))
        raise
    with store.connect() as db:
        db.execute(
            "UPDATE assistant_messages SET status='completed',result=? WHERE id=? AND claim=?",
            (json.dumps(result, ensure_ascii=False), mid, claim),
        )
        row = db.execute("SELECT * FROM assistant_messages WHERE id=?", (mid,)).fetchone()
        if not row:
            raise HTTPException(404, "Conversation was deleted")
        return message(row)


def clarification(language):
    return {
        "language": language,
        "facts": [],
        "citations": [],
        "analysis": [],
        "model_status": "evidence_only",
        "summary": "Hãy chọn một sự cố cụ thể." if language == "vi" else "Select a specific incident first.",
        "notice": "",
        "interpretation": None,
        "fallback": None,
        "truncated": False,
    }


def issue_link(store, owner, tid):
    token = secrets.token_urlsafe(24)
    with store.connect() as db:
        db.execute("BEGIN IMMEDIATE")
        owned(db, owner, tid, active=True)
        db.execute("DELETE FROM assistant_link_tokens WHERE expires<=? OR owner=?", (time.time(), owner))
        db.execute(
            "INSERT INTO assistant_link_tokens VALUES(?,?,?,?)",
            (hashlib.sha256(token.encode()).hexdigest(), owner, tid, time.time() + 300),
        )
    return token


def telegram_thread(store, owner, payload, *, create_new=False, code=None, select=None):
    chat, sender = payload.chat_id, payload.user_id
    # A signed private Telegram chat has the same chat and sender IDs. Group messages are public.
    if chat != sender:
        raise HTTPException(403, "Use a private bot chat for conversation history or actions")
    with store.connect() as db:
        db.execute("BEGIN IMMEDIATE")
        if code:
            digest = hashlib.sha256(code.encode()).hexdigest()
            link = db.execute(
                "SELECT thread_id FROM assistant_link_tokens WHERE digest=? AND owner=? AND expires>?",
                (digest, owner, time.time()),
            ).fetchone()
            if not link:
                raise HTTPException(404, "Conversation link is invalid or expired")
            tid = link["thread_id"]
            owned(db, owner, tid, active=True)
            db.execute("DELETE FROM assistant_link_tokens WHERE digest=?", (digest,))
        elif select:
            tid = owned(db, owner, select, active=True)["id"]
        else:
            link = db.execute(
                """SELECT l.thread_id FROM assistant_channel_links l JOIN assistant_threads t ON t.id=l.thread_id
                   WHERE l.owner=? AND l.user_id=? AND l.chat_id=? AND t.archived=0""",
                (owner, sender, chat),
            ).fetchone()
            if link and not create_new:
                return link["thread_id"]
            tid = create(db, owner, "Telegram investigation")["id"]
        db.execute(
            "INSERT OR REPLACE INTO assistant_channel_links VALUES(?,?,?,?)", (owner, sender, chat, tid)
        )
        db.execute(
            "DELETE FROM assistant_channel_intents WHERE owner=? AND user_id=? AND chat_id=?",
            (owner, sender, chat),
        )
        return tid


def telegram_intent(store, owner, payload, tid, selection=None):
    from .copilot_actions import confirmation_preview

    key = (owner, payload.user_id, payload.chat_id, tid)
    with store.connect() as db:
        if selection:
            db.execute("BEGIN IMMEDIATE")
            if not db.execute(
                "SELECT 1 FROM assistant_channel_links WHERE owner=? AND user_id=? AND chat_id=? AND thread_id=?",
                key,
            ).fetchone():
                raise HTTPException(409, "Telegram conversation selection changed")
            confirmation_preview(store, owner, tid, selection, db=db)
            db.execute(
                "INSERT OR REPLACE INTO assistant_channel_intents VALUES(?,?,?,?,?)", (*key, selection)
            )
        row = db.execute(
            "SELECT intent_id FROM assistant_channel_intents WHERE owner=? AND user_id=? AND chat_id=? AND thread_id=?",
            key,
        ).fetchone()
        return row["intent_id"] if row else None
