"""Pure helpers for Shuffle Python steps; no network calls or embedded credentials.

See README.md for the two workflows and the authenticated Telegram ingress boundary.
"""

import hashlib
import hmac
import json
import re
import sqlite3
import time
import uuid
from contextlib import contextmanager
from pathlib import Path


def verify_telegram_ingress(headers, webhook_secret):
    actual = next(
        (value for key, value in headers.items() if key.lower() == "x-telegram-bot-api-secret-token"), ""
    )
    if (
        not webhook_secret
        or not isinstance(actual, str)
        or not hmac.compare_digest(actual.encode(), webhook_secret.encode())
    ):
        raise ValueError("Untrusted Telegram ingress")


def trusted_callback_request(headers, update, webhook_secret, signing_secret, **kwargs):
    verify_telegram_ingress(headers, webhook_secret)
    return callback_request(update, signing_secret, **kwargs)


def callback_request(update, secret, *, language="en", now=None):
    """Call only after ingress verification. Never accept identity from query parameters."""
    button = update.get("callback_query")
    message = button.get("message", {}) if button else update.get("message", {})
    sender = button.get("from", {}) if button else message.get("from", {})
    if sender.get("is_bot"):
        raise ValueError("Only human commands are supported")
    if button:
        if not re.fullmatch(r"(?:as|ac):[ai]:[a-f0-9]{32}", str(button.get("data", ""))):
            raise ValueError("Invalid proposal button")
        command = "/callback"
    elif isinstance(message.get("text"), str):
        command = message["text"]
    else:
        raise ValueError("Only human text commands are supported")
    payload = {
        "update_id": str(update["update_id"]),
        "user_id": str(sender["id"]),
        "chat_id": str(message["chat"]["id"]),
        "command": command,
        "language": language,
    }
    if button:
        payload.update(callback_data=button["data"], callback_query_id=str(button["id"]))
    raw = json.dumps(payload, ensure_ascii=False, separators=(",", ":")).encode()
    timestamp = str(int(time.time() if now is None else now))
    signature = hmac.new(secret.encode(), timestamp.encode() + b"." + raw, hashlib.sha256).hexdigest()
    return {
        "body": raw.decode(),
        "headers": {
            "Content-Type": "application/json",
            "X-AgentSOC-Timestamp": timestamp,
            "X-AgentSOC-Signature": signature,
        },
    }


def notification_text(event):
    """Plain Telegram text; do not enable Markdown/HTML parsing of incident content."""
    if event["event"] == "response.completed":
        return (
            f"AgentSOC {event['case_id']}\nDecision: {event['decision']}\n"
            f"Result: {event['status']}\nMode: {event['mode']}\nBlocked: {event['blocked']}\n"
            f"Event: {event['event_id']}"
        )
    p = event["proposal"]
    text = (
        f"AgentSOC {event['case_id']}\nVerdict: {event.get('verdict')}\n"
        f"Severity: {event.get('severity', 'unknown')}\nExplanation (AI): {str(event.get('explanation', 'Unavailable'))[:1800]}\n"
        f"Proposal: {p['id']}\nEligible: {p['eligible']}\nSource: {p['source_ip']}\n"
        f"Mode: {p['mode']}\nExpires (Unix): {p['expires']}\nEvidence: {', '.join(p['evidence_ids'])}\n"
        + json.dumps(event.get("evidence_summary", []), ensure_ascii=False)[:800]
    )
    if p["eligible"] and p.get("run_id"):
        text += f"\n/approve {event['case_id']} {p['id']}\n/ignore {event['case_id']} {p['id']}"
    return text[:3500]


def notification_requests(event):
    """Two independent delivery identities; buttons fit Telegram's 64-byte limit."""
    requests = []
    for chat in dict.fromkeys(event["notification_recipients"]):
        if not re.fullmatch(r"-?[0-9]+", str(chat)):
            raise ValueError("Invalid notification chat")
        body = {"chat_id": str(chat), "text": notification_text(event)}
        p = event.get("proposal", {})
        if event["event"] == "proposal.created" and p.get("eligible") and p.get("run_id"):
            if p["run_id"] != p["id"] or not re.fullmatch(r"[a-f0-9]{32}", p["id"]):
                raise ValueError("Inline approval requires a versioned analysis run")
            body["reply_markup"] = {
                "inline_keyboard": [
                    [
                        {"text": "Approve", "callback_data": "as:a:" + p["id"]},
                        {"text": "Ignore", "callback_data": "as:i:" + p["id"]},
                    ]
                ]
            }
        requests.append({"event_id": event["event_id"], "chat_id": str(chat), "body": body})
    return requests


class DeliveryLedger:
    """Optional persistent Shuffle-side delivery ledger; contains no incident authority.

    Mount its directory persistently and share it across all workflow executors, or implement
    the same unique-key/CAS operations in your Shuffle instance's durable store.
    """

    def __init__(self, path):
        self.path = str(path)
        Path(path).parent.mkdir(parents=True, exist_ok=True)
        with self.connect() as db:
            db.execute(
                "CREATE TABLE IF NOT EXISTS delivery(event_id TEXT,chat_id TEXT,status TEXT,"
                "token TEXT,lease REAL,message_id TEXT,error TEXT,PRIMARY KEY(event_id,chat_id))"
            )

    @contextmanager
    def connect(self):
        db = sqlite3.connect(self.path, timeout=15)
        try:
            with db:
                yield db
        finally:
            db.close()

    def claim(self, event_id, chat_id, *, now=None):
        now = time.time() if now is None else now
        with self.connect() as db:
            db.execute("BEGIN IMMEDIATE")
            db.execute(
                "INSERT OR IGNORE INTO delivery VALUES(?,?,'pending',NULL,0,NULL,NULL)", (event_id, chat_id)
            )
            row = db.execute(
                "SELECT status,lease FROM delivery WHERE event_id=? AND chat_id=?", (event_id, chat_id)
            ).fetchone()
            if row[0] == "sending" and row[1] <= now:
                db.execute(
                    "UPDATE delivery SET status='unknown',error='AcknowledgementUnknown' WHERE event_id=? AND chat_id=?",
                    (event_id, chat_id),
                )
                return None
            if row[0] not in {"pending", "retry"}:
                return None
            token = uuid.uuid4().hex
            db.execute(
                "UPDATE delivery SET status='sending',token=?,lease=? WHERE event_id=? AND chat_id=?",
                (token, now + 60, event_id, chat_id),
            )
            return token

    def finish(self, event_id, chat_id, token, status, *, message_id=None):
        if status not in {"delivered", "retry", "unknown"}:
            raise ValueError("Invalid delivery state")
        with self.connect() as db:
            return (
                db.execute(
                    "UPDATE delivery SET status=?,message_id=?,error=?,lease=0 WHERE event_id=? AND chat_id=? AND token=? AND status='sending' AND lease>?",
                    (
                        status,
                        str(message_id) if message_id is not None else None,
                        None if status == "delivered" else "Delivery" + status.title(),
                        event_id,
                        chat_id,
                        token,
                        time.time(),
                    ),
                ).rowcount
                == 1
            )

    def status(self, event_id, chat_id):
        with self.connect() as db:
            row = db.execute(
                "SELECT status FROM delivery WHERE event_id=? AND chat_id=?", (event_id, chat_id)
            ).fetchone()
            return row[0] if row else "pending"


def query_text(result):
    if "error" in result:
        return str(result["error"]["message"])[:3500]
    if "copilot_text" in result:
        return result["copilot_text"][:3500]
    if "copilot_action" in result:
        action = result["copilot_action"]
        if action["status"] != "prepared":
            return f"Intent {action['id']}: {action['status']}; dry-run; blocked=false"
        return (
            f"Intent {action['id']} · {action['approval_policy']} · dry-run\n"
            f"Incident {action['case_id']} · run {action['run_id']}\n"
            f"Source: {action['target']} · Verdict: {action['original_judge_verdict']}\n"
            f"Evidence: {', '.join(action['evidence_ids'])}\n"
            f"Gaps: {'; '.join(action['evidence_gaps'])}\n"
            f"Justification: {action['justification']}\n"
            f"Expires (Unix): {action['expires']} · duration {action['ttl']} seconds\n"
            f"/confirm {action['id']} approve\n/confirm {action['id']} reject"
        )[:3500]
    if "status" in result:
        # Final decision is delivered exclusively by the response.completed event workflow.
        return "Decision request recorded. Reference: " + str(result["update_id"])
    if "system" in result:
        state = result["system"]
        return f"AgentSOC: {state['response_mode']}\nWorker fresh: {state['worker_fresh']}\nBacklog: {state['backlog']}"
    # Use the same server-authored conclusion shown by Web; never dump evidence JSON.
    lines = []
    fallback = result.get("fallback")
    if isinstance(fallback, dict) and fallback.get("origin") == "stored_analysis":
        lines.extend([fallback["label"], fallback["text"]])
    elif result.get("interpretation"):
        lines.append("AI interpretation: " + result["interpretation"])
    else:
        # Compatibility with older AgentSOC responses: stored rationale, not new AI prose.
        for analysis in result.get("analysis", [])[:3]:
            lines.append(
                f"Stored analysis {analysis['incident_id']}: {analysis['verdict']}, "
                f"confidence={analysis['confidence']}; {str(analysis['reason'])[:220]}"
            )
    lines.extend([result["summary"], result["notice"]])
    for fact in result.get("facts", [])[:3]:
        p = fact["proposal"]
        lines.append(
            f"{fact['incident_id']}: {fact['status']} / {fact['priority']}\nProposal {p['id']}; eligible={p['eligible']}; source={p['source_ip']}"
        )
    for citation in result.get("citations", [])[:5]:
        lines.append(f"Evidence [{citation['source']}:{citation['id']}]")
    for item in result.get("related", [])[:5]:
        lines.append(f"Historical investigation {item['incident_id']} / {item['run_id']}")
    return "\n".join(lines)[:3500]


def query_reply(result):
    body = {"chat_id": result["chat_id"], "text": query_text(result)}
    action = result.get("copilot_action")
    if action and action["status"] == "prepared" and re.fullmatch(r"[a-f0-9]{32}", action["id"]):
        body["reply_markup"] = {
            "inline_keyboard": [
                [
                    {"text": "Approve", "callback_data": "ac:a:" + action["id"]},
                    {"text": "Reject", "callback_data": "ac:i:" + action["id"]},
                ]
            ]
        }
    return body
