"""Three read-only tools. Scope and replay cutoff are enforced here, not by prompts."""

import json
import time
import uuid
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field


class ToolRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    name: Literal["incident_evidence", "related_alerts", "previous_investigations"]
    run_id: str = Field(min_length=1, max_length=64)
    entity: str | None = Field(default=None, max_length=300)
    limit: int = Field(default=20, ge=1, le=40)
    window_seconds: int = Field(default=3600, ge=1, le=86400)


class ToolResult(BaseModel):
    name: str
    items: list[dict]
    cutoff: float
    truncated: bool


class ToolBlocked(ValueError):
    pass


def execute(store, request, anon, *, incident_id, actor="worker"):
    start = time.monotonic()
    try:
        return _execute(store, request, anon, incident_id=incident_id, actor=actor)
    except ToolBlocked:
        raise
    except Exception as exc:
        store.audit(
            actor,
            "tool." + request.name,
            request.run_id,
            "denied" if isinstance(exc, PermissionError) else type(exc).__name__,
        )
        run = store.get_run(request.run_id)
        if run and run["case_id"] == incident_id:
            prompt = json.dumps(anon.obj(request.model_dump()))
            with store.connect() as db:
                db.execute(
                    "INSERT INTO ledger(ts,case_id,agent,mode,prompt,response,evidence,usage,duration_ms,error,run_id,step_id,provider,prompt_version,tool_name) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
                    (
                        time.time(),
                        incident_id,
                        "tool",
                        run["mode"],
                        "{}" if anon.leaks(prompt) else prompt,
                        None,
                        "[]",
                        "{}",
                        (time.monotonic() - start) * 1000,
                        type(exc).__name__,
                        run["id"],
                        uuid.uuid4().hex,
                        "sqlite",
                        run["prompt_version"],
                        request.name,
                    ),
                )
        raise


def _execute(store, request, anon, *, incident_id, actor="worker"):
    start = time.monotonic()
    run = store.get_run(request.run_id)
    if not run or run["case_id"] != incident_id:
        raise PermissionError("Tool run is outside incident scope")
    entities = run["evidence"].get("entities", [])
    with store.connect() as db:
        db.execute("PRAGMA busy_timeout=2000")
        deadline = time.monotonic() + 2
        db.set_progress_handler(lambda: int(time.monotonic() > deadline), 1000)
        if request.name == "incident_evidence":
            items = run["evidence"]["alerts"]
        elif request.name == "related_alerts":
            if not request.entity or request.entity not in entities:
                raise PermissionError("Entity is outside evidence snapshot")
            # json_each avoids substring matches and all values use bound parameters.
            rows = db.execute(
                "SELECT id,normalized,received FROM inbox WHERE received BETWEEN ? AND ? AND EXISTS(SELECT 1 FROM json_each(inbox.normalized,'$.entities') WHERE value=?) ORDER BY received DESC,id LIMIT ?",
                (run["cutoff"] - request.window_seconds, run["cutoff"], request.entity, request.limit + 1),
            ).fetchall()
            items = [
                {
                    "id": r["id"],
                    "received_at": r["received"],
                    "evidence": json.loads(r["normalized"])["evidence"],
                }
                for r in rows
            ]
        elif request.name == "previous_investigations":
            # Completed runs sharing a snapshot entity, within this local workspace and cutoff.
            scoped = entities[:40]
            placeholders = ",".join("?" for _ in scoped)
            rows = (
                db.execute(
                    "SELECT r.id,r.created,r.status,r.verdict FROM runs r WHERE r.id!=? AND r.finished BETWEEN ? AND ? "
                    "AND EXISTS(SELECT 1 FROM incident_alerts a JOIN inbox i ON i.id=a.alert_id "
                    "JOIN json_each(i.normalized,'$.entities') e WHERE a.case_id=r.case_id AND e.value IN ("
                    + placeholders
                    + ")) "
                    "ORDER BY r.created DESC,r.id LIMIT ?",
                    (
                        run["id"],
                        run["cutoff"] - request.window_seconds,
                        run["cutoff"],
                        *scoped,
                        request.limit + 1,
                    ),
                ).fetchall()
                if scoped
                else []
            )
            items = [dict(r) for r in rows]
        else:
            raise ValueError("Unknown read-only tool")
    result = ToolResult(
        name=request.name,
        items=items[: request.limit],
        cutoff=run["cutoff"],
        truncated=len(items) > request.limit,
    )
    safe_args = anon.obj(request.model_dump())
    safe_result = anon.obj(result.model_dump())
    prompt, output = json.dumps(safe_args), json.dumps(safe_result)
    refused = bool(anon.leaks(prompt) or anon.leaks(output))
    with store.connect() as db:
        db.execute(
            "INSERT INTO ledger(ts,case_id,agent,mode,prompt,response,evidence,usage,duration_ms,error,run_id,step_id,provider,prompt_version,tool_name) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
            (
                time.time(),
                incident_id,
                "tool",
                run["mode"],
                "{}" if refused else prompt,
                None if refused else output,
                "[]",
                "{}",
                (time.monotonic() - start) * 1000,
                "Blocked" if refused else None,
                run["id"],
                uuid.uuid4().hex,
                "sqlite",
                run["prompt_version"],
                request.name,
            ),
        )
        store.audit(actor, "tool." + request.name, run["id"], "blocked" if refused else "completed", db=db)
    if refused:
        raise ToolBlocked("Tool privacy guard refused output")
    return result
