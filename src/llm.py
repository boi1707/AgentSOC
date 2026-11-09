import json
import logging
import time
import uuid

import httpx

from .agents import Finding, Verdict
from .providers import MockProvider, OpenAICompatibleProvider, Provider

log = logging.getLogger("agentsoc.llm")


class Blocked(Exception):
    pass


class LLM:
    def __init__(self, settings, store, post=None):
        self.settings, self.store, self.post = settings, store, post or httpx.post
        self.run_id = None
        self.attempt = 1

    def ask(self, anon, cid, role, system, payload, evidence_ids):
        anon.secrets = tuple(
            set(
                (
                    *anon.secrets,
                    *(
                        v
                        for v in (
                            self.settings.ingest_key,
                            self.settings.approve_key,
                            self.settings.llm_key,
                            self.settings.admin_password,
                            self.settings.tg_token,
                            *self.settings.integration_secrets,
                        )
                        if v
                    ),
                )
            )
        )
        # Scan the entire messages array, including the system prompt, before any I/O.
        messages = anon.obj(
            [
                {"role": "system", "content": system},
                {"role": "user", "content": json.dumps(anon.obj(payload), ensure_ascii=False)},
            ]
        )
        prompt = json.dumps(messages, ensure_ascii=False)
        start = time.monotonic()
        started_at = time.time()
        response, usage, error = None, {}, None
        actual_model = self.settings.llm_model if self.settings.llm_mode == "live" else None
        model_source = "requested_configuration" if actual_model else None
        step_id = uuid.uuid4().hex
        if self.run_id:
            with self.store.connect() as db:
                queued = db.execute(
                    "SELECT id FROM steps WHERE run_id=? AND role=? AND status='queued' AND attempt=0 LIMIT 1",
                    (self.run_id, role),
                ).fetchone()
                if queued:
                    step_id = queued["id"]
                    db.execute(
                        "UPDATE steps SET status='running',attempt=?,started=? WHERE id=?",
                        (self.attempt, started_at, step_id),
                    )
                else:
                    db.execute(
                        "INSERT INTO steps(id,run_id,role,status,attempt,started) VALUES(?,?,?,'running',?,?)",
                        (step_id, self.run_id, role, self.attempt, started_at),
                    )
        try:
            if anon.leaks(prompt):
                # Persist only a safe placeholder, never the refused payload.
                prompt = "[]"
                raise Blocked("Sensitive data detected by egress guard")
            if len(prompt.encode("utf-8")) > 262144:
                prompt = "[]"
                raise Blocked("Prompt exceeds bounded input budget")
            log.info(
                "llm.started",
                extra={"case_id": cid, "details": {"agent": role, "mode": self.settings.llm_mode}},
            )
            provider: Provider = (
                MockProvider()
                if self.settings.llm_mode == "mock"
                else OpenAICompatibleProvider(self.settings, self.post)
            )
            body = provider.complete(messages, role=role, evidence_ids=evidence_ids)
            if isinstance(body.get("model"), str):
                actual_model, model_source = body["model"], "provider_response"
            raw_usage = body.get("usage") or {}
            usage = {
                k: v
                for k, v in raw_usage.items()
                if k in {"prompt_tokens", "completion_tokens", "total_tokens"}
                and isinstance(v, int)
                and not isinstance(v, bool)
                and v >= 0
            }
            response = body["choices"][0]["message"]["content"]
            result = json.loads(response)
            if not isinstance(result, dict):
                raise ValueError("Expected a JSON object")
            (Verdict if role == "judge" else Finding).model_validate(result)
            return result
        except Exception as exc:
            # Do not copy exception text: it may contain URLs, credentials or raw data.
            error = (
                "ProviderHTTP" + str(exc.response.status_code)
                if isinstance(exc, httpx.HTTPStatusError)
                else type(exc).__name__
            )
            log.exception(
                "llm.blocked" if isinstance(exc, Blocked) else "llm.failed",
                extra={"case_id": cid, "details": {"agent": role}},
            )
            raise
        finally:
            with self.store.connect() as db:
                db.execute(
                    """INSERT INTO ledger(ts,case_id,agent,mode,prompt,response,evidence,usage,
                           duration_ms,error,run_id,step_id,provider,model,prompt_version,attempt,model_source,parameters) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
                    (
                        started_at,
                        cid,
                        role,
                        self.settings.llm_mode,
                        prompt,
                        response,
                        json.dumps([] if error == "Blocked" else evidence_ids),
                        json.dumps(usage),
                        (time.monotonic() - start) * 1000,
                        error,
                        self.run_id,
                        step_id,
                        "mock" if self.settings.llm_mode == "mock" else "openai-compatible",
                        actual_model,
                        "net-host-judge-v2",
                        self.attempt,
                        model_source,
                        json.dumps({"temperature": 0, "max_tokens": 2048, "max_prompt_bytes": 262144}),
                    ),
                )
                if self.run_id:
                    db.execute(
                        "UPDATE steps SET status=?,finished=?,error=? WHERE id=?",
                        ("failed" if error else "completed", time.time(), error, step_id),
                    )
            log.info(
                "llm.finished",
                extra={
                    "case_id": cid,
                    "details": {
                        "agent": role,
                        "mode": self.settings.llm_mode,
                        "error_type": error,
                        "duration_ms": round((time.monotonic() - start) * 1000, 2),
                        "usage": usage,
                    },
                },
            )
