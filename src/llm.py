import json
import logging
import time

import httpx

from .agents import Finding, Verdict

log = logging.getLogger("agentsoc.llm")


class Blocked(Exception):
    pass


class LLM:
    def __init__(self, settings, store, post=None):
        self.settings, self.store, self.post = settings, store, post or httpx.post

    def ask(self, anon, cid, role, system, payload, evidence_ids):
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
        try:
            if anon.leaks(prompt):
                # Persist only a safe placeholder, never the refused payload.
                prompt = "[]"
                raise Blocked("Sensitive data detected by egress guard")
            log.info(
                "llm.started",
                extra={"case_id": cid, "details": {"agent": role, "mode": self.settings.llm_mode}},
            )
            if self.settings.llm_mode == "mock":
                data = json.loads(messages[1]["content"])
                if role == "judge":
                    net, host = data["net"], data["host"]
                    attack = net.get("suspicious") and host.get("suspicious")
                    result = {
                        "verdict": "attack" if attack else "review",
                        "confidence": 0.95 if attack else 0.5,
                        "evidence_ids": data["ids"],
                        "mitre": [],
                        "reason": "MOCK fixture only; not a security assessment.",
                        "block_ip": net.get("candidate") if attack else None,
                    }
                else:
                    result = {
                        "finding": "MOCK fixture",
                        "evidence_ids": evidence_ids,
                        "suspicious": any(a.get("level", 0) >= 8 for a in data),
                        "candidate": next((a.get("src_ip") for a in data if a.get("src_ip")), None),
                    }
                response = json.dumps(result)
            else:
                r = self.post(
                    self.settings.llm_url,
                    timeout=30,
                    follow_redirects=False,
                    headers={"Authorization": "Bearer " + self.settings.llm_key},
                    json={
                        "model": self.settings.llm_model,
                        "temperature": 0,
                        "response_format": {"type": "json_object"},
                        "messages": messages,
                    },
                )
                r.raise_for_status()
                body = r.json()
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
            error = type(exc).__name__
            log.exception(
                "llm.blocked" if isinstance(exc, Blocked) else "llm.failed",
                extra={"case_id": cid, "details": {"agent": role}},
            )
            raise
        finally:
            with self.store.connect() as db:
                db.execute(
                    """INSERT INTO ledger(ts,case_id,agent,mode,prompt,response,evidence,usage,
                           duration_ms,error) VALUES(?,?,?,?,?,?,?,?,?,?)""",
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
                    ),
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
