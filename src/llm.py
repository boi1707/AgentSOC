import json
import time

import httpx


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
        if anon.leaks(prompt):
            raise Blocked("Sensitive data detected by egress guard")
        start = time.monotonic()
        response, usage, error = None, {}, None
        try:
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
                usage = body.get("usage", {})
                response = body["choices"][0]["message"]["content"]
                result = json.loads(response)
            if not isinstance(result, dict):
                raise ValueError("Expected a JSON object")
            return result
        except Exception as exc:
            # Do not copy exception text: it may contain URLs, credentials or raw data.
            error = type(exc).__name__
            raise
        finally:
            with self.store.connect() as db:
                db.execute(
                    """INSERT INTO ledger(ts,case_id,agent,mode,prompt,response,evidence,usage,
                           duration_ms,error) VALUES(?,?,?,?,?,?,?,?,?,?)""",
                    (
                        time.time(),
                        cid,
                        role,
                        self.settings.llm_mode,
                        prompt,
                        response,
                        json.dumps(evidence_ids),
                        json.dumps(usage),
                        (time.monotonic() - start) * 1000,
                        error,
                    ),
                )
