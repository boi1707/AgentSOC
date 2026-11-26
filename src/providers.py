"""Provider boundary: transport configuration is server-owned; no runtime fallback to mock."""

import asyncio
import json
from typing import Protocol

import httpx


class Provider(Protocol):
    def complete(self, messages: list[dict], *, role: str, evidence_ids: list[str]) -> dict: ...


class MockProvider:
    def complete(self, messages, *, role, evidence_ids):
        data = json.loads(messages[1]["content"])
        if role == "judge":
            net, host = data["net"], data["host"]
            attack = bool(net.get("suspicious") and host.get("suspicious"))
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
        return {"choices": [{"message": {"content": json.dumps(result)}}]}


class OpenAICompatibleProvider:
    def __init__(self, settings, post):
        self.settings, self.post = settings, post

    def request_payload(self, messages, *, role):
        return {
            "model": self.settings.llm_model,
            "temperature": 0,
            "max_tokens": 1024 if role == "assistant" else 2048,
            "response_format": {"type": "json_object"},
            "messages": messages,
        }

    def complete(self, messages, *, role, evidence_ids):
        response = self.post(
            self.settings.llm_url,
            timeout=30,
            follow_redirects=False,
            headers={"Authorization": "Bearer " + self.settings.llm_key},
            json=self.request_payload(messages, role=role),
        )
        response.raise_for_status()
        return response.json()

    async def bounded_complete(self, messages, *, role, timeout):
        """Assistant-only wall-clock deadline and response cap; no background retry."""
        async with asyncio.timeout(timeout):
            async with httpx.AsyncClient(follow_redirects=False, timeout=timeout) as client:
                async with client.stream(
                    "POST",
                    self.settings.llm_url,
                    headers={"Authorization": "Bearer " + self.settings.llm_key},
                    json=self.request_payload(messages, role=role),
                ) as response:
                    response.raise_for_status()
                    data = bytearray()
                    async for chunk in response.aiter_bytes():
                        data.extend(chunk)
                        if len(data) > 65536:
                            raise ValueError("Provider response exceeds budget")
                    return json.loads(data)
