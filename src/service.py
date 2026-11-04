import json
import logging
import threading

import httpx

from .agents import analyze
from .anon import Anon
from .incident import Grouper
from .llm import LLM
from .storage import Store

log = logging.getLogger("agentsoc.service")


class Service:
    def __init__(self, settings):
        self.settings = settings
        self.store = Store(settings.db)
        self.llm = LLM(settings, self.store)
        self.lock = threading.Lock()

    def tick(self, now=None):
        # A single worker per database; the SQLite inbox survives process restarts.
        with self.lock:
            group = Grouper(
                gap=self.settings.gap,
                quiet=self.settings.quiet,
                host_ips=self.settings.host_ips,
                hi=self.settings.hi_level,
                cap=self.settings.cap,
            )
            for row in self.store.pending_alerts():
                group.add(json.loads(row["alert"]), row["received"])
            for incident in group.ready(now):
                cid = self.store.enqueue(incident)
                log.info(
                    "incident.created",
                    extra={
                        "case_id": cid,
                        "details": {
                            "alert_count": len(incident["raw_ids"]),
                            "ip_count": len(incident["ips"]),
                            "dropped_rows": incident["dropped_rows"],
                        },
                    },
                )
            with self.store.connect() as db:
                queued = [r[0] for r in db.execute("SELECT id FROM cases WHERE status='queued'")]
            for cid in queued:
                self.handle(cid)

    def handle(self, cid):
        case = self.store.get(cid)
        anon = Anon(self.settings.hosts)
        try:
            verdict = analyze(case["incident"], anon, cid, self.llm, self.settings.confidence)
        except Exception as exc:
            log.exception("analysis.failed", extra={"case_id": cid})
            verdict = {
                "verdict": "review",
                "confidence": 0,
                "block_ip": None,
                "evidence_ids": [],
                "grounded": 0,
                "mode": self.settings.llm_mode,
                "reason": "Analysis unavailable: " + type(exc).__name__,
            }
        self.store.finish(cid, verdict, anon.rev)
        log.info(
            "case.created",
            extra={
                "case_id": cid,
                "details": {
                    "verdict": verdict["verdict"],
                    "confidence": verdict["confidence"],
                    "mode": self.settings.llm_mode,
                },
            },
        )
        if self.settings.tg_token and self.settings.tg_chat:
            try:
                httpx.post(
                    "https://api.telegram.org/bot" + self.settings.tg_token + "/sendMessage",
                    timeout=10,
                    json={
                        "chat_id": self.settings.tg_chat,
                        "text": f"AgentSOC case {cid}: {verdict['verdict']}",
                    },
                ).raise_for_status()
                log.info("telegram.sent", extra={"case_id": cid})
            except Exception:
                log.exception("telegram.failed", extra={"case_id": cid})
