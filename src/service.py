import json
import logging
import threading
import uuid

import httpx

from .agents import analyze
from .anon import Anon
from .incident import Grouper
from .llm import LLM
from .shuffle import deliver_pending
from .storage import Store
from .thehive import sync_pending
from .tools import ToolRequest
from .tools import execute as execute_tool
from .virustotal import enrich_pending

log = logging.getLogger("agentsoc.service")


class Service:
    def __init__(self, settings):
        self.settings = settings
        self.store = Store(settings.db, host_ips=settings.host_ips)
        self.llm = LLM(settings, self.store)
        self.owner = uuid.uuid4().hex
        self.lock = threading.Lock()

    def tick(self, now=None):
        with self.lock:
            self.store.recover(stale_only=True)
            self.store.heartbeat(self.owner)
            with self.store.connect() as db:
                db.execute("BEGIN IMMEDIATE")
                group = Grouper(
                    gap=self.settings.gap,
                    quiet=self.settings.quiet,
                    host_ips=self.settings.host_ips,
                    hi=self.settings.hi_level,
                    cap=self.settings.cap,
                )
                rows = db.execute(
                    "SELECT * FROM inbox WHERE case_id IS NULL AND correlation_status='pending' ORDER BY received,rowid"
                ).fetchall()
                for row in rows:
                    group.add(json.loads(row["alert"]), row["received"], json.loads(row["normalized"]))
                for incident in group.ready(now):
                    cid = self.store.enqueue(incident, db=db, settings=self.settings)
                    log.info(
                        "incident.created",
                        extra={
                            "case_id": cid,
                            "details": {
                                "alert_count": len(incident["raw_ids"]),
                                "dropped_rows": incident["dropped_rows"],
                            },
                        },
                    )
                for case in db.execute(
                    "SELECT * FROM cases WHERE status='queued' AND latest_run_id IS NULL"
                ).fetchall():
                    self.store.new_run(case["id"], db=db, settings=self.settings)
            for _ in range(20):
                job = self.store.claim_job(self.owner, lease=self.settings.lease_seconds)
                if not job:
                    break
                self.handle(job["case_id"], job=job)
            self.store.heartbeat(self.owner)

        # External I/O is outside the analysis transaction and never changes job success.
        if not self.settings.demo:
            for name, enabled, operation in (
                ("virustotal", self.settings.vt_key, enrich_pending),
                ("thehive", self.settings.thehive_url, sync_pending),
                ("shuffle", self.settings.shuffle_hook, deliver_pending),
            ):
                if enabled:
                    try:
                        operation(self.store, self.settings)
                    except Exception:
                        log.warning(name + ".cycle_failed")
                    finally:
                        self.store.heartbeat(self.owner)

    def handle(self, cid, job=None):
        if job is None:
            raise ValueError("Investigation requires a claimed durable job")
        run = self.store.get_run(job["run_id"])
        anon = Anon(
            self.settings.hosts,
            secrets=(
                self.settings.ingest_key,
                self.settings.approve_key,
                self.settings.llm_key,
                self.settings.admin_password,
                self.settings.tg_token,
                *self.settings.integration_secrets,
            ),
        )
        self.llm.run_id, self.llm.attempt = run["id"], job["attempts"]
        with self.store.connect() as db:
            db.execute(
                "UPDATE runs SET parameters=? WHERE id=?",
                (
                    json.dumps(
                        {
                            "temperature": 0,
                            "max_tokens": 2048,
                            "max_prompt_bytes": 262144,
                            "min_confidence": self.settings.confidence,
                            "evidence_cap": self.settings.cap,
                        }
                    ),
                    run["id"],
                ),
            )
            db.execute(
                "UPDATE runs SET provider=?,model=?,mode=? WHERE id=?",
                (
                    "mock" if self.settings.llm_mode == "mock" else "openai-compatible",
                    self.settings.llm_model or None,
                    self.settings.llm_mode,
                    run["id"],
                ),
            )
        stop = threading.Event()

        def maintain_lease():
            while not stop.wait(min(5, self.settings.lease_seconds / 3)):
                self.store.heartbeat(self.owner, job["id"], self.settings.lease_seconds)

        keeper = threading.Thread(target=maintain_lease, daemon=True)
        keeper.start()
        try:
            evidence = execute_tool(
                self.store,
                ToolRequest(name="incident_evidence", run_id=run["id"], limit=self.settings.cap),
                anon,
                incident_id=cid,
            )
            context = []
            entities = run["evidence"].get("entities", [])
            if entities:
                context.append(
                    execute_tool(
                        self.store,
                        ToolRequest(name="related_alerts", run_id=run["id"], entity=entities[0]),
                        anon,
                        incident_id=cid,
                    ).model_dump()
                )
            context.append(
                execute_tool(
                    self.store,
                    ToolRequest(name="previous_investigations", run_id=run["id"]),
                    anon,
                    incident_id=cid,
                ).model_dump()
            )
            verdict = analyze(
                {**run["evidence"], "alerts": evidence.items},
                anon,
                cid,
                self.llm,
                self.settings.confidence,
                context,
            )
            if self.store.complete_job(job, verdict, anon.rev):
                log.info(
                    "case.created",
                    extra={
                        "case_id": cid,
                        "details": {"verdict": verdict["verdict"], "mode": self.settings.llm_mode},
                    },
                )
                if not run["replay"] and not self.settings.demo:
                    self.notify(cid, verdict)
        except Exception as exc:
            retryable = isinstance(exc, (httpx.TimeoutException, httpx.NetworkError)) or (
                isinstance(exc, httpx.HTTPStatusError)
                and (exc.response.status_code == 429 or exc.response.status_code >= 500)
            )
            error_code = (
                "ProviderHTTP" + str(exc.response.status_code)
                if isinstance(exc, httpx.HTTPStatusError)
                else type(exc).__name__
            )
            self.store.fail_job(job, error_code, retryable)
            log.exception("analysis.failed", extra={"case_id": cid})
        finally:
            stop.set()
            keeper.join(timeout=2)
            self.llm.run_id = None

    def notify(self, cid, verdict):
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
