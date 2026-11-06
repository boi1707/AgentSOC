import asyncio
import html
import json
import logging
import secrets
import subprocess
from contextlib import asynccontextmanager

from fastapi import Depends, FastAPI, HTTPException, Request
from fastapi.exceptions import RequestValidationError, ResponseValidationError
from fastapi.responses import HTMLResponse
from fastapi.security import HTTPBasic, HTTPBasicCredentials, HTTPBearer

from src import auth, response
from src.adapters.wazuh import WazuhAlert
from src.anon import Anon
from src.api.v1 import health_snapshot, scrub
from src.api.v1 import router as v1_router
from src.incident import Grouper, norm
from src.logs import configure_logging
from src.service import Service
from src.settings import Settings

log = logging.getLogger("agentsoc.api")


def create_app(settings=None, *, worker=None):
    config = settings or Settings.from_env()
    worker = config.embedded_worker if worker is None else worker
    basic, bearer = HTTPBasic(auto_error=False), HTTPBearer(auto_error=False)

    @asynccontextmanager
    async def lifespan(app):
        config.validate()
        configure_logging(config)
        service = Service(config)
        service.store.recover(stale_only=True)
        app.state.service = service
        app.state.settings = config
        auth.bootstrap(service.store, config)
        log.info(
            "service.started",
            extra={
                "details": {
                    "llm_mode": config.llm_mode,
                    "response_mode": config.response_mode,
                    "quiet_seconds": config.quiet,
                    "gap_seconds": config.gap,
                    "cap": config.cap,
                    "hi_level": config.hi_level,
                }
            },
        )
        stop = asyncio.Event()

        async def run():
            while not stop.is_set():
                try:
                    await asyncio.to_thread(service.tick)
                except Exception:
                    log.exception("worker.failed")
                try:
                    await asyncio.wait_for(stop.wait(), timeout=config.poll)
                except TimeoutError:
                    pass

        task = asyncio.create_task(run()) if worker else None
        try:
            yield
        finally:
            stop.set()
            if task:
                await task
            log.info("service.stopped")

    app = FastAPI(title="AgentSOC", version="0.1.0", lifespan=lifespan)
    app.include_router(v1_router)

    @app.get("/live")
    def live():
        return {"status": "alive"}

    @app.get("/ready")
    def ready(request: Request):
        from fastapi.responses import JSONResponse

        health = health_snapshot(request.app.state.service.store, config)
        ok = health["worker_fresh"]
        return JSONResponse(
            {"status": "ready" if ok else "degraded", "database": "ready", "worker_fresh": ok},
            status_code=200 if ok else 503,
        )

    @app.exception_handler(RequestValidationError)
    async def validation_error(request, exc):
        from fastapi.responses import JSONResponse

        malformed_json = any(error["type"] == "json_invalid" for error in exc.errors())
        fields = [{"location": list(error["loc"]), "type": error["type"]} for error in exc.errors()]
        # Do not echo raw rejected input or credentials back to clients.
        message = "Invalid JSON" if malformed_json else "Invalid request"
        return JSONResponse(
            {"error": {"code": 400 if malformed_json else 422, "message": message, "fields": fields}}
            if request.url.path.startswith("/api/v1/")
            else {"detail": message, "fields": fields},
            status_code=400 if malformed_json else 422,
        )

    @app.exception_handler(ResponseValidationError)
    async def invalid_stored_response(request, exc):
        from fastapi.responses import JSONResponse

        log.error("response.schema_error")
        return JSONResponse(
            {"error": {"code": 500, "message": "Stored data does not match the API contract"}},
            status_code=500,
        )

    import sqlite3

    from starlette.exceptions import HTTPException as StarletteHTTPException

    @app.exception_handler(StarletteHTTPException)
    async def http_error(request, exc):
        from fastapi.responses import JSONResponse

        body = (
            {"error": {"code": exc.status_code, "message": str(exc.detail)}}
            if request.url.path.startswith("/api/v1/")
            else {"detail": exc.detail}
        )
        return JSONResponse(body, status_code=exc.status_code, headers=exc.headers)

    @app.exception_handler(sqlite3.Error)
    async def database_error(request, exc):
        from fastapi.responses import JSONResponse

        log.error("database.unavailable", extra={"details": {"error_type": type(exc).__name__}})
        return JSONResponse({"error": {"code": 503, "message": "Database unavailable"}}, status_code=503)

    @app.middleware("http")
    async def security_headers(request, call_next):
        if request.url.path == "/ingest" or (
            request.url.path.startswith("/api/v1/") and request.method in {"POST", "PATCH", "PUT"}
        ):
            size = 0
            # Bound chunked bodies too; do not trust Content-Length.
            async for chunk in request.stream():
                size += len(chunk)
                if size > 262144:
                    from fastapi.responses import JSONResponse

                    return JSONResponse({"detail": "Alert exceeds 256 KiB"}, status_code=413)
                request.state.body = getattr(request.state, "body", b"") + chunk
            request._body = getattr(request.state, "body", b"")
        result = await call_next(request)
        result.headers["Cache-Control"] = "no-store"
        result.headers["X-Content-Type-Options"] = "nosniff"
        result.headers["Referrer-Policy"] = "no-referrer"
        result.headers["Content-Security-Policy"] = (
            "default-src 'none'; style-src 'self' 'unsafe-inline'; script-src 'self'; connect-src 'self'; "
            "frame-ancestors 'none'; base-uri 'none'; form-action 'self'"
        )
        return result

    def reviewer(credentials: HTTPBasicCredentials | None = Depends(basic)):
        if not credentials or not (
            secrets.compare_digest(credentials.username.encode(), b"reviewer")
            and secrets.compare_digest(credentials.password.encode(), config.approve_key.encode())
        ):
            raise HTTPException(401, "Reviewer login required", headers={"WWW-Authenticate": "Basic"})

    def ingestion(credentials=Depends(bearer)):
        if not credentials or not secrets.compare_digest(
            credentials.credentials.encode(), config.ingest_key.encode()
        ):
            raise HTTPException(401, "Invalid ingestion token")

    @app.get("/health")
    def health(request: Request):
        with request.app.state.service.store.connect() as db:
            db.execute("SELECT 1").fetchone()
            count = db.execute("SELECT count(*) FROM cases").fetchone()[0]
            queued = db.execute("SELECT count(*) FROM cases WHERE status='queued'").fetchone()[0]
            pending_rows = db.execute(
                "SELECT alert,received FROM inbox WHERE case_id IS NULL AND correlation_status='pending' ORDER BY received,rowid"
            ).fetchall()
            last = db.execute("SELECT max(received) FROM inbox").fetchone()[0]
        group = Grouper(
            gap=config.gap, quiet=config.quiet, hi=config.hi_level, cap=config.cap, host_ips=config.host_ips
        )
        for row in pending_rows:
            group.add(json.loads(row["alert"]), row["received"])
        return {
            "status": "ok",
            "llm_mode": config.llm_mode,
            "response_mode": config.response_mode,
            "llm_configured": bool(config.llm_url and config.llm_key and config.llm_model),
            "case_count": count,
            "pending_incidents": queued + len(group.inc),
            "unprocessed_alerts": len(pending_rows),
            "last_alert_at": last,
            "demo": config.demo,
        }

    @app.get("/metrics", dependencies=[Depends(reviewer)])
    def metrics(request: Request):
        return request.app.state.service.store.metrics()

    @app.post("/ingest", dependencies=[Depends(ingestion)], status_code=202)
    def ingest(alert: WazuhAlert, request: Request):
        data = alert.model_dump(exclude_unset=True)
        try:
            row, ips = norm(data, config.host_ips)
            level = int(data["rule"].get("level", 0))
            if not 0 <= level <= 15:
                raise ValueError()
        except (ValueError, TypeError, AttributeError, KeyError):
            raise HTTPException(422, "Malformed Wazuh alert") from None
        if level < 7:
            return {"accepted": False, "reason": "below_level_7"}
        accepted = request.app.state.service.store.ingest(
            data, host_ips=config.host_ips, synthetic=config.demo, source=config.wazuh_source
        )
        log.info(
            "alert.received",
            extra={
                "details": {
                    "accepted": accepted,
                    "alert_id": data["id"],
                    "rule_id": row["rule"],
                    "rule_level": level,
                    "kind": row["kind"],
                }
            },
        )
        return {
            "accepted": accepted,
            "id": data["id"],
            "source": config.wazuh_source,
            "synthetic": config.demo,
        }

    def public_case(case):
        anon = Anon(config.hosts)
        anon.rev = case["restore"]
        result = {k: v for k, v in case.items() if k != "restore"}

        def restore(value):
            if isinstance(value, str):
                return anon.restore(value)
            if isinstance(value, list):
                return [restore(v) for v in value]
            if isinstance(value, dict):
                return {k: restore(v) for k, v in value.items()}
            return value

        result["verdict"] = restore(result["verdict"])
        try:
            response.candidate(case, config)
            result["can_approve"] = case["status"] == "pending"
        except ValueError:
            result["can_approve"] = False
        return scrub(result, config)

    @app.get("/api/cases", dependencies=[Depends(reviewer)])
    def list_cases(request: Request):
        return [public_case(c) for c in request.app.state.service.store.cases()]

    @app.get("/cases", dependencies=[Depends(reviewer)], response_class=HTMLResponse)
    def cases(request: Request):
        out = [
            "<!doctype html><html lang='vi'><meta charset='utf-8'><meta name='viewport' "
            "content='width=device-width'><title>AgentSOC review</title><style>"
            "body{max-width:1000px;margin:3rem auto;padding:1rem;font:16px system-ui;background:#101923;"
            "color:#e5edf5}article{border:1px solid #425466;padding:1.4rem;margin:1rem 0}"
            "pre{white-space:pre-wrap;overflow-wrap:anywhere}button{padding:.7rem;margin:.3rem}"
            "small{color:#94b8c6}</style><h1>AgentSOC · Case review</h1>",
            f"<p>LLM: {html.escape(config.llm_mode)} · Response: {html.escape(config.response_mode)}</p>",
            "<p>Chỉ hành động sau khi người duyệt xác nhận. Mock là dữ liệu mô phỏng.</p>",
        ]
        for case in request.app.state.service.store.cases():
            view = public_case(case)

            def esc(x):
                return html.escape(str(x))

            out.append(
                f"<article><h2>{esc(case['id'])}</h2><p>{esc(case['status'])}</p>"
                f"<pre>{esc(json.dumps(view['verdict'], ensure_ascii=False, indent=2))}</pre>"
                f"<details><summary>Bằng chứng</summary><pre>"
                f"{esc(json.dumps(case['incident'], ensure_ascii=False, indent=2))}</pre></details>"
            )
            if case["status"] == "pending":
                if view["can_approve"]:
                    out.append(
                        f"<button data-id='{case['id']}' data-action='approve'>Approve · "
                        f"{esc(config.response_mode)}</button>"
                    )
                out.append(f"<button data-id='{case['id']}' data-action='reject'>Reject</button>")
            out.append("</article>")
        out.append("<script src='/review.js'></script></html>")
        return "".join(out)

    @app.get("/review.js", dependencies=[Depends(reviewer)])
    def javascript():
        from fastapi.responses import Response

        return Response(
            """document.querySelectorAll('button[data-id]').forEach(b=>b.onclick=async()=>{
          if(!confirm(b.dataset.action+' this case?'))return;
          b.disabled=true;
          try{const r=await fetch('/'+b.dataset.action+'/'+b.dataset.id,{method:'POST',
            headers:{'X-AgentSOC-Review':'1'}});
            if(!r.ok)throw new Error(await r.text());location.reload();
          }catch(e){alert(e.message);b.disabled=false;}
        });""",
            media_type="application/javascript",
        )

    @app.post("/{action}/{cid}", dependencies=[Depends(reviewer)])
    def review(action: str, cid: str, request: Request):
        if action not in {"approve", "reject"}:
            raise HTTPException(404)
        # A custom header disallows cross-site HTML form submissions; no CORS is enabled.
        if request.headers.get("X-AgentSOC-Review") != "1":
            raise HTTPException(403, "Review header required")
        if request.headers.get("sec-fetch-site") == "cross-site":
            raise HTTPException(403)
        store = request.app.state.service.store
        case = store.get(cid)
        if not case:
            raise HTTPException(404)
        if case["status"] != "pending":
            raise HTTPException(409, "Case is no longer pending")
        ip = None
        if action == "approve":
            try:
                ip = response.candidate(case, config)
            except ValueError as exc:
                raise HTTPException(400, str(exc)) from None
        if not store.claim(cid, actor="legacy-reviewer", mode=config.response_mode, action=action, ip=ip):
            raise HTTPException(409, "Case is no longer pending")
        status = "rejected"
        if action == "approve":
            try:
                status = response.execute(ip, config)
            except (OSError, TimeoutError, subprocess.TimeoutExpired):
                status = "action_unknown"
        store.record_action(cid, action, ip, config.response_mode, status)
        log.info(
            "review.completed",
            extra={
                "case_id": cid,
                "details": {
                    "action": action,
                    "mode": config.response_mode,
                    "status": status,
                    "reviewer": "reviewer",
                },
            },
        )
        return {"id": cid, "status": status}

    from pathlib import Path

    from fastapi.responses import FileResponse, RedirectResponse
    from fastapi.staticfiles import StaticFiles

    dist = Path(__file__).resolve().parents[2] / "frontend" / "dist"
    if (dist / "assets").is_dir():
        app.mount("/assets", StaticFiles(directory=dist / "assets"), name="console-assets")

    @app.get("/")
    def root():
        return RedirectResponse("/console")

    @app.get("/THIRD_PARTY_NOTICES.txt")
    def notices():
        if not (dist / "THIRD_PARTY_NOTICES.txt").is_file():
            raise HTTPException(404)
        return FileResponse(dist / "THIRD_PARTY_NOTICES.txt", media_type="text/plain")

    @app.get("/console")
    @app.get("/console/{path:path}")
    def console(path: str = ""):
        if not (dist / "index.html").is_file():
            raise HTTPException(
                503, "Console not built. Run npm ci && npm run build in frontend, or use npm run dev."
            )
        return FileResponse(dist / "index.html")

    return app


app = create_app()
