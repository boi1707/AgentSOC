"""Disposable browser-test server. No seeded outcomes and no external integrations."""

import os
import subprocess
import sys
import tempfile
from pathlib import Path


def main():
    with tempfile.TemporaryDirectory(prefix="agentsoc-browser-") as folder:
        os.environ.update(
            INGEST_KEY="e2e-ingest-fixture-not-a-live-secret",
            APPROVE_KEY="e2e-review-fixture-not-a-live-secret",
            ADMIN_USERNAME="admin",
            ADMIN_PASSWORD="",
            DEMO_MODE="1",
            DEMO_DB=str(Path(folder) / "demo.db"),
            LLM_MODE="mock",
            RESPONSE_MODE="dry-run",
            TG_TOKEN="",
            TG_CHAT="",
            EMBEDDED_WORKER="0",
            POLL_SECONDS="0.05",
            SESSION_COOKIE_SECURE="0",
        )
        import uvicorn

        from src.api.main import create_app

        worker = subprocess.Popen([sys.executable, "-m", "src.worker"])
        try:
            uvicorn.run(create_app(worker=False), host="127.0.0.1", port=8765, access_log=False)
        finally:
            worker.terminate()
            worker.wait(timeout=10)


if __name__ == "__main__":
    main()
