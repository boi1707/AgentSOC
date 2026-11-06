"""Separate durable worker: python -m src.worker. API has no worker by default."""

import logging
import signal
import sqlite3
import sys
import threading
import time
from pathlib import Path

from .logs import configure_logging
from .service import Service
from .settings import Settings


def main():
    settings = Settings.from_env()
    settings.validate()
    settings.log_component = "worker"
    configure_logging(settings)
    service = Service(settings)
    stop = threading.Event()
    for signum in (signal.SIGINT, signal.SIGTERM):
        signal.signal(signum, lambda *_: stop.set())
    while not stop.is_set():
        try:
            service.tick()
        except Exception:
            logging.getLogger("agentsoc.worker").exception("worker.cycle_failed")
        stop.wait(settings.poll)


if __name__ == "__main__":
    if "--health" in sys.argv:
        try:
            db = sqlite3.connect(Path(Settings.from_env().db).resolve().as_uri() + "?mode=ro", uri=True)
            latest = db.execute("SELECT max(last_seen) FROM workers").fetchone()[0]
            db.close()
            raise SystemExit(0 if latest and time.time() - latest < 30 else 1)
        except (sqlite3.Error, OSError):
            raise SystemExit(1) from None
    else:
        main()
