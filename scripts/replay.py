"""Replay JSONL through an offline mock pipeline, or send alerts to a running API."""

import argparse
import json
import math
import os
import tempfile
import time
import uuid
from datetime import datetime
from pathlib import Path

import httpx
from dotenv import load_dotenv

from src.service import Service
from src.settings import Settings


def load_alerts(path):
    text = Path(path).read_text(encoding="utf-8-sig")
    try:
        parsed = json.loads(text)
        alerts = parsed if isinstance(parsed, list) else [parsed]
    except json.JSONDecodeError:
        alerts = [json.loads(line) for line in text.splitlines() if line.strip()]
    if not alerts or any(not isinstance(a, dict) or not a.get("id") for a in alerts):
        raise ValueError("Expected Wazuh alert objects with IDs (JSON or JSONL)")
    return alerts


def delays(alerts, speed):
    if not math.isfinite(speed) or speed < 0:
        raise ValueError("Speed must be finite and nonnegative; 0 means immediate")
    previous = None
    for alert in alerts:
        if not speed:
            yield 0.0
            continue
        stamp = datetime.fromisoformat(alert["timestamp"].replace("Z", "+00:00"))
        if stamp.tzinfo is None:
            raise ValueError("Timestamp requires timezone for timed replay")
        current = stamp.timestamp()
        if previous is not None and current < previous:
            raise ValueError("Timed replay requires chronological alerts")
        yield 0.0 if previous is None else (current - previous) / speed
        previous = current


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("file", nargs="?", default="datasets/demo.jsonl")
    parser.add_argument("--url", help="Send to API URL instead of offline replay")
    parser.add_argument("--fresh", action="store_true", help="Assign new IDs for a new API demo run")
    parser.add_argument(
        "--speed", type=float, default=0, help="0: immediate; 1: real time; 10: ten times faster"
    )
    args = parser.parse_args()
    try:
        alerts = load_alerts(args.file)
        waits = list(delays(alerts, args.speed))
    except (OSError, ValueError, KeyError, TypeError) as exc:
        parser.exit(2, f"Invalid replay file or timing ({type(exc).__name__}); check IDs and timestamps.\n")
    if args.url:
        load_dotenv()
        key = os.environ["INGEST_KEY"]
        if Path(args.file).resolve() == Path("datasets/demo.jsonl").resolve():
            health = httpx.get(args.url.rstrip("/") + "/health", timeout=5)
            health.raise_for_status()
            if not health.json().get("demo"):
                parser.error("Synthetic demo fixtures require a separate DEMO_MODE=1 service/database")
        for alert, delay in zip(alerts, waits):
            if delay:
                time.sleep(delay)
            if args.fresh:
                alert["id"] = uuid.uuid4().hex
            r = httpx.post(
                args.url.rstrip("/") + "/ingest",
                json=alert,
                headers={"Authorization": "Bearer " + key},
                timeout=10,
            )
            r.raise_for_status()
            print(r.json())
        return
    with tempfile.TemporaryDirectory(prefix="agentsoc-replay-") as folder:
        settings = Settings(db=str(Path(folder) / "demo.db"))
        service = Service(settings)
        now = time.time()
        clock = now
        for alert, delay in zip(alerts, waits):
            clock += delay
            service.store.ingest(alert, clock, synthetic=True)
        service.tick(clock + settings.quiet)
        for case in service.store.cases():
            print(
                json.dumps(
                    {"id": case["id"], "status": case["status"], "verdict": case["verdict"]},
                    ensure_ascii=False,
                    indent=2,
                )
            )
        with service.store.connect() as db:
            prompts = [r[0] for r in db.execute("SELECT prompt FROM ledger")]
        print(f"Offline mock: {len(alerts)} alerts, {len(prompts)} ledger calls. No cloud or SSH calls.")


if __name__ == "__main__":
    main()
