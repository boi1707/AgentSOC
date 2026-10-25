"""Replay JSONL through an offline mock pipeline, or send alerts to a running API."""

import argparse
import json
import os
import tempfile
import time
import uuid
from pathlib import Path

import httpx
from dotenv import load_dotenv

from src.service import Service
from src.settings import Settings


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("file", nargs="?", default="datasets/demo.jsonl")
    parser.add_argument("--url", help="Send to API URL instead of offline replay")
    parser.add_argument("--fresh", action="store_true", help="Assign new IDs for a new API demo run")
    args = parser.parse_args()
    alerts = [
        json.loads(line)
        for line in Path(args.file).read_text(encoding="utf-8-sig").splitlines()
        if line.strip()
    ]
    if args.url:
        load_dotenv()
        key = os.environ["INGEST_KEY"]
        for alert in alerts:
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
        for index, alert in enumerate(alerts):
            service.store.ingest(alert, now + index)
        service.tick(now + len(alerts) + settings.quiet)
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
