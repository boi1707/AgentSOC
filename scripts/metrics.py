"""Read a local database; print audit and consolidation metrics, not invented accuracy."""

import argparse
import json
import statistics

from src.anon import Anon
from src.storage import Store


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--db", default="data/agentsoc.db")
    args = parser.parse_args()
    store = Store(args.db)
    with store.connect() as db:
        alerts = db.execute("SELECT count(*) FROM inbox").fetchone()[0]
        cases = db.execute("SELECT count(*) FROM cases").fetchone()[0]
        calls = db.execute("SELECT * FROM ledger").fetchall()
    tokens = sum(json.loads(c["usage"]).get("total_tokens", 0) for c in calls)
    output = {
        "alerts": alerts,
        "cases": cases,
        "consolidation_ratio": 1 - cases / alerts if alerts else None,
        "ledger_calls": len(calls),
        "guard_pattern_matches": sum(bool(Anon().leaks(c["prompt"])) for c in calls),
        "total_tokens": tokens,
        "mean_call_ms": statistics.mean(c["duration_ms"] for c in calls) if calls else None,
        "precision": None,
        "recall": None,
        "note": "Precision/recall require labeled ground truth; consolidation is not false-positive reduction.",
    }
    print(json.dumps(output, indent=2))


if __name__ == "__main__":
    main()
