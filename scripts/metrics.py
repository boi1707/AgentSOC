"""Read a local database; print audit and consolidation metrics, not invented accuracy."""

import argparse
import json
import math
import sqlite3

from scripts.audit import load_labels, report
from src.settings import Settings


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--db", default="data/agentsoc.db")
    parser.add_argument("--ground-truth", help="CSV with alert_id,label (attack or benign)")
    parser.add_argument("--include-mock", action="store_true", help="Include simulated cases, explicitly")
    parser.add_argument("--input-usd-per-million", type=float)
    parser.add_argument("--output-usd-per-million", type=float)
    args = parser.parse_args()
    if any(
        v is not None and (v < 0 or not math.isfinite(v))
        for v in (
            args.input_usd_per_million,
            args.output_usd_per_million,
        )
    ):
        parser.error("Token prices must be finite, nonnegative numbers")
    try:
        output = report(
            args.db,
            labels=load_labels(args.ground_truth) if args.ground_truth else None,
            include_mock=args.include_mock,
            input_price=args.input_usd_per_million,
            output_price=args.output_usd_per_million,
            hosts=Settings.from_env().hosts,
        )
    except (OSError, ValueError, sqlite3.Error) as exc:
        parser.exit(2, f"Cannot read evaluation inputs ({type(exc).__name__}). Check paths and CSV format.\n")
    print(json.dumps(output, indent=2))


if __name__ == "__main__":
    main()
