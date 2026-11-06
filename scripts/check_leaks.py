"""Exit 1 if ledger prompts contain sensitive patterns; never print their values."""

import argparse
import json
import sqlite3

from scripts.audit import read_database
from src.anon import Anon
from src.settings import Settings


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--db", default=Settings.from_env().db)
    args = parser.parse_args()
    try:
        _, _, ledger = read_database(args.db)
        anon = Anon(Settings.from_env().hosts)
        count = sum(bool(anon.leaks(row["prompt"])) for row in ledger)
    except (OSError, ValueError, sqlite3.Error) as exc:
        parser.exit(2, f"Cannot inspect database ({type(exc).__name__}); no database was created.\n")
    print(json.dumps({"prompts_checked": len(ledger), "prompts_with_sensitive_patterns": count}))
    return 1 if count else 0


if __name__ == "__main__":
    raise SystemExit(main())
