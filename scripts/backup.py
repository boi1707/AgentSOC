"""Create a consistent SQLite backup including committed WAL content."""

import argparse
import sqlite3
from contextlib import closing
from pathlib import Path


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--db", default="data/agentsoc.db")
    parser.add_argument("--output", required=True)
    args = parser.parse_args()
    output = Path(args.output)
    if output.exists():
        parser.error("Backup output already exists; choose a new filename")
    output.parent.mkdir(parents=True, exist_ok=True)
    try:
        with closing(sqlite3.connect(Path(args.db).resolve().as_uri() + "?mode=ro", uri=True)) as source:
            with closing(sqlite3.connect(output)) as target:
                source.backup(target)
        output.chmod(0o600)
    except (sqlite3.Error, OSError):
        parser.exit(1, "Backup failed; check source database and output permissions.\n")
    print("Consistent backup created. Keep it outside Git and protect access.")


if __name__ == "__main__":
    main()
