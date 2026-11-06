"""Run the built same-origin console, API and a separate worker locally."""

import argparse
import os
import secrets
import subprocess
import sys
import time
from pathlib import Path

from dotenv import dotenv_values, set_key


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--demo", action="store_true", help="Separate synthetic database, mock and dry-run only"
    )
    parser.add_argument("--port", type=int)
    parser.add_argument("--build", action="store_true")
    args = parser.parse_args()
    root = Path(__file__).resolve().parent.parent
    os.chdir(root)
    env_file = root / ".env"
    if not env_file.exists():
        env_file.write_text((root / ".env.example").read_text(encoding="utf-8"), encoding="utf-8")
    values = dotenv_values(env_file)
    for name in ("INGEST_KEY", "APPROVE_KEY"):
        if not values.get(name):
            set_key(env_file, name, secrets.token_urlsafe(32))
    if args.build or not (root / "frontend/dist/index.html").exists():
        npm = "npm.cmd" if os.name == "nt" else "npm"
        if not (root / "frontend/node_modules").exists():
            subprocess.run([npm, "ci"], cwd=root / "frontend", check=True)
        subprocess.run([npm, "run", "build"], cwd=root / "frontend", check=True)
    env = {**os.environ, "EMBEDDED_WORKER": "0"}
    if args.demo:
        env.update(
            DEMO_MODE="1",
            DEMO_DB="data/demo/agentsoc.db",
            LLM_MODE="mock",
            RESPONSE_MODE="dry-run",
            TG_TOKEN="",
            TG_CHAT="",
        )
    port = args.port or (8001 if args.demo else 8000)
    processes = [
        subprocess.Popen(
            [
                sys.executable,
                "-m",
                "uvicorn",
                "src.api.main:app",
                "--host",
                "127.0.0.1",
                "--port",
                str(port),
                "--no-access-log",
            ],
            env=env,
        ),
        subprocess.Popen([sys.executable, "-m", "src.worker"], env=env),
    ]
    print(f"AgentSOC console: http://127.0.0.1:{port}/console", flush=True)
    print(
        "Sign in with ADMIN_USERNAME (default admin) and ADMIN_PASSWORD or APPROVE_KEY from .env.", flush=True
    )
    try:
        while all(p.poll() is None for p in processes):
            time.sleep(0.5)
    except KeyboardInterrupt:
        pass
    finally:
        for process in processes:
            if process.poll() is None:
                process.terminate()
        for process in processes:
            try:
                process.wait(timeout=15)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait()


if __name__ == "__main__":
    main()
