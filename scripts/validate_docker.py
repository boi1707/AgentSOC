"""Isolated image/runtime/rollback gate. Uses disposable fixtures only; never deploys.

Run on a Docker-equipped Linux host. No production env files or existing Compose projects are read.
"""

import argparse
import http.cookiejar
import json
import os
import secrets
import sqlite3
import subprocess
import tempfile
import time
import urllib.error
import urllib.request
from pathlib import Path

from scripts.migration_lab import assert_relationships, seed_v1, snapshot


def docker(*args):
    try:
        return subprocess.check_output(
            ["docker", *map(str, args)], stdin=subprocess.DEVNULL, text=True
        ).strip()
    except subprocess.CalledProcessError:
        # Never echo a command containing even disposable credential arguments into a CI traceback.
        raise RuntimeError("Docker validation command failed; inspect the isolated test step") from None


def wait_for(check, timeout=120):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        try:
            return check()
        except (AssertionError, urllib.error.URLError, ConnectionError):
            time.sleep(1)
    raise AssertionError("Container readiness deadline exceeded")


def run(image, previous_image, report_path):
    report = {"classification": "NOT RUN", "image": image, "previous_image": previous_image, "checks": {}}
    prefix = "agentsoc-lab-" + secrets.token_hex(5)
    containers, network = [], prefix + "-net"
    root = Path(__file__).resolve().parents[1]
    with tempfile.TemporaryDirectory(prefix="agentsoc-docker-lab-") as folder:
        lab = Path(folder)
        data = lab / "data"
        data.mkdir()
        db_path = data / "agentsoc.db"
        original = seed_v1(db_path)
        data.chmod(0o777)
        guard = lab / "bin"
        guard.mkdir()
        (guard / "ssh").write_text("#!/bin/sh\ntouch /app/data/ssh-executed\nexit 99\n", encoding="utf-8")
        (guard / "ssh").chmod(0o755)
        # The image runs as UID 10001. Change ownership only inside this newly-created test mount.
        docker(
            "run",
            "--rm",
            "--network",
            "none",
            "--user",
            "0",
            "-v",
            f"{data}:/app/data",
            image,
            "python",
            "-c",
            "import os; os.chown('/app/data/agentsoc.db',10001,10001)",
        )
        env = {
            "PYTHON_DOTENV_DISABLED": "1",
            "DB": "/app/data/agentsoc.db",
            "LLM_MODE": "mock",
            "RESPONSE_MODE": "dry-run",
            "EMBEDDED_WORKER": "0",
            "POLL_SECONDS": "0.1",
            "INGEST_KEY": secrets.token_urlsafe(32),
            "APPROVE_KEY": secrets.token_urlsafe(32),
            "TG_TOKEN": "",
            "TG_CHAT": "",
            "SHUFFLE_HOOK": "",
            "VT_KEY": "",
            "THEHIVE_URL": "",
            "THEHIVE_KEY": "",
            "ADMIN_PASSWORD": "",
            "SESSION_COOKIE_SECURE": "0",
            "PATH": "/validation/bin:/usr/local/bin:/usr/bin:/bin",
        }
        env_args = [item for key, value in env.items() for item in ("-e", f"{key}={value}")]
        try:
            env_path = lab / ".env"
            env_path.write_text(
                "\n".join(f"{key}={value}" for key, value in env.items()) + "\n", encoding="utf-8"
            )
            env_path.chmod(0o600)
            compose_path = lab / "docker-compose.yml"
            compose_path.write_text(
                (root / "docker-compose.yml").read_text(encoding="utf-8"), encoding="utf-8"
            )
            compose = subprocess.check_output(
                [
                    "docker",
                    "compose",
                    "--project-directory",
                    str(lab),
                    "--env-file",
                    str(env_path),
                    "-f",
                    str(compose_path),
                    "config",
                    "--format",
                    "json",
                ],
                env={**os.environ, "AGENTSOC_IMAGE": image, "BIND_IP": "127.0.0.1"},
                stdin=subprocess.DEVNULL,
                text=True,
            )
            services = json.loads(compose)["services"]
            for role in ("backend", "worker"):
                config = services["agentsoc-" + role]
                assert config["image"] == image
                assert config["environment"]["RESPONSE_MODE"] == "dry-run"
            report["checks"]["compose_configuration"] = "PASS"
            docker("network", "create", "--internal", network)
            version = docker(
                "run",
                "--rm",
                "--network",
                "none",
                image,
                "python",
                "-c",
                "import sys; assert sys.version_info[:2]==(3,12); print(sys.version.split()[0])",
            )
            report["checks"]["python"] = version
            for role in ("backend", "worker"):
                name = prefix + "-" + role
                containers.append(name)
                args = [
                    "run",
                    "-d",
                    "--name",
                    name,
                    "--network",
                    network,
                    "--cap-drop=ALL",
                    "--security-opt=no-new-privileges",
                    "--read-only",
                    "--tmpfs",
                    "/tmp",
                    "-v",
                    f"{data}:/app/data",
                    "-v",
                    f"{guard}:/validation/bin:ro",
                    *env_args,
                ]
                if role == "backend":
                    args += ["-p", "127.0.0.1::8000", image]
                else:
                    args += [
                        "--health-cmd",
                        "python -m src.worker --health",
                        "--health-interval",
                        "2s",
                        image,
                        "python",
                        "-m",
                        "src.worker",
                    ]
                docker(*args)
            backend, worker = containers
            ids = [docker("inspect", "--format", "{{.Image}}", name) for name in containers]
            assert ids[0] == ids[1]
            revision = docker(
                "image",
                "inspect",
                "--format",
                '{{index .Config.Labels "org.opencontainers.image.revision"}}',
                image,
            )
            assert revision and revision != "unknown"
            report["checks"]["shared_image_id"] = ids[0]
            report["checks"]["source_revision"] = revision
            port = docker("port", backend, "8000/tcp").split(":")[-1]
            base = f"http://127.0.0.1:{port}"
            opener = urllib.request.build_opener(
                urllib.request.ProxyHandler({}),
                urllib.request.HTTPCookieProcessor(http.cookiejar.CookieJar()),
            )
            csrf = ""

            def request(path, payload=None):
                headers = {"Content-Type": "application/json", "X-CSRF-Token": csrf}
                raw = json.dumps(payload).encode() if payload is not None else None
                with opener.open(
                    urllib.request.Request(base + path, data=raw, headers=headers), timeout=5
                ) as response:
                    return json.load(response)

            wait_for(lambda: request("/ready"))
            assert request("/live")["status"] == "alive"
            assert request("/health")["response_mode"] == "dry-run"
            docker("exec", worker, "python", "-m", "src.worker", "--health")
            wait_for(lambda: _healthy(backend, worker))
            csrf = request("/api/v1/auth/login", {"username": "admin", "password": "lab-review-" + "r" * 32})[
                "csrf"
            ]
            cases = request("/api/v1/incidents")["items"]
            assert len(cases) == 2
            pending = next(case for case in cases if case["status"] == "pending")
            assert request("/api/v1/assistant/query", {"message": "why", "incident_id": pending["id"]})[
                "citations"
            ]
            outcome = request(
                "/api/v1/incidents/" + pending["id"] + "/response",
                {"decision": "approve", "run_id": pending["latest_run_id"]},
            )
            assert outcome["status"] == "dry_run" and outcome["blocked"] is False
            assert outcome["verification_status"] == "not_verified"
            # Exercise ingestion and the independent worker with the supported synthetic dataset.
            for line in (root / "datasets/demo.jsonl").read_text(encoding="utf-8").splitlines():
                raw = json.dumps(json.loads(line)).encode()
                req = urllib.request.Request(
                    base + "/ingest",
                    data=raw,
                    headers={
                        "Content-Type": "application/json",
                        "Authorization": "Bearer " + env["INGEST_KEY"],
                    },
                )
                with opener.open(req, timeout=5) as response:
                    assert response.status == 202

            def processed():
                rows = request("/api/v1/incidents")["items"]
                assert len(rows) >= 3 and any(c["status"] == "pending" for c in rows)
                return True

            wait_for(processed)
            docker(
                "exec",
                backend,
                "python",
                "-m",
                "scripts.backup",
                "--db",
                "/app/data/agentsoc.db",
                "--output",
                "/app/data/migrated-copy.db",
            )
            migrated_copy = lab / "migrated-copy.db"
            docker("cp", backend + ":/app/data/migrated-copy.db", migrated_copy)
            assert_relationships(migrated_copy)
            migrated = snapshot(migrated_copy)
            assert {r[0] for r in migrated["schema_migrations"]} == {1, 2}
            assert len(migrated["actions"]) == len(original["actions"]) + 1
            assert not (data / "ssh-executed").exists()
            report["checks"]["runtime_and_dry_run"] = "PASS"
            for name in containers:
                logs = docker("logs", name)
                assert not any(
                    marker in logs
                    for marker in (
                        "Traceback (most recent call last)",
                        '"level": "ERROR"',
                        '"level": "CRITICAL"',
                    )
                )
            report["checks"]["startup_logs"] = "PASS"
            # Run the old application/worker against a COPY of the migrated database, never the active one.
            rollback = lab / "rollback"
            rollback.mkdir()
            rollback.chmod(0o777)
            target = rollback / "agentsoc.db"
            with sqlite3.connect(migrated_copy) as src, sqlite3.connect(target) as dst:
                src.backup(dst)
            docker(
                "run",
                "--rm",
                "--network",
                "none",
                "--user",
                "0",
                "-v",
                f"{rollback}:/app/data",
                image,
                "python",
                "-c",
                "import os; os.chown('/app/data/agentsoc.db',10001,10001)",
            )
            code = "from src.service import Service; from src.settings import Settings; s=Service(Settings.from_env()); s.tick(); assert len(s.store.cases())>=3"
            docker(
                "run",
                "--rm",
                "--network",
                "none",
                "-v",
                f"{rollback}:/app/data",
                *env_args,
                previous_image,
                "python",
                "-c",
                code,
            )
            # An old backend must also serve the migrated copy and pass its health endpoint.
            old_backend = prefix + "-rollback"
            containers.append(old_backend)
            docker(
                "run",
                "-d",
                "--name",
                old_backend,
                "--network",
                network,
                "-v",
                f"{rollback}:/app/data",
                *env_args,
                previous_image,
            )
            wait_for(lambda: _old_health(old_backend))
            report["checks"]["previous_image_migrated_copy"] = "PASS"
            report["classification"] = "PASS"
        except BaseException:
            report["classification"] = "FAIL"
            raise
        finally:
            Path(report_path).write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
            for name in reversed(containers):
                subprocess.run(
                    ["docker", "rm", "-f", name],
                    stdin=subprocess.DEVNULL,
                    stdout=subprocess.DEVNULL,
                    check=False,
                )
            subprocess.run(
                ["docker", "network", "rm", network],
                stdin=subprocess.DEVNULL,
                stdout=subprocess.DEVNULL,
                check=False,
            )
            # Give ownership back only within this disposable mount so TemporaryDirectory can clean it.
            if hasattr(os, "getuid"):
                code = f"import os; root='/app/data'; [(os.chown(os.path.join(p,n),{os.getuid()},{os.getgid()})) for p,ds,fs in os.walk(root) for n in ds+fs]"
                for directory in (data, lab / "rollback"):
                    if directory.exists():
                        docker(
                            "run",
                            "--rm",
                            "--network",
                            "none",
                            "--user",
                            "0",
                            "-v",
                            f"{directory}:/app/data",
                            image,
                            "python",
                            "-c",
                            code,
                        )
    print("PASS: isolated Python 3.12 containers, shared image, migration, dry-run and image rollback")


def _healthy(*names):
    assert all(docker("inspect", "--format", "{{.State.Health.Status}}", name) == "healthy" for name in names)
    return True


def _old_health(name):
    try:
        docker(
            "exec",
            name,
            "python",
            "-c",
            "import urllib.request; urllib.request.urlopen('http://127.0.0.1:8000/health',timeout=3)",
        )
    except RuntimeError as exc:
        raise AssertionError("Old backend not ready") from exc
    return True


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--image", required=True)
    parser.add_argument("--previous-image", required=True)
    parser.add_argument("--report", required=True)
    args = parser.parse_args()
    run(args.image, args.previous_image, args.report)
