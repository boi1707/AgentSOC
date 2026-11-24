"""Isolated image/runtime/rollback gate. Uses disposable fixtures only; never deploys.

Run on a Docker-equipped Linux host. No production env files or existing Compose projects are read.
"""

import argparse
import json
import os
import re
import secrets
import sqlite3
import subprocess
import tempfile
import time
import urllib.error
from contextlib import closing
from pathlib import Path

from scripts.migration_lab import assert_relationships, seed_v1, snapshot

STAGES = (
    "fixture_preparation",
    "compose_configuration",
    "internal_network",
    "python_312",
    "legacy_port_diagnostics",
    "backend_worker_startup",
    "shared_image_revision",
    "container_health",
    "session_csrf_api_dry_run",
    "migration_backup",
    "startup_logs",
    "historical_image_service",
    "historical_image_backend",
)


def sanitize(value, credentials=()):
    if isinstance(value, dict):
        return {key: sanitize(item, credentials) for key, item in value.items()}
    if isinstance(value, list):
        return [sanitize(item, credentials) for item in value]
    if isinstance(value, str):
        for secret in sorted((s for s in credentials if len(s) >= 4), key=len, reverse=True):
            value = value.replace(secret, "[REDACTED]")
        value = re.sub(r"https?://[^\s\"<>]+", "[URL]", value)
        value = re.sub(r"(?i)(bearer\s+)[A-Za-z0-9._~-]+", r"\1[REDACTED]", value)
        value = re.sub(
            r"(?i)((?:password|token|secret|csrf|cookie|api_key)\s*[=:]\s*)[^\s,;]+", r"\1[REDACTED]", value
        )
    return value


def docker(*args):
    result = subprocess.run(
        ["docker", *map(str, args)],
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        check=False,
    )
    if result.returncode:
        credentials = [str(arg).partition("=")[2] for arg in args if "=" in str(arg)]
        error = sanitize(result.stderr[-2500:], credentials)
        raise RuntimeError(f"Docker {args[0]} failed ({result.returncode}): {error}")
    output = result.stdout + (result.stderr if args[0] == "logs" else "")
    return output.strip()


def advance(report, stage=None):
    previous = report.pop("active_stage", None)
    if previous:
        report["stages"][previous] = "PASS"
        print(f"PASS: {previous}", flush=True)
    if stage:
        report["active_stage"] = stage
        print(f"RUN: {stage}", flush=True)


def container_state(name, credentials=()):
    # Never inspect Config.Env, labels containing credentials, or raw healthcheck output.
    template = (
        '{"status":{{json .State.Status}},"exit_code":{{json .State.ExitCode}},'
        '"oom_killed":{{json .State.OOMKilled}},"error":{{json .State.Error}},'
        '"health":{{if .State.Health}}{{json .State.Health.Status}}{{else}}null{{end}},'
        '"ports":{{json .NetworkSettings.Ports}},"requested_bindings":{{json .HostConfig.PortBindings}}}'
    )
    return sanitize(json.loads(docker("inspect", "--format", template, name)), credentials)


def diagnostics(names, credentials=()):
    result = {}
    for name in names:
        entry = {}
        for key, operation in (
            ("state", lambda: container_state(name, credentials)),
            ("logs", lambda: sanitize(docker("logs", "--tail", "60", name), credentials)),
        ):
            try:
                entry[key] = operation()
            except Exception as exc:
                entry[key] = {"error_type": type(exc).__name__}
        result[name] = entry
    return result


def wait_for(check, timeout=120):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        try:
            return check()
        except (AssertionError, urllib.error.URLError, ConnectionError, RuntimeError):
            time.sleep(1)
    raise AssertionError("Container readiness deadline exceeded")


def run(image, previous_image, report_path):
    report = {
        "classification": "NOT RUN",
        "image": image,
        "previous_image": previous_image,
        "checks": {},
        "stages": dict.fromkeys(STAGES, "NOT RUN"),
    }
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
            advance(report, "fixture_preparation")
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
            advance(report, "compose_configuration")
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
            advance(report, "internal_network")
            docker("network", "create", "--internal", network)
            assert json.loads(docker("network", "inspect", "--format", "{{json .Internal}}", network)) is True
            advance(report, "python_312")
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
            advance(report, "legacy_port_diagnostics")
            legacy_probe = prefix + "-port-reproduction"
            containers.append(legacy_probe)
            docker(
                "run",
                "-d",
                "--name",
                legacy_probe,
                "--network",
                network,
                "-p",
                "127.0.0.1::8000",
                "-v",
                f"{data}:/app/data",
                *env_args,
                image,
            )
            docker("exec", legacy_probe, "python", "-m", "scripts.container_probe", "--health-only")
            report["legacy_port_reproduction"] = container_state(legacy_probe, env.values())
            assert report["legacy_port_reproduction"]["status"] == "running"
            docker("rm", "-f", legacy_probe)
            containers.remove(legacy_probe)
            advance(report, "backend_worker_startup")
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
                    args += [image]
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
            report["container_startup"] = {name: container_state(name, env.values()) for name in containers}
            assert all(state["status"] == "running" for state in report["container_startup"].values())
            assert all(not state["requested_bindings"] for state in report["container_startup"].values())
            advance(report, "shared_image_revision")
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
            advance(report, "container_health")
            docker("exec", backend, "python", "-m", "scripts.container_probe", "--health-only")
            wait_for(lambda: _healthy(backend, worker))
            docker("exec", worker, "python", "-m", "src.worker", "--health")
            advance(report, "session_csrf_api_dry_run")
            report["api_probe"] = json.loads(
                docker("exec", backend, "python", "-m", "scripts.container_probe")
            )
            assert set(report["api_probe"].values()) == {"PASS"}
            advance(report, "migration_backup")
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
            assert {r[0] for r in migrated["schema_migrations"]} == {1, 2, 3}
            assert migrated["managed_block_leases"] == []
            with closing(sqlite3.connect(migrated_copy)) as db:
                columns = {row[1] for row in db.execute("PRAGMA table_info(managed_block_leases)")}
            assert {"activation_deadline", "block_ttl_seconds", "block_requested_at"} <= columns
            assert len(migrated["actions"]) == len(original["actions"]) + 1
            assert not (data / "ssh-executed").exists()
            report["checks"]["runtime_and_dry_run"] = "PASS"
            advance(report, "startup_logs")
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
            advance(report, "historical_image_service")
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
            advance(report, "historical_image_backend")
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
            advance(report)
            report["classification"] = "PASS"
        except BaseException as exc:
            report["classification"] = "FAIL"
            active = report.pop("active_stage", None)
            if active:
                report["stages"][active] = "FAIL"
            report["failed_stage"] = active or "fixture_preparation"
            report["error"] = {
                "type": type(exc).__name__,
                "message": sanitize(str(exc), (*env.values(), "lab-review-" + "r" * 32)),
            }
            report["diagnostics"] = diagnostics(containers, (*env.values(), "lab-review-" + "r" * 32))
            print(
                json.dumps(
                    {
                        "failed_stage": report["failed_stage"],
                        "error": report["error"],
                        "diagnostics": report["diagnostics"],
                    }
                ),
                flush=True,
            )
            raise RuntimeError(
                f"Container validation failed at {report['failed_stage']}; see JSON diagnostics"
            ) from None
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
