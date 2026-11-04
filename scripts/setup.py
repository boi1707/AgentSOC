"""Prepare local configuration without printing credentials or private keys."""

import ipaddress
import json
import os
import secrets
import shutil
import subprocess
from pathlib import Path

from dotenv import load_dotenv, set_key

from src.settings import Settings


def main():
    env = Path(".env")
    if not env.exists():
        shutil.copyfile(".env.example", env)
    env.chmod(0o600)
    load_dotenv(env)
    for name in ("INGEST_KEY", "APPROVE_KEY"):
        if not os.getenv(name):
            value = secrets.token_urlsafe(32)
            set_key(env, name, value)
            os.environ[name] = value
            print(f"Generated {name} in .env (value hidden).")
    config = Settings.from_env()
    config.validate()
    # The Compose volume is fixed at ./data:/app/data.
    data = Path("data").resolve()
    for value in (config.db, config.ssh_key, config.known_hosts):
        if not Path(value).resolve().is_relative_to(data):
            raise ValueError("Docker DB, SSH_KEY and KNOWN_HOSTS must be inside ./data")
    bind = str(ipaddress.ip_address(os.getenv("BIND_IP", "127.0.0.1")))
    addresses = json.loads(subprocess.check_output(["ip", "-j", "address", "show"], text=True))
    assigned = {a["local"] for interface in addresses for a in interface.get("addr_info", [])}
    if bind not in assigned:
        raise ValueError("BIND_IP is not assigned to this host; start WireGuard first")
    (data / "logs").mkdir(parents=True, exist_ok=True)
    key = Path(config.ssh_key)
    key.parent.mkdir(parents=True, exist_ok=True)
    if not key.exists():
        subprocess.run(["ssh-keygen", "-q", "-t", "ed25519", "-f", str(key), "-N", ""], check=True)
    if key.stat().st_mode & 0o777 != 0o600:
        key.chmod(0o600)
    public_key = Path(str(key) + ".pub")
    if not public_key.exists():
        raise ValueError("Existing SSH key has no .pub; recover its public key with ssh-keygen -y")
    print("Gateway authorized_keys entry (public key only):")
    print(
        'from="10.8.0.1",restrict,command="/usr/local/bin/agentsoc-block" ' + public_key.read_text().strip()
    )
    print("Verify the gateway fingerprint separately, then populate KNOWN_HOSTS before enabling SSH.")
    print(f"Configuration valid: LLM_MODE={config.llm_mode}, RESPONSE_MODE={config.response_mode}.")


if __name__ == "__main__":
    try:
        main()
    except (OSError, ValueError, subprocess.SubprocessError) as exc:
        # Validation messages are authored locally and never include input values.
        print(f"Setup failed ({type(exc).__name__}): check .env, interface addresses and file permissions.")
        raise SystemExit(1) from None
