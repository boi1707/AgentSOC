#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/.."
for tool in docker python3 ip ssh-keygen; do
  command -v "$tool" >/dev/null || { echo "Missing prerequisite: $tool" >&2; exit 1; }
done
docker compose version >/dev/null
docker info >/dev/null
python3 -c 'import sys; sys.exit(0 if sys.version_info >= (3, 12) else "Setup needs Python 3.12+ (Ubuntu 22.04 does not include it by default). You can instead use the manual Docker steps in README.md.")'
if [[ ! -x .venv/bin/python ]]; then python3 -m venv .venv; fi
.venv/bin/python -m pip install -r requirements.lock
.venv/bin/python -m scripts.setup
# Container UID owns runtime data; configuration stays owned by the operator.
if [[ $EUID -eq 0 ]]; then
  chown -R 10001:10001 data
else
  sudo chown -R 10001:10001 data
fi
echo 'Ready. Review .env, then run: make up && make health'
