# Validation record

Validated locally on Windows on 2026-11-06. These results describe the working
tree; they do not certify a deployed environment.

| Check | Result |
| --- | --- |
| Python 3.12 backend suite | 103 passed, 1 skipped |
| Python 3.14 backend suite | 103 passed, 1 skipped |
| Ruff lint and format | Passed; 42 Python files formatted |
| Frontend TypeScript and ESLint | Passed |
| Vite production build | Passed; JavaScript 309.32 kB / 95.80 kB gzip |
| Playwright with installed Chrome | 2 passed |
| npm dependency audit | 0 reported vulnerabilities |

The backend suite includes real HTTP ingestion and a separate worker process
with disposable SQLite databases, additive legacy migration, durable job
ownership/retry, replay cutoff, permissions, CSRF, privacy guards and response
intent recovery. The browser suite covers empty data, the synthetic Wazuh
pipeline, ledger, analyst notes, dry-run review, mobile navigation, keyboard
focus and session cookie isolation.

The skipped test requires the explicit `--live-provider` option and may make a
paid provider request. It was not enabled. One Starlette TestClient deprecation
warning remains in the backend suite.

Docker CLI is unavailable on this machine: image build and Compose startup were
not run. Compose/workflow YAML and shell syntax were checked statically only.
No real Wazuh/VPS/WireGuard/firewall, Telegram, SSH response or paid LLM
integration was exercised. No RAM, throughput, detection accuracy or model cost
benchmark is claimed. No GitHub push or deployment was performed.

Reproduction commands and prerequisites are in [README](../README.md).
