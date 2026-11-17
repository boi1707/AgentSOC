# Phase 2 — deployment readiness and dry-run validation

Recorded 2026-11-17, Asia/Bangkok. Phase 1/2 changes were preserved from `feat/soc-integrations`
on review branch `feat/ai-assistant-telegram-i18n`. Historical reference: committed baseline `0022d28`. No production
credentials/data were used for validation. No VPS, live bot/workflow, firewall or deployment was changed.

**READY FOR GITHUB PR REVIEW: YES** — source and local checks are ready for review; CI remains a gate.

**READY FOR VPS DRY-RUN DEPLOYMENT: NO** — Python 3.12 container/rollback CI must execute and pass,
and the actual VPS images/configuration must be inventoried and checked first.

**READY FOR LIVE BLOCKING: NO** — SSH/pfSense mitigation remains unauthorized and disabled for this release.

## Actual validation results

Classifications: **PASS** = executed locally and successful; **FAIL** = executed and unsuccessful;
**NOT RUN** = not executed; **MOCKED** = external interactions simulated; **REQUIRES LIVE LAB** =
requires the actual VPS, Shuffle, Telegram or integrations. A mocked result is not live integration success.

| Validation | Status | Actual result / limit |
| --- | --- | --- |
| Full backend regression | PASS | Runtime-fix regression: `193 passed, 1 skipped` in 101.54 seconds, Windows Python 3.14; two dependency deprecation warnings; includes mocked external integrations |
| Focused Phase 2/assistant tests | PASS | `46 passed` before adding the sixth migration test; all are included in the final full run |
| Ruff lint and formatting | PASS | Ruff 0.17.3, matching the development lock; `src scripts tests integrations` |
| Python compile check | PASS | `compileall` over source, scripts, integration helpers and tests |
| Frontend typecheck, ESLint, production build | PASS | Existing TypeScript/Vite toolchain |
| Browser regression | PASS | `3 passed` in 11.6 seconds; real disposable local API/worker/SQLite, mock LLM and no external services |
| Workflow YAML parsing | PASS | Parsed locally; this does not execute GitHub Actions or Docker |
| v1 → v2 migration, preservation and repeat | PASS | Exact historical schema fixture, representative records, all original table rows preserved; two migration runs identical |
| SQL failure / abrupt migration interruption | PASS | Injected failure rolls back DDL/data; subprocess exit before commit recovers original schema/data and can retry |
| WAL-aware backup / disposable restore | PASS | SQLite online backup includes committed WAL state and excludes an in-flight transaction; backup restores into a separate database |
| Previous application source with migrated schema | PASS | Historical `0022d28` backend and worker service run against a migrated copy; incidents/runs/evidence/actions/outbox preserved |
| Docker image builds and Python 3.12 interpreter | PASS | Initial Ubuntu run `44098787194` built both images and passed the interpreter assertion |
| Docker runtime gate | FAIL | Initial run `44098787194` failed at host port discovery; corrected container-local validation awaits a new CI run |
| Backend/Worker container health | NOT RUN | Initial run stopped before health/API validation; no health success claimed |
| Previous **image** with migrated database copy | NOT RUN | CI builds the historical image and checks its service/backend against a copy; distinct from the source-level PASS above |
| Proactive two-chat delivery, inline callbacks and final result delivery | MOCKED | Real local API/storage with mocked Shuffle/Telegram HTTP and a persistent disposable delivery ledger; one logical result sent separately to each chat |
| Callback auth, idempotency, races, policy and audit | MOCKED | Fifteen workflow/security test cases described below; no live messages/firewall calls |
| Dry-run Web/Telegram integration | MOCKED | Shared authoritative state, one claimed transition/action/result event, correct actor; response `dry_run`, `blocked=false`, `not_verified` |
| Actual Shuffle workflow installation and Telegram delivery | REQUIRES LIVE LAB | No instance/bot access used; exact node guide supplied |
| Actual VPS image compatibility, networking and integrations | REQUIRES LIVE LAB | Must test the recorded running images/configuration, not assume they equal `0022d28` |
| Opt-in live-provider test | NOT RUN | One skipped test; no paid model request made |
| Live SSH/pfSense blocking | NOT RUN | Must remain disabled; no real firewall test performed |

The first Ruff format check flagged an unformatted new Docker-validation line; formatting was fixed
and the final lint/format checks pass. No unresolved local test failures remain. Python 3.12 and
container behavior have not been inferred from successful Python 3.14 tests.

## Changes in this phase

* `.github/workflows/tests.yml`: isolated Ubuntu Docker build/runtime/rollback gate, read-only GitHub
  permissions, full history for historical-source checks, no publish/deploy/merge step.
* `scripts/validate_docker.py`: disposable data, internal Docker network, random localhost port,
  shared versioned image assertions, health/API/ingestion/assistant/dry-run checks, startup-log checks,
  SSH execution sentinel, migrated-copy and old-image rollback checks. It removes only its own
  randomly named test containers/network and temporary directories; it does not delete volumes.
* `scripts/migration_lab.py`, `tests/fixtures/schema_v1.sql`, `tests/test_migration_readiness.py`:
  reproducible historical fixture, preservation/relationship checks, interruption, compatibility and
  SQLite backup/restore tests. No operational data is embedded in the fixture.
* `src/migrations.py`: explicit rollback on migration failure even for callers without a transaction
  context. No destructive down migration or new schema version beyond v2.
* `src/notifications.py`, storage/service notification paths: one bounded, redacted proposal envelope
  containing severity, source, explanation, evidence summary and stable recipient snapshot.
* `src/shuffle.py`: persist recipient identity before first send so retries cannot move an event to
  different chats after configuration changes.
* `src/api/assistant.py`, `integrations/shuffle/agentsoc_bridge.py`: version-bound inline callbacks,
  verified Telegram ingress wrapper, safe text formatting and optional durable recipient ledger.
  Whitespace-only commands now return a controlled error rather than leaving an unexpected dispatch failure.
* `tests/test_telegram_workflow.py`: mocked HTTP round trips, races, negative authorization cases,
  partial recipient failure and ambiguous acknowledgement behavior.
* `tests/conftest.py`: shared existing authenticated-console fixture; remove duplicate fixture
  imports from test modules so CI lint passes. Existing eligibility, Wazuh thresholds and exclusions remain unchanged.
* Python formatting/import cleanup for the Phase 1 additions so the existing Ruff CI gate can pass.

## Docker and Backend/Worker gate

The production Dockerfile declares `FROM python:3.12-slim`; Node is a separate frontend build stage.
The main Compose configuration uses the same `AGENTSOC_IMAGE` for Backend and Worker and forces
`RESPONSE_MODE=dry-run` in both. Persistent mounts and bind-address interpolation are unchanged.

The CI `container` job builds `agentsoc:ci-$GITHUB_SHA` once with an OCI source-revision label. It also
builds historical `0022d28` in a separate directory from committed Git content only. It then runs:

```bash
python -m scripts.validate_docker \
  --image "agentsoc:ci-$GITHUB_SHA" \
  --previous-image agentsoc:rollback-0022d28 \
  --report "$RUNNER_TEMP/agentsoc-docker-validation.json"
```

The gate copies Compose YAML into its temporary project before parsing it with a synthetic `.env`;
it does not resolve the real repository `.env`. Runtime containers are started directly with matching
read-only/security/worker settings on an isolated internal network. They share only disposable data,
receive generated test credentials and empty external-service configuration. API checks execute inside
Backend against its own localhost:8000, with a persistent cookie jar and CSRF header in one probe
process. Backend/Worker publish no host ports. A short-lived diagnostic reproduction alone requests
the original loopback-only binding and records state/ports before removal. This verifies container
startup, not a production Compose rollout.

Assertions include actual interpreter 3.12, equal Backend/Worker image IDs, a nonempty revision label,
`/live`, `/health`, `/ready`, Docker health states and worker `--health`; incident APIs, assistant
citations, an authorized dry-run approval and supported fixture ingestion through the independent
worker. It checks the new action count, migration version/relationships, absence of the SSH sentinel
and startup errors. Historical service/backend checks use a SQLite backup copy rather than the active
test database. CI uploads its JSON result as `docker-validation-result`; build/startup failure is not success.

**Initial CI status: FAIL.** [Run 44098787194](https://github.com/boi1707/AgentSOC/actions/runs/44098787194)
passed Python 3.12, Python 3.14 and console jobs. Both images built successfully. The runtime harness
failed at `docker port` before health/API/rollback checks. The old containers were removed by cleanup,
so their state cannot be inspected retrospectively. The repair records state, exit code, health,
`NetworkSettings.Ports` and requested bindings in CI to distinguish a running unexposed container from
an exited one. It keeps `--internal` and moves authenticated HTTP checks into the container.

The JSON artifact now records every validation stage as PASS, FAIL or NOT RUN, the failed stage,
and whitelisted container diagnostics with bounded sanitized stdout/stderr logs. It excludes container
environment arrays, cookies, CSRF values and raw healthcheck output. New CI results will be recorded
after execution; an absent artifact or unexecuted stage never satisfies the gate.

## Migration, relationships and rollback findings

Current migration marker: **v2**. Its additions are `callback_receipts` and `notification_outbox`;
existing incident, evidence, run, decision and integration tables retain their data and shape.

The disposable v1 schema was exported from actual `0022d28` storage/migration code. The test seed has
two incidents, four linked inbox events, two completed runs/jobs, judge ledger entries, notes, a local
user, an approved dry-run decision and its result outbox row, plus existing integration records.
Every pre-existing table row is compared before/after migration, except the intentional version-2
marker addition. Indexes, SQLite integrity and logical incident/run/action/outbox relationships are
checked. The historical schema does **not** declare SQL foreign keys: `foreign_key_check` alone is
insufficient, so explicit orphan checks are included. This phase does not silently retrofit constraints.

The migration is idempotent. A simulated SQL error after new DDL rolls the standalone connection back.
An abrupt subprocess exit immediately before the v2 marker/commit leaves the v1 snapshot intact;
reopening and migrating succeeds. The new API and worker service read migrated incidents successfully.

Old source `0022d28` can run against the additive migrated schema in the local compatibility test,
while preserving the important incident/run/action/evidence/outbox rows. This is **not** a guarantee
that the actual VPS images, different revisions or old dependency sets are compatible. The old version
does not implement the assistant, receipts, pending-notification outbox, inline callbacks, expiry or
new dead-letter handling; pause the new Telegram workflows during any image rollback. Old delivery
code can otherwise retry states it does not understand. Preserve new tables, audit and callback state.

Image rollback and database rollback are different operations. No automatic down migration exists.
SQLite's online backup API was used both with committed WAL content and a concurrent uncommitted
transaction, and restoration was tested only to a separate disposable filename. Never copy a live
`.db` alone while ignoring active WAL files, and never restore over a running database.

## Shuffle/Telegram status and security matrix

Use the exact [node-by-node workflow template](../integrations/shuffle/WORKFLOWS.md). There is no
claimed native export/import: the installed Shuffle version and workflow schema are unavailable.

Flow A: committed proposal → AgentSOC outbox → authenticated private Shuffle ingress → one persistent
delivery identity per `(event_id, chat_id)` → Telegram plaintext plus Approve/Ignore inline keyboard.
The message includes incident/run IDs, severity, source IP, stored AI explanation and evidence summary.
Buttons contain only `as:a:<run_id>` / `as:i:<run_id>` (37 bytes). No credential is placed in a URL/button.

Flow B: authenticated Telegram webhook → verified helper → HMAC-signed raw body → AgentSOC. The server
resolves the button's run to its incident and applies the same current-role/state/version/expiry/IP
policy and atomic claim used by Web. Identity comes from `callback_query.from`, not the bot's message.
Text commands remain `/status`, `/incidents`, `/pending`, `/review 24h`, `/incident`, `/why`, `/approve`
and `/ignore`. Shuffle formats/delivers messages; it never grants approval authority.

| Required case | Status | Evidence |
| --- | --- | --- |
| 1. Authorized approval | MOCKED | Full notification/button/signed API round trip, actor `admin` |
| 2. Unauthorized sender | MOCKED | Unknown identity rejected before a decision |
| 3. Notification-only sender | MOCKED | Chat recipient has no mapped account; mapped viewer also denied |
| 4. Duplicate callback | MOCKED | Cached reply; one action/claimed transition/result event |
| 5. Two authorized Telegram approvers | MOCKED | Concurrent HTTP requests; one succeeds, one conflicts |
| 6. Web/Telegram race | MOCKED | Real local session and signed callback; one succeeds, one conflicts |
| 7. Expired/stale proposal | MOCKED | Inline run IDs rejected after expiry or version change; replay also denied |
| 8. Protected source IP | MOCKED | Existing protected network policy rejects the proposal |
| 9. Ignore/rejection | MOCKED | Attributed `second` actor, `rejected`, one result event |
| 10. Invalid HMAC | MOCKED | HTTP 401; no decision |
| 11. Expired timestamp | MOCKED | HTTP 401 outside allowed five-minute skew |
| 12. Update ID rebound | MOCKED | Changed payload under same original update ID returns conflict |
| 13. Retry after delivery failure | MOCKED | Same stable event ID, due-time backoff and failed-recipient retry |
| 14. Two recipients | MOCKED | Two separate ledger identities, successful first recipient skipped on retry; no mitigation actions from sending |
| 15. Forged/missing Telegram ingress trust | MOCKED | Trusted wrapper rejects before signing or API dispatch |

The dry-run tests fail immediately if SSH/shell execution or a pfSense method is invoked. They check
`RESPONSE_MODE=dry-run`, `blocked=false`, `verification_status=not_verified`, one claimed transition,
one action, actor attribution and consistent Web/Telegram state. Setting `LLM_MODE=live` does not grant
a mapped viewer approval rights and an authorized decision still returns dry-run without a provider call.

The optional `DeliveryLedger` is a notification-delivery store, not another incident database. It needs
durable local storage shared by the workflow executors on one host, or equivalent unique-key/atomic
operations in the installed platform's durable store. Do not share SQLite over network filesystems.
An ambiguous/lost Telegram acknowledgement becomes `unknown` and requires reconciliation; a successful
send followed by a lost acknowledgement can still duplicate a physical message if an operator resends.
One logical decision/result event is not exactly-once physical Telegram delivery.

## Reproduce local validation

```bash
python -m pip install -r requirements-dev.lock
python -m ruff check src scripts tests integrations
python -m ruff format --check src scripts tests integrations
python -m pytest -q -s
python -m pytest tests/test_migration_readiness.py tests/test_telegram_workflow.py -q -s
python -m compileall -q src scripts integrations tests
cd frontend
npm ci
npm run typecheck
npm run lint
npm run build
npm run test:e2e
```

Playwright needs its browser dependencies. On this Windows host set
`$env:AGENTSOC_TEST_PYTHON=(Get-Command python).Source`; the existing `.venv` interpreter is blocked
by application-control policy. `pytest -s` avoids the local invalid-subprocess-handle capture issue.
Linux CI uses an isolated Python 3.12 environment and the locked dependency files. Full Git history
is required by the historical-source compatibility test (`git archive 0022d28 src`).

## Required manual configuration

| Setting | Where / requirement |
| --- | --- |
| `RESPONSE_MODE` | AgentSOC; must remain `dry-run` |
| `LLM_MODE`, existing LLM URL/key/model | Existing analysis configuration; no mitigation authority |
| `SHUFFLE_HOOK` | Private, access-controlled outgoing event ingress; no raw credentials in new callback URLs |
| `SHUFFLE_CALLBACK_SECRET` | Same independent 32+ character secret in AgentSOC/Shuffle; never displayed |
| `TELEGRAM_USERS` | Numeric sender IDs mapped to enabled local accounts with explicit roles |
| `TELEGRAM_NOTIFY_CHATS` | Two numeric notification chat IDs; grants no operator role |
| `PROPOSAL_TTL_SECONDS` | Existing default 86400; allowed 60..86400 |
| Telegram bot credential | Shuffle secret storage; AgentSOC's legacy `TG_TOKEN/TG_CHAT` are not required for the new path |
| Telegram webhook secret | Separate secret, verified at trusted ingress before signing |
| Delivery ledger location | Persistent protected local runner volume or equivalent atomic durable platform store |
| `AGENTSOC_IMAGE` | One reviewed committed release image tag for both services |
| `SOURCE_REVISION` build arg | Exact reviewed commit for the image label |
| `DB`, bind/WireGuard, existing integration settings | Preserve actual deployment values and data mounts |

Manual gates: inventory actual VPS revisions/images/local edits; run Ubuntu/container CI; test actual
rollback images on copies; configure/authenticate both Shuffle ingresses; configure bot/test chats and
operator mapping; execute every real-lab step in the workflow guide; verify Wazuh/TheHive/VirusTotal
health without changing their configuration. Production deployment requires separate explicit approval.

## Future VPS deployment — commands for an authorized operator

These commands were **not executed** on the VPS. Replace placeholders using reviewed inventory.
Do not run on a production database until deployment is explicitly authorized. The examples assume
the existing database is `/app/data/agentsoc.db`; verify the actual configured path first without
printing secret-bearing environment dumps. Preserve the actual Compose project name and bind address.

### 1. Inventory and consistent protected backup

```bash
cd /opt/soc/AgentSOC
umask 077
STAMP=$(date -u +%Y%m%dT%H%M%SZ)
BACKUP=/opt/soc/backups/agentsoc-$STAMP
mkdir -p "$BACKUP"
git status --short
git rev-parse HEAD > "$BACKUP/source-revision.txt"
git diff --binary > "$BACKUP/tracked-changes.patch"
BACKEND_CID=$(docker compose ps -q agentsoc-backend)
WORKER_CID=$(docker compose ps -q agentsoc-worker)
test -n "$BACKEND_CID"
test -n "$WORKER_CID"
docker inspect --format '{{.Image}}' "$BACKEND_CID" > "$BACKUP/backend-image.txt"
docker inspect --format '{{.Image}}' "$WORKER_CID" > "$BACKUP/worker-image.txt"
docker inspect --format '{{index .Config.Labels "com.docker.compose.project"}}' "$BACKEND_CID" > "$BACKUP/project.txt"
cp docker-compose.yml "$BACKUP/original-compose.yml"
install -m 600 .env "$BACKUP/environment.env"
if [ -f .ingest-key.pending ]; then install -m 600 .ingest-key.pending "$BACKUP/ingest-key.pending"; fi
docker compose exec -T agentsoc-backend python -m scripts.backup \
  --db data/agentsoc.db --output "data/backups/preupgrade-$STAMP.db"
docker cp "$BACKEND_CID:/app/data/backups/preupgrade-$STAMP.db" "$BACKUP/agentsoc.db"
chmod 600 "$BACKUP/agentsoc.db"
docker image save -o "$BACKUP/previous-images.tar" \
  "$(cat "$BACKUP/backend-image.txt")" "$(cat "$BACKUP/worker-image.txt")"
```

Keep this directory outside Git with restricted access. Securely preserve any other untracked local
files. Do not reset, overwrite, stash or force-pull VPS-only modifications. Review/reconcile them in
a separate release worktree and commit the intended combined source before building. A prior image
backup is not a database backup; both are required.

### 2. Build one reviewed release and validate before rollout

```bash
REV=<reviewed-full-commit-sha>
RELEASE=/opt/soc/AgentSOC-release-$REV
git fetch origin
git worktree add --detach "$RELEASE" "$REV"
cd "$RELEASE"
export AGENTSOC_IMAGE=agentsoc:$REV
docker build --build-arg SOURCE_REVISION="$REV" -t "$AGENTSOC_IMAGE" .
docker image inspect --format '{{index .Config.Labels "org.opencontainers.image.revision"}}' "$AGENTSOC_IMAGE"
# Run scripts.validate_docker on a Docker-equipped validation host with disposable fixtures
# and each recorded rollback image. It does not accept a production database path.
```

Actual Backend and Worker images may differ: test both recorded source/image versions independently.
Do not infer compatibility from the example `0022d28` image. Confirm required GitHub checks/artifact
passed for `REV`, and complete the real Shuffle/Telegram lab checks before enabling that integration.

### 3. Authorized dry-run rollout and health checks

```bash
PROJECT=$(cat "$BACKUP/project.txt")
test -n "$PROJECT"
export AGENTSOC_IMAGE="agentsoc:$REV"
EXPECTED_IMAGE_ID=$(docker image inspect --format '{{.Id}}' "$AGENTSOC_IMAGE")
docker compose -p "$PROJECT" --project-directory /opt/soc/AgentSOC \
  -f "$RELEASE/docker-compose.yml" up -d --no-build --pull never agentsoc-backend agentsoc-worker
for SERVICE in agentsoc-backend agentsoc-worker; do
  CID=$(docker compose -p "$PROJECT" --project-directory /opt/soc/AgentSOC -f "$RELEASE/docker-compose.yml" ps -q "$SERVICE")
  test -n "$CID"
  test "$(docker inspect --format '{{.Image}}' "$CID")" = "$EXPECTED_IMAGE_ID"
done
docker compose -p "$PROJECT" --project-directory /opt/soc/AgentSOC -f "$RELEASE/docker-compose.yml" ps
docker compose -p "$PROJECT" --project-directory /opt/soc/AgentSOC -f "$RELEASE/docker-compose.yml" \
  exec -T agentsoc-worker python -m src.worker --health
HEALTH_URL=http://127.0.0.1:8000  # use the existing private bind/WireGuard address if different
curl --fail "$HEALTH_URL/live"
curl --fail "$HEALTH_URL/health"
curl --fail "$HEALTH_URL/ready"
```

Inspect only `.Image` and the revision label to confirm both containers use the expected image ID.
The explicit exported `agentsoc:$REV` tag overrides the development default in `.env`; use the same
reviewed `REV` for build and rollout. If resuming in another shell, restore `REV`, `RELEASE`, `PROJECT`
and `BACKUP` from the reviewed inventory before running these commands.
Confirm health says `response_mode=dry-run`, worker freshness, original data visibility and no startup
exceptions. Verify existing integrations. In the authorized disposable lab, approve one eligible
fixture in Web/Telegram and confirm the exact dry-run/audit/action invariants; do not seed production
with synthetic actionable incidents. No SSH/pfSense activation is part of this runbook.

## Explicit rollback runbook

### Image-only rollback, keeping the migrated database

1. Obtain rollback authorization and pause the new Telegram command ingress/outbound workflow.
2. Preserve a second consistent **post-upgrade** database backup before changing anything.
3. Use each previously recorded image, not an assumed shared tag. Keep response mode dry-run and
   temporarily pause old notification delivery because its retry/dead-letter semantics differ.
4. Leave v2 tables and their receipts/audit intact; do not run a down migration or replay approvals.

Create `$BACKUP/rollback.yml` with actual recorded image IDs (no secrets):

```yaml
services:
  agentsoc-backend:
    image: <recorded-backend-image-id>
    environment:
      RESPONSE_MODE: dry-run
      SHUFFLE_HOOK: ""
      TG_TOKEN: ""
      TG_CHAT: ""
  agentsoc-worker:
    image: <recorded-worker-image-id>
    environment:
      RESPONSE_MODE: dry-run
      SHUFFLE_HOOK: ""
      TG_TOKEN: ""
      TG_CHAT: ""
```

```bash
docker compose -p "$PROJECT" --project-directory /opt/soc/AgentSOC \
  -f "$BACKUP/original-compose.yml" -f "$BACKUP/rollback.yml" \
  up -d --no-build --pull never agentsoc-backend agentsoc-worker
```

Verify recorded image IDs, mounts, health and `dry-run`. Reconcile pending/new delivery state before
deliberately restoring notification delivery. Existing Wazuh ingestion, TheHive and VirusTotal settings
remain in the preserved environment. If the actual old images fail against a migrated **copy**, do not
attempt image-only rollback against the live database; use an authorized restoration plan instead.

### Database restoration — separate explicit authorization required

Restoration loses decisions/events after the backup. Stop/pause all writers, ingestion and Telegram
callbacks, retain the post-upgrade backup, and stop Backend/Worker before switching databases. Restore
to a **new** filename through SQLite's backup API; do not overwrite the active DB or copy a live WAL DB:

```bash
docker compose -p "$PROJECT" --project-directory /opt/soc/AgentSOC \
  -f "$BACKUP/original-compose.yml" -f "$BACKUP/rollback.yml" stop agentsoc-backend agentsoc-worker
docker run --rm --network none --user 10001:10001 \
  -v /opt/soc/AgentSOC/data:/app/data \
  -e BACKUP_DB="/app/data/backups/preupgrade-$STAMP.db" \
  -e RESTORED_DB="/app/data/restored-$STAMP.db" \
  --entrypoint python "$(cat "$BACKUP/backend-image.txt")" -c '
import os, sqlite3
from pathlib import Path
from contextlib import closing
source, target = Path(os.environ["BACKUP_DB"]), Path(os.environ["RESTORED_DB"])
target.touch(exist_ok=False)
with closing(sqlite3.connect(source.resolve().as_uri()+"?mode=ro",uri=True)) as src:
    with closing(sqlite3.connect(target)) as dst:
        src.backup(dst)
target.chmod(0o600)
with closing(sqlite3.connect(target)) as check:
    assert check.execute("PRAGMA integrity_check").fetchone()[0] == "ok"
'
```

Set `DB: /app/data/restored-<STAMP>.db` for **both** roles in the rollback override (use the actual
timestamp), verify the restored file/relationships, then start the recorded images with the same
`up -d --no-build --pull never` command. Do not remove the original database/WAL or any volumes.
The local tests validated restoration into disposable copies only; production restoration was not run.

## Remaining gates

No real VPS/Shuffle/Telegram configuration was invented, installed or verified. The outstanding
container gate, actual-image compatibility checks and live-lab workflow configuration are the reason
VPS dry-run readiness is **NO**. Once those pass, request explicit deployment authorization. Live
blocking readiness remains **NO** regardless of analysis mode or successful dry-run tests.
