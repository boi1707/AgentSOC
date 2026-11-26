# AgentSOC assistant and secure operator control upgrade

Current read-only interpretation contract, compact context, retry limits and rollback:
[Assistant grounding fix](ASSISTANT_GROUNDING_FIX.md). The older 12-second request
description below is historical; the current assistant uses bounded 7/5-second attempts.

Phase 2 validation, inline Telegram buttons, current test results and deployment gates are recorded in
[DEPLOYMENT_READINESS.md](DEPLOYMENT_READINESS.md). The sections below preserve the Phase 1 audit.

Audit and implementation date: 2026-11-17 (Asia/Bangkok). Local baseline:
`0022d28`, branch `feat/soc-integrations`, initially clean working tree.
This is a local source upgrade; no VPS, firewall, Telegram bot or Shuffle instance was deployed.
The supplied VPS commit `3451f63` and historical GitHub `8e25b91` are deployment context,
not verified identities of current containers. The local repository is a different revision.
Secret file contents were not inspected or printed. `.env` and `.ingest-key.pending` were not
edited, rotated, or committed.

## Architecture audit and gaps

| Area | Existing implementation reused | Gap addressed |
| --- | --- | --- |
| Ingestion | FastAPI `/ingest`, typed Wazuh adapter, normalized SQLite inbox, source/external-ID deduplication | Preserved; no Wazuh retention changes |
| Investigation | Grouper, durable jobs with leases, immutable run evidence, net/host/judge analysis, provider boundary and anonymization | Separate assistant request path so conversations cannot alter worker run state |
| Evidence | `cases`, `inbox`, `incident_alerts`, `runs`, ledger and source IDs | Assistant retrieves existing records; no second incident database |
| Web | React 19, React Router, Vite, Lucide, existing CSS, typed APIs and 15-second polling | Compact assistant panel, shared EN/VI catalogs and navbar switcher |
| Authentication | Server-side sessions, CSRF, viewer/analyst/approver/admin hierarchy, audit records | Session-protected assistant; signed callbacks map Telegram identities to enabled local users |
| Response | Policy checks, durable execution intent, `BEGIN IMMEDIATE` claim, unknown-result recovery, dry-run and SSH modes | Shared decision service; run/version and expiry checks repeated inside atomic claim |
| Shuffle | Leased, durable result outbox, stable event ID and backoff | Rejection results, pending-proposal outbox, separate recipients and bounded retry attempts |
| Telegram | Optional direct outbound notification to one `TG_CHAT`; no inbound commands | Authenticated Shuffle command endpoint, multi-chat notification metadata and workflow templates |
| Enrichment | VirusTotal jobs/cache/budget; TheHive synchronization and ambiguous-create fencing | Preserved and covered by regression tests |
| Containerization | Multi-stage frontend/backend image, non-root backend and worker, shared SQLite volume, configurable bind address | Both services use one image tag; Compose explicitly keeps response mode dry-run |
| pfSense | No adapter | Non-executing contract, plan validation, mocked tests, future lifecycle design |

The pre-change response route validated the run before the atomic claim. The new claim repeats
version, state, expiry and policy checks under the same database write lock as the transition.
The legacy Basic-auth review endpoint now delegates to this service too; its existing shared
review credential remains a compatibility mechanism, with actor `legacy-reviewer`. Prefer individual
session accounts or signed Telegram identities for operator attribution.

## Implemented behavior

The Web assistant is accessible from the dashboard and retains up to 20 messages in memory. Opening
an incident scopes questions to that incident; changing incident context clears history and cancels
the active request. Requests include bounded question history. No conversation is persisted to disk
or localStorage. Logout unmounts the panel and aborts its request.

Starter questions are “Rà soát 24 giờ qua”, “Có đề xuất nào đang chờ duyệt?” and
“Vì sao incident này đề xuất hành động đó?” in Vietnamese, with English equivalents.
The default review covers incidents created in the last 24 hours and counts inbox events received
in that window. Pending queries cover pending incidents regardless of age. A selected incident can
be inspected outside the default window. Results show up to 30 incidents, with an explicit total
and truncation flag. `/proposals` is a bounded list of up to 100 pending records.

Facts contain stored incident IDs, timestamps, response state, Wazuh levels, priority, proposal
metadata, synthetic flags, and linked evidence IDs. Citations contain normalized source records,
including available source/target IPs, source timestamps, Wazuh rules and severity. Missing evidence
is explicit. Stored verdict, confidence and rationale are labelled analysis, not observations.
High priority means at least one stored Wazuh alert has level 12 or higher. Confidence is a model
score, not a calibrated attack probability.

In `LLM_MODE=live`, an independent provider request can explain the retrieved context. It has a
12-second timeout, bounded context and output, anonymization and secret redaction. Failure leaves
the facts and citations available with `model_status=unavailable`. Mock mode returns evidence and
stored analysis without inventing a model conversation. The browser has a 20-second request timeout.
Explicit requests for English/Vietnamese can override the current interface language.

All assistant text is escaped by React. No model-generated Markdown, HTML, URLs, buttons or tool
requests are interpreted. Incident and citation links are constructed from structured server records.
The assistant only links to existing incident review controls; it cannot approve, reject, execute
commands or invoke response adapters. Raw evidence and enrichment are untrusted data in the prompt.
Prompt instructions are a defense layer, not a guarantee against incorrect model prose: interpretation
always remains separately labelled and has no execution authority.

EN/VI catalogs cover dashboard/navigation, incident and alert views, filters, statuses, empty states,
confirmation prompts, common API errors, system health, forms and the assistant. English is the default.
`agentsoc.language` persists the preference; switching updates the interface and document language
without reloading. Status/filter values remain immutable English API identifiers; their labels are
translated. Incident IDs, IPs, rule IDs, JSON field names, evidence contents, original model rationales
and audit records remain unchanged. Existing assistant answers retain their original response language;
subsequent questions use the selected language. The legacy `/cases` compatibility page is not the
React dashboard and has not been converted to the new i18n system.

## APIs and authorization

| Method/path | Authorization | Contract |
| --- | --- | --- |
| `POST /api/v1/assistant/query` | Existing session + CSRF | `message`, `language: en/vi`, optional `incident_id`, up to 8 history strings; returns facts, citations, analysis, interpretation and model status |
| `GET /api/v1/proposals` | Existing session | Pending proposal metadata derived from authoritative cases/runs |
| `POST /api/v1/incidents/{id}/response` | Approver/admin session + CSRF | Existing `decision: approve/reject`, current `run_id`; shared decision policy |
| `POST /api/v1/integrations/telegram` | Fresh HMAC-authenticated Shuffle request + mapped local identity | Original update ID, user ID, chat ID, documented command and language |

Telegram commands: `/status`, `/incidents`, `/pending`, `/review 24h`, `/incident <id>`, `/why <id>`,
`/approve <incident_id> <proposal_id>`, `/ignore <incident_id> <proposal_id>` and `/reject` as an alias.
Read-only operators can query; approval/rejection requires a mapped local approver/admin account.
Unknown or disabled users are denied. Callback command errors are stored as `error.code/message`
inside the authenticated callback response so retries receive the same result; authentication,
schema and replay-conflict errors use HTTP errors. Check the JSON `error` field even with HTTP 200.

The HMAC input is the exact raw UTF-8 `timestamp + '.' + request_body`, SHA-256, hex signature.
Headers are `X-AgentSOC-Timestamp` and `X-AgentSOC-Signature`. Timestamps must be within 300 seconds.
The independent signing secret belongs only on AgentSOC and trusted Shuffle. AgentSOC does not
accept a Telegram user ID from an unsigned payload. However, Shuffle is a trusted identity attestor:
it **must authenticate Telegram ingress** before extracting the sender from the original Telegram
update. Compromise of Shuffle or the signing secret defeats that trust boundary.

Persistent callback receipts reserve the original Telegram `update_id` before dispatch. Exact
duplicates return the cached result; reuse with different bytes is denied; an incomplete receipt
returns 409 and requires authoritative-state inspection. No automatic redispatch occurs after a crash.
Keep receipts until the bot's replay/retention policy is explicitly designed; this change does not
automatically prune security records.

## Proposal and response safety

A proposal is a projection of a non-replay analysis run, not a duplicate incident table. Its ID is
the run ID (or legacy case ID when no run exists). It exposes incident/run IDs, action, eligible source
IP, cited evidence IDs, creation and expiry, eligibility reason, response status/mode and blocked state.
Expiry is run completion time plus `PROPOSAL_TTL_SECONDS`; legacy cases use case creation time.
Expired, incomplete, replayed, closed, already-decided or stale proposals cannot execute.

The policy retains the existing attack verdict, confidence threshold (`MIN_CONFIDENCE`, default 0.85),
groundedness and cited network-source requirements. Protected networks and the gateway are rechecked.
SSH synthetic/mock restrictions remain intact. One transaction checks current policy, changes the
case from pending to executing, writes the actor/run/evidence-bound intent and audits the claim.
Only the successful claimant executes. Duplicates/stale Web requests return conflicts; exact Telegram
retries return their stored response. Unknown execution outcomes are fenced, never automatically rerun.

`RESPONSE_MODE=dry-run` remains the default, and both main Compose services now explicitly enforce it.
Approval records `status=dry_run`, `mode=dry-run`, `blocked=false`, and `verification_status=not_verified`.
It does not call SSH or a firewall. Live LLM mode grants no mitigation authority. Existing SSH code is
retained for compatibility but was not enabled, called or tested against a live gateway in this task.

Result events are unique by action ID. Both approve and reject now queue `response.completed`.
Pending notifications are transactionally queued as `proposal.created`, unique by run-derived event ID.
Synthetic/demo cases do not create external notifications. Both outboxes use leases, stable idempotency
headers, up to 10 attempts and exponential backoff capped at one hour. Repeated failures become
`dead_letter`; operators must inspect and explicitly requeue the same notification ID after repair.
Logging records error types/status codes rather than exception messages; integration secrets are redacted.

One logical result event does not guarantee exactly-once physical Telegram delivery. Shuffle must
persist per-event/per-recipient deduplication. Lost acknowledgements after Telegram accepts a message
can still cause duplicate physical delivery. Do not retry an approval to repair notification delivery.

## Database changes

Additive, idempotent migration version 2 adds:

* `callback_receipts(id, created, digest, result)` for replay protection and cached callback outcomes.
* `notification_outbox` for pending proposal notifications, with delivery status, attempts, due time,
  lease, redacted error and delivered timestamp.

Existing case/run/action/evidence/integration tables are reused and retained. No evidence is deleted.
There is no automatic down migration. A rollback to the recorded pre-upgrade images can leave these
unused tables in place. Restore the protected pre-upgrade database backup only if recovery actually
requires it; doing so discards decisions/events made after the backup and needs explicit authorization.

## Environment and manual setup

| Variable | Default | Purpose |
| --- | --- | --- |
| `SHUFFLE_CALLBACK_SECRET` | empty/disabled | Independent random secret, 32+ characters; must differ from application/model/bot credentials |
| `TELEGRAM_USERS` | `{}` | JSON map, e.g. `{"123456":"soc-approver","987654":"soc-viewer"}`; users must already exist |
| `TELEGRAM_NOTIFY_CHATS` | empty | Comma-separated numeric chat IDs; independent of authorization |
| `PROPOSAL_TTL_SECONDS` | `86400` | Proposal lifetime, validated range 60..86400 seconds |
| `AGENTSOC_IMAGE` | `agentsoc:local` | One exact image tag for both Compose services |
| Docker build arg `SOURCE_REVISION` | `unknown` | OCI revision label; supply the committed source revision when building |

Existing environment variables, database persistence, bind address/WireGuard options, TheHive,
VirusTotal and Wazuh configuration remain supported. `TG_TOKEN`/`TG_CHAT` retain their legacy direct
notification behavior when the new Shuffle-recipient path is not configured. The durable multi-chat
path requires `SHUFFLE_HOOK` plus `TELEGRAM_NOTIFY_CHATS`; configure it to avoid legacy direct delivery.
Notifications are disabled in demo mode. No new credential values have been generated for production.

Follow [Shuffle setup templates](../integrations/shuffle/README.md). They include pure Python helpers
for authenticating Telegram ingress, preserving sender identity, signing exact request bytes and
formatting bounded plaintext messages. No importable native workflow export is claimed because the
live Shuffle version and workflow schema were not available. Supply the private API address, webhook
ingress protection, bot credentials, two chat IDs, enabled local accounts and synchronized clocks.

## pfSense read-only diagnostics and managed response simulation

`PfSenseAdapter` validates plans and supports a separate operator-invoked HTTPS check for the
configured alias, configuration apply status and runtime PF table membership. `block` and
`remove` still raise, and settings reject live pfSense mode. Migration v3 supports transactionally
queued approvals, restart recovery and expiry through an explicitly injected simulated transport.
Normal runtime approval continues to use the existing dry-run or SSH paths.

The pinned pfREST v2.11.1 source uses positional alias identity for updates and a global filter apply.
Scoped and concurrency-safe mutation remains a prerequisite for running the lifecycle against a
real firewall. See [pfSense integration](PFSENSE_INTEGRATION.md) for
the source audit, exact read contract, lab configuration and remaining acceptance gates.

## Validation commands and results

Use a disposable test environment; no credentials are needed for normal tests:

```bash
python -m venv .venv
. .venv/bin/activate
python -m pip install -r requirements-dev.lock
python -m pytest -q -s
python -m pytest tests/test_assistant_control.py -q
python -m compileall -q src integrations/shuffle
cd frontend
npm ci
npm run lint
npm run build
npx playwright install chromium
npm run test:e2e
```

On this Windows host, use the available system Python with
`$env:AGENTSOC_TEST_PYTHON=(Get-Command python).Source` before Playwright. The checked-in virtual
environment executable was blocked by local application-control policy. `pytest -q` with default
capture produced Windows invalid-handle errors in subprocess tests; `-s` avoids that host issue.
Subprocess and browser fixtures now explicitly disable dotenv/external integrations and force mock
analysis plus dry-run, so local production credentials are not used by those fixtures.

Validation recorded locally:

* Focused backend unit/mocked integration run: **73 passed** before the final additional tests.
* Final backend regression run: **168 passed, 1 skipped** (71.69 seconds), including rejection
  crash recovery and denied-decision audit handling. The skipped test is the opt-in live provider.
* Frontend TypeScript/Vite production build: **passed**.
* Frontend ESLint: **passed**.
* Browser suite: **3 passed**, using real local HTTP backend, worker and disposable SQLite with mock
  LLM/no external services. Covers existing ingestion, ledger, notes and dry-run review; mobile
  navigation/session isolation; EN/VI switching, persistence, Unicode and assistant read-only output.
* Docker build/Compose runtime: **not run; Docker is unavailable on this host**.
* Python Ruff: **not run; module unavailable in usable system Python**.
* Python compile check: **passed**. Backend tests used the available Windows Python 3.14;
  the locked Python 3.12 container environment still requires Docker validation.
* Live provider, VPS, Wazuh manager, Shuffle, Telegram, TheHive, VirusTotal and pfSense lab E2E:
  **not verified by this task**. Paid live-provider tests remain opt-in.

New backend tests cover recent/pending/context retrieval, citations, missing evidence, unauthorized
sessions and CSRF, injection without side effects, isolated model failure and interpretation,
signed/expired/unsigned Telegram commands, role separation, duplicate/rebound update IDs, all command
types, approval/ignore/reject results, expired/stale/protected proposals, concurrent claims, revalidation
under lock, two recipients, durable retry/dead-letter state, disabled pfSense and catalog parity/Unicode.
Existing tests cover Wazuh adapters, source deduplication, worker leases/replays, API compatibility,
TheHive, VirusTotal, result delivery and the real local TCP ingest-to-review pipeline.

## Safe build and deployment runbook (operator execution only)

Do not deploy this uncommitted working tree. Review and commit the intended source first. On the VPS,
record the actual Compose project name/configuration and currently running backend/worker image IDs
separately. Do not assume their tags or build times match. Protect inventory and backup files outside Git.
Do not print `docker inspect` environment arrays, `.env`, or secret-bearing Compose configuration.

```bash
cd /opt/soc/AgentSOC
git status --short
git rev-parse HEAD
docker compose ps
umask 077
STAMP=$(date -u +%Y%m%dT%H%M%SZ)
mkdir -p /opt/soc/backups/agentsoc-$STAMP
BACKUP=/opt/soc/backups/agentsoc-$STAMP
docker inspect --format '{{.Image}}' "$(docker compose ps -q agentsoc-backend)" > "$BACKUP/backend-image.txt"
docker inspect --format '{{.Image}}' "$(docker compose ps -q agentsoc-worker)" > "$BACKUP/worker-image.txt"
cp docker-compose.yml "$BACKUP/docker-compose.yml"
python -m scripts.backup --db data/agentsoc.db --output "$BACKUP/agentsoc.db"
```

Also retain exact container configuration and securely back up `.env` through your existing secret
backup procedure, without printing it. Preserve VPS-only `.dockerignore`, `src/agents.py`,
`tests/test_core.py` changes as a reviewed patch in protected backup storage; preserve any untracked
secret files separately. Do not stash, reset, delete, force-pull or overwrite them. Reconcile these
changes into a separate release worktree and test that combined source before deployment.

Build both services once from the same **reviewed committed** release worktree:

```bash
# Set REV to the reviewed commit, RELEASE to its separate worktree path.
REV=<reviewed-full-commit>
RELEASE=/opt/soc/AgentSOC-release-$REV
git worktree add --detach "$RELEASE" "$REV"
cd "$RELEASE"
export AGENTSOC_IMAGE=agentsoc:$REV
docker build --build-arg SOURCE_REVISION="$REV" -t "$AGENTSOC_IMAGE" .
docker image inspect --format '{{index .Config.Labels "org.opencontainers.image.revision"}}' "$AGENTSOC_IMAGE"
```

After explicit production-deployment authorization, use the actual existing Compose project name.
Keeping the project directory at `/opt/soc/AgentSOC` preserves the existing `.env`, relative data mount
and WireGuard bind configuration while using the reviewed release's Compose file:

```bash
PROJECT=<existing-compose-project-name>
export AGENTSOC_IMAGE="agentsoc:$REV"
docker compose -p "$PROJECT" --project-directory /opt/soc/AgentSOC -f "$RELEASE/docker-compose.yml" \
  up -d --no-build agentsoc-backend agentsoc-worker
docker compose -p "$PROJECT" --project-directory /opt/soc/AgentSOC -f "$RELEASE/docker-compose.yml" ps
curl --fail http://127.0.0.1:8000/live
curl --fail http://127.0.0.1:8000/health
curl --fail http://127.0.0.1:8000/ready
```

Adjust the health-check address to the existing `BIND_IP`/WireGuard address; do not expose the service
publicly to make checks pass. Verify both running containers report the same image ID and health
reports `response_mode=dry-run`. Verify the worker heartbeat, ingestion/source IDs, TheHive state and
VirusTotal interface before enabling Telegram callbacks. Validate new secrets through secure management,
not shell history. Updating Git alone never updates a container.

For functional verification, first run `python -m pytest tests/test_assistant_control.py -q` and the
browser suite in a disposable environment. On the authorized lab, inspect a genuine eligible pending
proposal in Web and `/pending`, compare IDs, approve once, and confirm one action plus one result event,
`dry_run`, `blocked=false`, `not_verified`. Repeat the exact callback and confirm no additional action.
Verify both notification chats and an unauthorized recipient denial. Do not inject synthetic evidence
into production to manufacture an actionable proposal. Do not enable SSH/pfSense.

## Rollback

Retain the previous backend **and** worker image IDs; they may differ. After operator authorization,
create a small protected Compose override with each recorded ID separately:

```yaml
services:
  agentsoc-backend:
    image: <recorded-backend-image-id>
    environment:
      RESPONSE_MODE: dry-run
  agentsoc-worker:
    image: <recorded-worker-image-id>
    environment:
      RESPONSE_MODE: dry-run
```

Use the recorded original Compose file and override with the same project name/directory and
`up -d --no-build --pull never agentsoc-backend agentsoc-worker`. Confirm those exact image IDs,
database mount, mode and `/ready` afterward. Do not run `down -v`, prune images/volumes, delete data,
or silently restore the database. Additive tables may remain; restoring a backup loses newer state
and is a separate recovery decision. Do not re-submit prior approvals after rollback.

## Changed files and reasons

| Files | Reason |
| --- | --- |
| `src/assistant.py`, `src/api/assistant.py` | Bounded read-only retrieval, optional interpretation, signed Telegram ingress and proposal reads |
| `src/approvals.py`, `src/storage.py` | Unified policy/expiry and atomic claim; transactional pending notifications and rejection result events |
| `src/api/main.py`, `src/api/v1.py`, `src/api/schemas.py` | Route registration, shared decisions, proposal projection in existing incident contracts |
| `src/settings.py`, `.env.example` | Secure optional integration configuration, mapping, recipient separation and TTL |
| `src/migrations.py` | Additive replay-receipt and notification tables, migration marker |
| `src/service.py`, `src/shuffle.py`, `src/integrations.py` | Durable notification routing, bounded retry/dead-letter state and delivery health |
| `src/response.py`, `src/response_adapters.py` | Dry-run adapter and disabled pfSense planning contract |
| `frontend/src/AssistantPanel.tsx`, `frontend/src/main.tsx`, `frontend/src/style.css`, `frontend/src/types.ts` | Integrated panel, proposal metadata, responsive styling and contracts |
| `frontend/src/i18n/*` | Central catalogs and persistent language preference; components localize error keys when rendering |
| `integrations/shuffle/README.md`, `integrations/shuffle/agentsoc_bridge.py` | Manual workflow steps and testable signing/formatting helpers |
| `tests/test_assistant_control.py`, `tests/test_external_integrations.py` | New security/behavior tests; updated notification semantics and health contract |
| `frontend/e2e/assistant.spec.ts`, `frontend/playwright.config.ts` | Browser language/assistant tests and configurable test Python |
| `scripts/e2e_server.py`, `tests/test_http_pipeline.py` | Test isolation from dotenv and external integrations |
| `Dockerfile`, `docker-compose.yml` | Revision label, shared image and explicit dry-run environment |
| `.gitignore`, `.dockerignore` | Exclude pending ingest credential file from Git/build context |
| `docs/UPGRADE_AI_ASSISTANT.md` | Audit, implementation, limitations, configuration, validation and operations report |

## Remaining validation and limitations

The assistant retrieves locally ingested Wazuh evidence; it does not query the Wazuh manager live.
Recent means incident creation time, not activity on older incidents. Catalog fallback preserves
unknown API text and technical values; future UI/API messages need matching translations. Original
evidence, stored analysis and audit text intentionally retain their original language.

pfSense read-only HTTP diagnostics are available for separate lab verification. Automatic lease
reconciliation and expiry have been tested in simulation. Live apply/removal remain pending.
Legacy direct Telegram delivery
does not gain the new durable outbox semantics; configure the Shuffle path for those guarantees.
Native Shuffle workflows, trusted ingress, durable recipient deduplication and bot setup remain
manual. No production readiness or actual external-service E2E success is claimed.
