# Read-only assistant: grounded explanations and output validation

Baseline: `cb87e4fcd92120e24509256d04bc26489b1c75fc`.
Feature branch: `feat/assistant-grounded-interpretation`.
Local review: 2026-11-26. No VPS deployment or secret changes.

## Diagnosis

The original `src/assistant.py` parsed the provider's JSON and accepted any
`interpretation` string shorter than 12,000 characters. That includes empty text,
whitespace, `...`, and `…`. It then unconditionally set `model_status=available`.
HTTP 200 confirms transport success; JSON mode confirms syntax, not a substantive
explanation. The worker's stored investigation is a separate path and is not
rewritten by an assistant query.

The assistant also forwarded full normalized citations, proposal dictionaries,
history and analysis. That could inflate context, but it does not explain every
placeholder response: a one-incident/four-citation response still passed the same
weak validator. The original path did not inspect finish reasons or refusals.

DeepSeek's [JSON Output documentation](https://api-docs.deepseek.com/guides/json_mode/)
describes JSON formatting and possible blank content, even with a `stop` finish
reason. This is an additional reason to validate the message itself. We did not
make a paid request, inspect VPS secrets or capture the original raw production
response. The exact upstream reason for that particular `...` generation remains
unverified; the local acceptance defect is reproduced by deterministic tests.

## Behavior

Both session/CSRF-protected Web queries and authenticated, mapped Telegram queries
use `src.assistant.answer`. Telegram also accepts natural-language questions and
`/ask <question>` after its existing HMAC, timestamp, identity and receipt checks.
Existing explicit approval commands/buttons still use their separate RBAC-protected
control path. Conversational text never dispatches those controls.

Retrieval recognizes EN/VI recent incidents, most dangerous incidents, pending
approvals, a specific incident and blocking-policy explanations. An explicit
`incident_id` takes precedence; otherwise a full 32-hex ID in the question scopes
retrieval. Pending lists exclude closed cases, but may include ineligible proposals;
eligibility and reasons are always shown. Recent/dangerous searches cover 24 hours.
Dangerous ordering uses stored attack/review/other verdict, then maximum stored
Wazuh level, then creation time/ID. This is not a new model risk assessment.

The API retains facts, full linked citations and separately labelled stored analysis,
with at most 30 incidents and 40 citations per incident. New fact fields expose
severity, verdict, confidence, groundedness, observed source/destination IPs, rules,
blocking reasons and a deterministic server-policy explanation. That explanation is
labelled as policy/facts; it is never substituted into `interpretation` as generated AI.

Only compact context goes to the optional provider:

| Field | Source |
| --- | --- |
| Incident ID, status, Wazuh severity | SQLite case and normalized evidence |
| Source/destination IP, rule, signature/protocol, evidence IDs | Linked normalized inbox observations |
| Verdict, confidence, groundedness, rationale, mode | Existing stored investigation |
| Eligibility, mode and ineligibility reasons | Existing server proposal policy |

First attempt: at most 8 incidents, 4 evidence/rule references each, 500 characters
of rationale, 2 short history questions, and 24,000 serialized UTF-8 prompt bytes.
Retry: at most 2 incidents, 2 evidence/rule references each, 220 rationale characters,
no history and 12,000 prompt bytes. These are bounded excerpts; all retrieved facts
and citations remain in the response. Prompt records declare the matching total and
context limit. Internal IPs and identities are pseudonymized; configured credentials
are scrubbed. SECRET tokens are never restored into model prose or stored rationale.

Only `stop` or an omitted legacy finish reason is accepted. Refusals, tool/function
calls, malformed envelopes/JSON, wrong types, unsupported schema fields, unknown
explicit citation IDs, truncation and placeholder-only prose are rejected. A valid
interpretation needs at least two alphabetic words and twelve letters. This rejects
terse legitimate text too; such responses retry/fall back to facts instead of being
misrepresented as useful model output. It is not a proof that arbitrary model prose
is true: interpretation remains untrusted and has no action authority.

At most two provider requests are made. Production requests use cancellable async
HTTP: 7 seconds for attempt one and 5 for retry, within a 15-second model-stage
deadline, with at most 65,536 decoded response bytes and 1,024 output tokens.
The database retrieval is outside that deadline. HTTP status errors and privacy
guard rejection do not cause automatic network retry; invalid content and timeouts
can retry once. The worker's existing request limits are unchanged.

Failure returns `interpretation=null`, `model_status=unavailable`, existing evidence
and analysis, attempt count and a short error category. No provider body, exception
text, credential or failed completion is returned or copied into the retry prompt.
Mock mode and empty retrieval remain `evidence_only`, without a provider request.

## Supplied ICMP example

The regression fixture reconstructs the supplied facts for incident
`5eb4b0f385fb4467b8d4046cb5d036cb`; it does not mutate or impersonate that production
record. Four linked observations describe ICMP from `10.100.27.10` to `172.22.50.10`,
Wazuh rule `100101`, level 7. The stored verdict is `benign`, confidence `0.92`,
groundedness `1`. The returned policy states that the stored investigation does not
establish an attack and does not propose blocking. These facts remain available if
the optional model returns ellipses, malformed JSON or times out.

No conversational assistant code calls executors, runs shell commands, changes
proposal state, updates investigation analysis or mutates pfSense. `RESPONSE_MODE`
remains `dry-run`; `PFSENSE_LIVE_ENABLED` remains `0`. No database migration or new
runtime secret/configuration variable is introduced.

## Review and reproduce

Local results (2026-11-26): **299 passed, 1 skipped** for the full Python suite;
Ruff check/format passed (66 files); frontend `npm ci`, typecheck, lint and build
passed; **3 Playwright tests passed** with installed Chrome. npm's install audit
reported zero vulnerabilities. The skipped test is the opt-in paid LLM check;
the existing Starlette/httpx deprecation warning remains. No actual provider,
external integration, Docker image startup or VPS deployment is certified by these
local results.

```powershell
uv pip sync --python .venv/Scripts/python.exe requirements-dev.lock
.\.venv\Scripts\python.exe -m pytest -q
.\.venv\Scripts\python.exe -m ruff check src scripts tests
.\.venv\Scripts\python.exe -m ruff format --check src scripts tests
cd frontend
npm ci
npm run typecheck
npm run lint
npm run build
npm run test:e2e
```

Tests use disposable SQLite, local ASGI and simulated provider/Telegram requests.
The ICMP fixture supplies stored analysis directly, without making a live model
call. Existing approval/RBAC/HMAC and pfSense managed-response tests remain part of
the full regression suite. Browser tests cover facts, IP flow, rule ID and stored
verdict rendering without action buttons in conversational output using a labelled
UI response fixture. Backend tests separately exercise the real ASGI/SQLite path;
the existing browser pipeline test exercises real HTTP ingestion and a worker process.

Source diff after review/commit:

```bash
git diff cb87e4fcd92120e24509256d04bc26489b1c75fc..HEAD -- src frontend tests docs
```

## Deployment plan — operator-run only

1. Review the feature diff and test results. Back up the deployment `.env` privately
   and take a consistent SQLite backup with `python -m scripts.backup`; retain the
   current API/worker image tags and baseline commit for rollback.
2. Obtain the reviewed feature source through your normal release process. Preserve
   existing credentials, Wazuh/TheHive/Shuffle/Telegram settings, pfSense configuration
   and database. Keep `RESPONSE_MODE=dry-run` and `PFSENSE_LIVE_ENABLED=0`.
3. Build API and worker from the same version. For the existing Compose setup:
   `docker compose config --quiet`, then
   `docker compose build agentsoc-backend agentsoc-worker`.
4. Recreate only those two services with
   `docker compose up -d --no-deps agentsoc-backend agentsoc-worker`. Do not restart
   unrelated integrations, change firewall rules, use `down -v` or reset the database.
5. Check health/readiness and worker freshness. In the Web console, inspect the
   supplied incident and ask the ICMP/blocking question in Vietnamese. Verify facts
   and citations first; if opting into a paid live provider check, verify a substantive
   answer or honest `unavailable` response. Test the mapped Telegram identity with
   `/why <id>` or a natural-language question. Do not use approval commands/buttons
   during this read-only smoke test.
6. Confirm investigation verdicts and actions are unchanged. No state-changing
   integration, real firewall action or provider accuracy is certified by local mocks.

## Rollback

Recreate API and worker using the previously retained versioned images (baseline
`cb87e4f...`). Restore that version's frontend assets together with its API; reload
browser tabs to discard cached UI code. No schema rollback or database reset is
needed. Preserve the current SQLite database and `.env`; restore a database backup
only for a separately diagnosed data problem after stopping writers. Review the
independent existing integration queues rather than deleting them.
