# Focused SOC explanation and stored-evidence fallback

Baseline: `013457e3face0e713765bd7194cfcab6805dca1a`.
Branch: `feat/assistant-focused-fallback`.
Date: 2026-11-26. This change does not deploy anything or modify deployment secrets.

## Confirmed problem and scope

Production reports show intermittent DeepSeek responses with HTTP 200,
`finish_reason=stop` and a valid JSON `interpretation` field, but only placeholder
text. Both attempts can fail. The baseline correctly rejects these completions;
it uses `invalid_output` for the failure and returns the retrieved facts. Its retry
still uses the same system instruction with a smaller context.

This change focuses the writing task rather than treating transport or prompt size
as the only cause. It does not claim to eliminate every model generation failure.
Local tests simulate the exact 24/25-character payloads
`{"interpretation":"..."}` and `{"interpretation": "..."}` with a `stop` finish reason.

## Prompt and privacy

The first instruction asks for a short SOC explanation: observed flow/protocol/rule,
stored verdict/confidence/rationale, and server approval eligibility/blocking reasons.
Vietnamese questions get an explicit Vietnamese writing task. The retry is a
different, shorter instruction asking for 2–3 sentences; it is not another copy of
the original instruction. It drops history, reduces context and does not quote the
failed response. User text, stored rationale and evidence remain untrusted data.

Canonical rules are deduplicated, without removing the full citations returned to
the authorized caller. The model receives at most 8 incidents on the first attempt
and 2 on retry; 3/1 distinct rules, 4/2 evidence IDs, and 500/220 rationale characters
per incident. Stored verdict, groundedness and eligibility remain server-owned.
Redaction and pseudonymization occur **before** model text is shortened, protecting
against a truncated credential or identity being sent as an unmatched prefix.

Strict JSON/envelope, finish-reason, refusal/tool-call and explicit-citation checks
remain. Interpretation is limited to 2,400 characters. ID lists and punctuation-only
or placeholder content are rejected; they produce the safe category
`model_error=placeholder_output`. Malformed/schema-invalid JSON remains
`invalid_output`; transport, HTTP, timeout and privacy errors retain distinct safe
categories. No raw provider text, exception message, prompt or credential is exposed.
These checks do not prove arbitrary natural-language claims true; model prose
remains separately labelled and has no authority to change incident state.

Maximum provider calls remain **two**, with cancellable 7/5-second production request
limits, a 15-second model-stage deadline, 65,536-byte response cap and 1,024-token
output cap. Database retrieval is outside the model deadline. No tools, shell,
approval or pfSense execution is added to the conversation path.

## Factual fallback and channel consistency

When no valid interpretation is available, the shared backend adds:

```json
{
  "interpretation": null,
  "model_status": "unavailable",
  "model_error": "placeholder_output",
  "model_attempts": 2,
  "fallback": {
    "origin": "stored_analysis",
    "label": "Stored analysis / Evidence-based summary",
    "text": "A deterministic summary of the retrieved case data.",
    "truncated": false
  }
}
```

The example describes the API shape; the actual summary uses the stored fields,
not this sample sentence. Fallback is also available in evidence-only/mock mode,
without a provider request. On a valid completion, `fallback=null` and
`model_error=null`; `interpretation` remains the actual validated model response.

Fallback contains flow, available protocol/rules/severity, stored verdict/confidence/
groundedness, a labelled rationale excerpt, actual eligibility/policy explanation
and evidence references. Missing observations are explicitly not recorded; absent
linked evidence is flagged instead of inferred from an unlinked snapshot. The
summary covers at most 3 incidents within 2,400 characters, with a truncation notice
when limited. Full retrieved facts/citations remain in the API response. This is
templated stored analysis, **not** a newly generated LLM interpretation or a new
verdict. Known credentials and vendor-secret patterns are redacted from the rationale.

Web displays `fallback.label` and `fallback.text` in a separate section. The Shuffle
`query_text` helper sends those exact fields first in the conversational Telegram
reply. It no longer serializes normalized evidence JSON, including for older
AgentSOC responses; citation references remain available. Valid model prose is
sent as AI interpretation; receipts, system status and notification delivery behavior
are preserved. Telegram text is still capped at 3,500 characters and has no parse
mode. HMAC, timestamp, operator mapping, callback dedupe and role checks are unchanged.

The deployed Shuffle workflow must use the updated `query_text` helper. The repository
does not update that live workflow automatically, and no real Telegram message was
sent during local verification. Legacy callback receipts keep their cached original
results; a new Telegram update retrieves the new response shape. Never clear receipts
or replay a decision to refresh an old conversational answer.

## Supplied ICMP case

The disposable regression database reconstructs incident
`5eb4b0f385fb4467b8d4046cb5d036cb`: source `10.100.27.10`, destination `172.22.50.10`,
protocol ICMP, Wazuh rule `100101`, level 7, stored verdict `benign`, confidence
`0.92`, groundedness `1`, blocking eligibility `false`. Even after two ellipsis
responses, the Vietnamese fallback explains the stored benign conclusion, that ICMP
alone does not establish an attack, and that blocking is not proposed. No production
incident or investigation was edited to construct this test.

## Validation and rollout

Local Windows checks on 2026-11-26: **308 passed, 1 skipped**; Ruff check/format
passed (70 files including integrations); `npm ci`, typecheck, lint and production
build passed; **3 Chrome browser tests passed**. The install audit reported zero
vulnerabilities. The opt-in paid-provider test remains skipped and the existing
Starlette/httpx deprecation warning remains. Docker CLI is unavailable locally;
the repository's isolated Docker CI gate supplies the runtime image check.

Run Python tests and Ruff using `requirements-dev.lock`; run frontend `npm ci`,
typecheck, lint, build and Playwright. The existing GitHub Actions workflow runs
Python 3.12/3.14, frontend/browser and the isolated Docker Python 3.12 image/rollback
gate on push/PR. See the PR's checks for results tied to the exact reviewed head;
local HTTP mocks do not certify a live DeepSeek or VPS deployment.

Tests cover both exact production payload shapes, a different shorter retry prompt,
placeholder→valid, two failures, repeated ID lists, single and multiple cases,
missing evidence, Vietnamese fallback, redaction before truncation, prompt injection,
shared Web/Telegram output and HMAC/authorization. Existing integration and managed
pfSense lifecycle tests remain in the full suite.

Operator-only release steps:

1. Back up deployment `.env` privately and use SQLite online backup; retain old image
   tags. Review the PR and CI checks before releasing.
2. Preserve integration configuration and secrets. Keep `RESPONSE_MODE=dry-run`
   and `PFSENSE_LIVE_ENABLED=0`. Build/recreate API and worker from the same reviewed
   version; no schema change or data reset is required.
3. Update the Shuffle Python `query_text` helper without changing ingress secrets,
   operator mapping or approval controls. Send no raw AgentSOC JSON to Telegram.
4. Verify Web/Telegram read-only questions using a new update ID, compare fallback
   labels/conclusions, and confirm the stored investigation/action history is unchanged.
   An optional live paid-provider test must be explicitly authorized by the operator.

Rollback API/worker/frontend together to baseline `013457e3...` and restore the prior
Shuffle helper version if necessary; refresh browser tabs. Preserve `.env`, SQLite
data and queues. There is no migration to undo. Do not reset callback receipts,
rerun approvals or restore a database merely to roll back a display/prompt change.
