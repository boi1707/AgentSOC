# Exact Shuffle workflow setup: commands, buttons and delivery

Status: code and mocked HTTP flows tested locally. **No native workflow was imported and no live
Shuffle/Telegram workflow was installed.** The installed Shuffle version/export schema is unknown;
this node guide is the supported template. Do not invent a version-specific export JSON.

Provision the existing AgentSOC configuration from `.env.example`: `SHUFFLE_HOOK`, independent
`SHUFFLE_CALLBACK_SECRET`, `TELEGRAM_USERS` mapping to existing enabled local accounts,
`TELEGRAM_NOTIFY_CHATS=111,222`, and `PROPOSAL_TTL_SECONDS`. Keep `RESPONSE_MODE=dry-run`.
On Shuffle, use secret storage for the bot token, signing secret and a separate Telegram webhook
ingress secret. These sample chat/user IDs are placeholders. No real values belong in workflow source.

Copy `agentsoc_bridge.py` into an importable helper module for the workflow Python runner. If your
Python app cannot import a mounted module, paste its pure helper definitions into its script step.
Pin/review the helper version with this release. It needs only Python's standard library.

## Workflow A: proactive notifications (node by node)

| Node | Input/action | Output and branch |
| --- | --- | --- |
| A1: authenticated private webhook | Endpoint referenced by `SHUFFLE_HOOK`. Accept only AgentSOC's WireGuard/private source, enforce TLS/private routing at the existing proxy, and reject public ingress. The legacy outbound protocol supplies event IDs but no HMAC identity. | Original JSON event; reject untrusted ingress before any Telegram calls. Never authenticate by `Idempotency-Key` alone. |
| A2: event validation | Accept only `proposal.created` / `response.completed`. Require `event_id`, `case_id`, recipient list and expected event-specific fields. | Reject malformed input. Optional important-only filter: pending `proposal.eligible` or Wazuh `priority >= 12`. Always deliver final result events. |
| A3: format and split recipients (Python) | `deliveries = notification_requests(event)` | A list of independent `{event_id, chat_id, body}` items. Text includes incident/proposal IDs, severity, source IP, AI explanation, evidence summary, expiry and mode. `reply_markup.inline_keyboard` contains Approve/Ignore buttons only for eligible versioned proposals. No `parse_mode`. |
| A4: per-recipient loop / atomic claim | For each item, `token = ledger.claim(event_id, chat_id)` | If token exists, go to A5. If `ledger.status(...) == 'delivered'`, skip sending. Otherwise retain failure/busy/unknown and go to A7. |
| A5: Telegram sendMessage app/HTTP node | Use the bot credential from secret storage. POST the exact `body` from A3 as JSON; preserve the nested `reply_markup` object. | On `ok=true`, take `result.message_id` and go to A6. Never log bot URLs or credentials. |
| A6: delivery commit (Python) | `ledger.finish(event_id, chat_id, token, 'delivered', message_id=message_id)` | CAS/fenced commit must return true. For a known nonaccepted request, finish as `retry`. For a timeout, ambiguous 5xx, executor crash or lost acknowledgement, finish as `unknown`; do not automatically resend. |
| A7: aggregate / webhook reply | After all recipients, check each ledger status. | If all are `delivered`, return HTTP 200 `{"success":true}`. Otherwise return HTTP 503 `{"success":false}`. Never return success after only one chat succeeds. |

Example Python A3/A4 initialization, using a persistent **local** filesystem shared by this workflow's
executors on the same host:

```python
from agentsoc_bridge import DeliveryLedger, notification_requests

ledger = DeliveryLedger("/var/lib/agentsoc-shuffle/delivery.sqlite3")
deliveries = notification_requests(event)
# Loop each item through nodes A4-A6; carry the opaque claim token to the commit node.
```

This is a delivery ledger only, not an incident or approval database. Mount its directory persistently;
an ephemeral Python runner directory or process-global dictionary is not sufficient. SQLite locking
must operate on one local filesystem. For executors spread across hosts, use the installed platform's
transactional durable store with unique `(event_id, chat_id)` and atomic claim/fencing instead of
sharing a SQLite file over a network filesystem. If neither is available, keep the workflow disabled
until durable recipient state is provisioned.

AgentSOC retries the same event, with the original persisted recipient snapshot, using bounded
backoff and ten attempts. A successful first recipient is skipped when the second recipient retries.
An expired `sending` lease becomes `unknown`. After inspecting an ambiguous delivery in Telegram,
an operator must reconcile its ledger row; explicitly resending can duplicate a physical message.
Unknown or permanently failing events ultimately need manual handling after AgentSOC dead-letters
them. Never replay the approval to repair a message.

## Workflow B: authenticated Telegram commands and buttons (node by node)

| Node | Input/action | Output and branch |
| --- | --- | --- |
| B1: Telegram webhook / proxy | Configure Telegram's webhook `secret_token`. Preserve the raw update JSON and `X-Telegram-Bot-Api-Secret-Token` header. Require HTTPS. | Reject if missing/incorrect **before** creating a signed AgentSOC request. If the Shuffle webhook hides headers, validate at a trusted proxy and restrict downstream ingress to that proxy. A hidden webhook URL is insufficient. |
| B2: validate, normalize and sign (Python) | Call `trusted_callback_request(headers, update, webhook_secret, signing_secret, language='vi')`. | Exact raw UTF-8 body string plus HMAC headers. Text commands use `message.from.id`; inline callbacks use `callback_query.from.id`, never the bot's message author. |
| B3: AgentSOC HTTP request | POST to the private `/api/v1/integrations/telegram` URL. Use returned headers and exact raw body bytes/string, not a JSON object that the HTTP app reserializes. Verify TLS. | Require successful authentication; check JSON `error` even on HTTP 200. HTTP 401/403/409 are not approvals. |
| B4: callback acknowledgement | For inline callbacks, use Telegram `answerCallbackQuery` with the original `callback_query.id` and a short receipt/denial text. | This only removes the Telegram spinner. Ack failures must not create a new update ID or re-execute a decision. |
| B5: command reply formatting | Use `query_reply(result)`. Send the resulting object as JSON to Telegram `sendMessage`, including nested `reply_markup` when present. Leave `parse_mode` unset. | Check HTTP 2xx and Telegram `ok=true`. The legacy standard approval returns a receipt; workflow A sends its final result. Copilot previews can include signed intent buttons. If no inline buttons can be forwarded, the preview text includes the explicit confirmation command. |

```python
prepared = trusted_callback_request(
    ingress_headers, original_telegram_update, webhook_secret, signing_secret, language="vi"
)
# B3: HTTP POST raw body=prepared['body'], headers=prepared['headers'].
# Do not place any secret in the callback URL or Telegram callback_data.
```

Investigation commands such as `/incidents`, `/pending`, `/review 24h`, `/incident <id>`, and `/why <id>` require a private bot chat. Group chats retain `/status`, help, and legacy `/approve <incident_id> <proposal_id>` and `/ignore <incident_id> <proposal_id>` (`/reject` alias) for authenticated mapped approvers. Group chats cannot open private threads or confirm Copilot intents.

Inline callback data is `as:a:<analysis_run_id>` or `as:i:<analysis_run_id>` (37 ASCII bytes for the
existing 32-character run IDs, below Telegram's 64-byte limit). Private Copilot preview buttons use
`ac:a:<intent_id>` or `ac:i:<intent_id>`. The bridge signs `/callback` plus
`callback_data` and `callback_query_id`. AgentSOC resolves the run to its incident, rechecks that
it is the current completed non-replay analysis, and validates expiry/role/protected IP/pending state
in the shared atomic approval flow. A message's old eligibility label or attacker-edited text grants
no authority. Legacy incidents without a versioned run do not receive inline approval buttons.

The original Telegram `update_id` is the replay key, including for buttons. On HTTP retry, resend
the same body, optionally with a freshly signed timestamp. Do not change the update ID, sender, chat,
language or serialization to bypass a receipt conflict. An in-progress receipt after a crash requires
incident-state inspection. Cached results do not cause another action or result event.

## Required operator checks in a real lab

1. Confirm B1 rejects missing/forged ingress secrets, and the signing step cannot be reached directly.
2. Map a real approver, second approver and viewer to enabled local AgentSOC accounts. Keep both
   notification chat IDs separate. A notification-only chat/user must fail approval.
3. Send a pending fixture through A1-A7 to both test chats. Check severity, source, explanation,
   evidence and both buttons. Compare incident/run IDs with Web.
4. Click Approve as the authorized person. Verify `dry_run`, `blocked=false`, `not_verified`, one
   action/claimed transition, attributed actor and one logical result event. Check the same status
   through Web and `/incident` in the private test chat. Race a second operator and Web against the same proposal.
5. Test Ignore, expiry/stale run, invalid HMAC, expired timestamp, duplicate update and changed-content
   update reuse. None may create duplicate mitigation actions.
6. Fail one recipient delivery before acceptance; retry the same event and verify only that recipient
   sends again. Test a lost acknowledgement separately: physical exactly-once delivery is not promised.

These manual checks are **REQUIRES LIVE LAB**. Local pytest coverage uses ASGI/SQLite plus mocked
Shuffle/Telegram HTTP and is classified **MOCKED**, not a live workflow validation.

## Copilot staging acceptance

1. In an isolated Shuffle workflow, run nodes B1–B5 with the updated bridge and a test bot. Verify the outbound `sendMessage` JSON retains the nested `inline_keyboard`, the bot renders both buttons, and the API returns `ok=true` with a `message_id`.
2. Link a Web thread to a mapped private test account. Ask a follow-up in Telegram and check its cited incident and history in Web. From a group, attempt the same query and thread link. Expect a refusal with no history or evidence in the reply.
3. Use a legitimate received lab incident whose stored verdict is `review`. Prepare a manual response with human justification. Typing Approve without selection must present no control. Use `/select INTENT_ID`, type Approve, and verify that only the selected intent can be confirmed.
4. Click the delivered button with a valid identity. Repeat the same callback, retry from Web, and try a forged and an expired callback. Verify exactly one dry-run action, `blocked=false`, and one result outbox event. Repeat with Reject on a fresh incident.
5. Compare the case status in Web, Telegram and the same TheHive remote case. Verify the original Judge verdict before and after. Run migration and rollback on disposable database copies as described in the [Copilot guide](../../docs/UNIFIED_COPILOT.md#deployment-and-rollback).
