# Shuffle integration templates (manual setup required)

Phase 2 adds versioned inline buttons and a persistent recipient-delivery helper. Follow the exact
[node-by-node workflow guide](WORKFLOWS.md) for the current setup, retry branches and trust boundaries.

These are integration templates, **not an exported or deployed Shuffle workflow**. The repository has
no versioned workflow format or live Shuffle instance to validate an import against. Use the pure
Python helpers in `agentsoc_bridge.py` in your instance's Python steps. Keep all credentials in
Shuffle secrets, never workflow URLs, source control, logs, or Telegram messages.

## Inbound: Telegram → Shuffle → AgentSOC

1. Configure a dedicated Telegram bot webhook with a random `secret_token`. At the Shuffle ingress
   or its trusted reverse proxy, require HTTPS and verify `X-Telegram-Bot-Api-Secret-Token` with
   `verify_telegram_ingress`. Reject requests before processing if it is absent or wrong. Preserve
   the original Telegram JSON and headers. If your Shuffle webhook does not expose headers, perform
   this validation in its reverse proxy and restrict Shuffle ingress to that proxy. **Do not enable
   approvals until ingress validation is proven.** A hidden webhook URL alone is insufficient.
2. Populate `TELEGRAM_USERS` on AgentSOC with numeric Telegram user IDs mapped to existing enabled
   local usernames. Assign approver/admin roles using the existing local user management UI/API.
   A viewer may inspect records but cannot approve. Telegram usernames and chat IDs grant no rights.
3. Store the same independent 32+ character `SHUFFLE_CALLBACK_SECRET` on AgentSOC and Shuffle.
   This secret must differ from the Telegram webhook secret, bot token, ingestion key, and approval key.
4. Feed original headers and update to `trusted_callback_request(headers, update, webhook_secret, secret, language="vi")`.
   POST the returned **exact UTF-8 body string** (no JSON reserialization) and headers to
   `https://<private-agentsoc>/api/v1/integrations/telegram`. Verify TLS; use WireGuard/private ingress
   and restrict this endpoint to Shuffle. Sign `timestamp + '.' + raw_body` with HMAC SHA-256.
   AgentSOC permits five minutes of clock skew. Keep both systems synchronized.
5. Route the JSON reply through `query_text`; send plain text only to its returned `chat_id`.
   Use the current helper: conversational replies prioritize the shared labelled fallback
   or validated interpretation and include citation references, never normalized evidence JSON.
   See [focused assistant fallback](../../docs/ASSISTANT_FOCUSED_FALLBACK.md). Updating source does
   not automatically update the Python step of your deployed Shuffle workflow.
   Do not set Telegram `parse_mode`. Use the bot token in the Telegram app's secret credential field.
   Do not forward raw HTTP errors, server configuration, or full API JSON directly into a group chat.
6. Use `/status`, `/incidents` (last 24 hours), `/dangerous`, `/pending`, `/review 24h`, `/incident <id>`, `/why <id>`,
   `/approve <incident_id> <proposal_id>`, `/ignore <incident_id> <proposal_id>` (`/reject` is an alias).
   Query results include the exact proposal ID needed for a decision. Inline Approve/Ignore buttons
   reference the current analysis-run ID; arbitrary natural-language decision parsing is absent.

The callback receipt uses Telegram's original `update_id`. Retrying the same body returns the stored
result without dispatching again; changing a reserved update ID returns 409. Re-sign the same body
with a fresh timestamp on a later retry. A crashed in-progress request returns 409 for manual inspection;
never create a new update ID to retry mitigation. AgentSOC rechecks current user role on every request.

## Outbound: AgentSOC outbox → Shuffle → two Telegram chats

1. Configure `SHUFFLE_HOOK` using the existing webhook delivery integration. Protect the receiving
   Shuffle endpoint at private ingress; this outbound legacy protocol does not add an HMAC signature.
   Configure `TELEGRAM_NOTIFY_CHATS=111111,-222222` on AgentSOC. These IDs are independent of operators.
   With this option enabled, analysis notifications use the durable Shuffle outbox instead of the
   legacy direct bot notification path.
2. Accept `proposal.created` and `response.completed` events. Authenticate ingress before delivery.
   For important-only notifications, filter proposals by `proposal.eligible` or `priority >= 12`.
   Queue one send for each unique `(event_id, notification_recipients[i])`. Persist this identity in
   a durable store supported by your Shuffle installation; serialize sends for the same identity.
   Do not keep incident state or approval authorization in Shuffle.
3. Format with `notification_requests` to include text and inline buttons for each chat. Only
   approvers listed in AgentSOC can use the command examples. Receiving the message grants no role.
4. Return HTTP 2xx with `{"success":true}` **only after durable acceptance** of all recipient sends;
   otherwise return a failure so AgentSOC retries. Store per-recipient delivery status to avoid
   resending to a successful recipient after a partial failure. Preserve the AgentSOC event ID.
5. The inbound decision reply is a receipt; send the final status only from `response.completed`.
   Poll incident details in the Web UI (already every 15 seconds) for the same authoritative state.

AgentSOC creates one logical result event per action. HTTP and Telegram delivery are at least once.
Telegram does not participate in the AgentSOC database transaction: a lost acknowledgement after a
successful send can still duplicate a physical message. Do not claim exactly-once Telegram delivery.
After ten failed outbox attempts, inspect the redacted error and fix delivery before explicitly
requeuing that same event ID. Never replay an approval to retry a notification.

## Manual validation

Use a disposable bot and two test chats first. Verify unsigned, expired, spoofed-sender and non-approver
requests fail; compare Web/Telegram proposal IDs; race one Web approval against one Telegram approval;
confirm one action and one logical result event, `status=dry_run`, `blocked=false`; retry a delivery
failure with the same event ID. No live Shuffle or Telegram deployment was performed by this change.
