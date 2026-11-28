# Unified Web and Telegram Copilot

Web sessions and signed, mapped Telegram identities use the same SQLite conversation service and evidence assistant. The model produces analysis only. Explicit response intents and confirmation use a separate server-side policy with a dry-run adapter.

## Conversations

The Web conversation menu supports resuming, renaming, archiving and restoring threads. Navigation updates the context for the next question. Replies stay in the thread where the question was sent. **Older messages** loads the next page without dropping it when the latest page refreshes. Start or select a conversation before composing a draft. Drafts are saved in SQLite after redaction, are visible only to the Web account that owns the thread, and reload with the conversation. The browser stores only the last thread identifier. **Draft saved** confirms the server received it. Offline edits that never reach the server can be lost when the page closes. Review any redaction placeholders before sending a restored draft.

In a private bot chat, use **/new**, **/history**, **/use THREAD_ID**, **/analyze INCIDENT_ID** or send a follow-up question. To continue a Web thread, choose **Link Telegram** and send **/link CODE** to the private bot within five minutes. The signed Telegram sender must map to the local account that owns the thread. Telegram threads appear in Web history for that account. **/clear** archives the selected thread.

| Telegram chat | Available capabilities |
| --- | --- |
| Private chat with the bot | Incident queries, persistent threads, Web linking, action previews and explicit Copilot confirmations. |
| Group or channel | Help, operational status, and existing signed standard-response commands and notification buttons for mapped approvers. Incident queries, free-form Copilot chat, linking and Copilot intent controls are refused. Existing configured notifications are visible to group members, so only configure groups approved to receive them. |

There are limits of 100 threads per account, 120 exchanges per thread and 2,000 characters per message. Archived threads count toward the limit. The API can delete threads without response history. Action-bearing threads can be archived and retained for audit. The model history includes at most four previous questions about the same incident. Known secrets and recognized sensitive text are redacted. Conversation answers retain citation references without storing normalized payloads.

## Dry-run confirmation

Ask to prepare containment, open **Prepare response** in Web, or use **/prepare** for standard policy and **/prepare JUSTIFICATION** for manual review in Telegram. To use conversational confirmation, choose **Select for chat** on the Web card or use **/select INTENT_ID** in private Telegram. Typing **Approve** or **Reject** shows a confirmation control only for that explicitly selected, current prepared intent. The operator must still press the bound control or send **/confirm INTENT_ID approve|reject**. A conversation switch in Telegram clears the selection.

- **Standard** retains the existing requirements for verdict, confidence, grounding, cited source, protected networks and current proposal.
- **Manual analyst** requires a stored review verdict and a human-written justification. The server checks that a single source and its traffic direction match original received Network evidence in the frozen run. The target must pass the existing lab allowlist and protected-address checks.
- Both require an enabled approver or administrator. An intent expires after at most 15 minutes and cannot outlive its run proposal. The dry-run plan is capped at 24 hours. One SQLite transaction revalidates policy and persists the result, audit and existing response outbox. Duplicate confirmations against a consumed intent return the existing result.

## Web API

All paths below are relative to **/api/v1/assistant/threads** and use existing session and CSRF protection.

| Method and path | Contract |
| --- | --- |
| GET / | List owned threads with limit and offset. |
| POST / | Create with optional title and incident_id. |
| GET /{thread} | Get thread metadata, saved draft, messages, and current response cards. Use limit and before for older messages. |
| PATCH /{thread} | Rename, update incident context, archive, or restore. |
| DELETE /{thread} | Delete a thread without response audit history. |
| PUT /{thread}/draft | Save bounded content and an increasing revision. Older requests cannot overwrite newer drafts. |
| POST /{thread}/messages | Submit message, language, optional incident_id, optional selected_intent_id, and request_key. Reuse the same key and payload for a retry. |
| POST /{thread}/telegram-link | Issue a five-minute, one-time private bot link. |
| POST /{thread}/actions | Prepare standard or manual_analyst intent with optional incident_id, justification and ttl. |
| POST /{thread}/actions/{intent} | Confirm the exact intent with decision approve or reject. |

Shuffle can forward the plain-text message and optional reply_markup from **query_reply(result)**. **query_text(result)** remains compatible and includes explicit textual confirmation commands. Stage workflow changes separately before updating a running integration.

## Deployment and rollback

Migration v5 adds seven tables without rewriting the incident or action schema. Run `python -m pytest -q tests/test_copilot_staging.py` for the isolated acceptance exercise. It starts from a disposable database generated by the exact v4 source, uses the real signed bridge with mocked Telegram and TheHive HTTP, verifies both button decisions and duplicate handling, then starts the v4 application on a backup of the populated v5 database. This is separate from live Shuffle workflow acceptance.

For staging, start API and worker on the same disposable SQLite copy with `RESPONSE_MODE=dry-run` and `PFSENSE_LIVE_ENABLED=0`. Use a test bot, dedicated Shuffle ingress, and isolated TheHive case space. Run the [workflow acceptance checks](../integrations/shuffle/WORKFLOWS.md#copilot-staging-acceptance). Capture the build revision, case/run/intent/action IDs, Telegram delivery receipt, duplicate count, and TheHive case ID. For rollback, back up the populated v5 state and start the last known-good API and worker images together against a copy. Verify readiness, original verdict and action retention, and health of the legacy workflow. Retain the original v5 backup for conversation and audit recovery.

## Future pfSense enforcement

Live writes require a separately approved design with conditional writes or independently enforced ownership, a dedicated alias, fresh target and evidence checks, durable leases and TTL, owned-only removal, restart reconciliation, and independent checks of rule application and observed traffic. The read-only REST adapter can inspect alias and runtime state. The current contract does not establish conditional updates or traffic-level verification. Keep writes disabled unless those capabilities are verified against the exact deployed pfSense API.
