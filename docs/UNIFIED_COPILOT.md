# Unified Web and Telegram Copilot

Web sessions and signed, mapped Telegram identities use the same SQLite conversation service and evidence assistant. The model produces analysis only. Explicit response intents and confirmation use a separate server-side policy with a dry-run adapter.

## Conversations

The Web conversation menu supports resuming, renaming, archiving and restoring threads. Navigation updates the context for the next question. Replies stay in the thread where the question was sent. The browser keeps only the last thread identifier per account. Unsent drafts stay in memory while the signed-in console is open.

In a private bot chat, use **/new**, **/history**, **/use THREAD_ID**, **/analyze INCIDENT_ID** or send a follow-up question. To continue a Web thread, choose **Link Telegram** and send **/link CODE** to the private bot within five minutes. The signed Telegram sender must map to the local account that owns the thread. Telegram threads also appear in Web history for that account. **/clear** archives the selected thread. Group chats cannot open, link, or read persistent private threads or confirm Copilot intents. Existing stateless group commands still post to the group and should only be used in authorized chats.

There are limits of 100 threads per account, 120 exchanges per thread and 2,000 characters per message. Archived threads count toward the limit. The API can delete threads without response history. Action-bearing threads can be archived and retained for audit. The model history includes at most four previous questions about the same incident. Known secrets and recognized sensitive text are redacted. Conversation answers retain citation references without storing normalized payloads.

## Dry-run confirmation

Ask to prepare containment, open **Prepare response** in Web, or use **/prepare** for standard policy and **/prepare JUSTIFICATION** for manual review in Telegram. Confirm on the specific preview with Web buttons, Telegram inline buttons, or **/confirm INTENT_ID approve|reject**. Free-form approval never authorizes execution.

- **Standard** retains the existing requirements for verdict, confidence, grounding, cited source, protected networks and current proposal.
- **Manual analyst** requires a stored review verdict and a human-written justification. The server checks that a single source and its traffic direction match original received Network evidence in the frozen run. The target must pass the existing lab allowlist and protected-address checks.
- Both require an enabled approver or administrator. An intent expires after at most 15 minutes and cannot outlive its run proposal. The dry-run plan is capped at 24 hours. One SQLite transaction revalidates policy and persists the result, audit and existing response outbox. Duplicate confirmations against a consumed intent return the existing result.

## Web API

All paths below are relative to **/api/v1/assistant/threads** and use existing session and CSRF protection.

| Method and path | Contract |
| --- | --- |
| GET / | List owned threads with limit and offset. |
| POST / | Create with optional title and incident_id. |
| GET /{thread} | Get thread metadata, messages, and current response cards. Use limit and before for older messages. |
| PATCH /{thread} | Rename, update incident context, archive, or restore. |
| DELETE /{thread} | Delete a thread without response audit history. |
| POST /{thread}/messages | Submit message, language, optional incident_id, and request_key. Reuse the same key and payload for a retry. |
| POST /{thread}/telegram-link | Issue a five-minute, one-time private bot link. |
| POST /{thread}/actions | Prepare standard or manual_analyst intent with optional incident_id, justification and ttl. |
| POST /{thread}/actions/{intent} | Confirm the exact intent with decision approve or reject. |

Shuffle can forward the plain-text message and optional reply_markup from **query_reply(result)**. **query_text(result)** remains compatible and includes explicit textual confirmation commands. Stage workflow changes separately before updating a running integration.

## Deployment and rollback

Migration v5 adds five tables without rewriting the incident or action schema. Validate the upgrade against a disposable SQLite copy and take a verified backup before deployment. Test Web and mapped private Telegram flows on isolated staging. Keep dry-run and live pfSense disabled. Verify both backend and worker use the same database. For rollback, back up the new state and restore the previously tested API and worker images together. Older images ignore the additive tables. Retain the v5 backup for conversation and audit recovery.

## Future pfSense enforcement

Live writes require a separately approved design with conditional writes or independently enforced ownership, a dedicated alias, fresh target and evidence checks, durable leases and TTL, owned-only removal, restart reconciliation, and independent checks of rule application and observed traffic. The read-only REST adapter can inspect alias and runtime state. The current contract does not establish conditional updates or traffic-level verification. Keep writes disabled unless those capabilities are verified against the exact deployed pfSense API.
