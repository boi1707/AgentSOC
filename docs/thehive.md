# TheHive 5 integration

The optional mirror sends newly completed non-replay investigations to TheHive 5's
`/api/v1/case` API. The existing AgentSOC approval and gateway policy remain the
source of response decisions. Nothing in this integration executes blocking.

## Configure and deploy

1. Back up the AgentSOC SQLite database using SQLite's backup API, and copy the
   deployment `.env` before upgrading. Do not copy a live SQLite file with `cp`.
2. Create an unlocked TheHive Service account in the intended organisation with
   case create/update/read permissions (the built-in analyst profile can be used
   for a lab). Test `/api/v1/user/current` and case creation first.
3. Set both `THEHIVE_URL` and `THEHIVE_KEY` in the deployment `.env`. Keep that file
   mode 600 and out of git. For this WireGuard lab the URL is
   `http://10.8.0.1:9000`. Use HTTPS for networks that are not trusted.
4. Verify `/api/v1/query` with a `listCase` pipeline and tag filter using the same
   account before deployment. The synchronizer deliberately refuses to create a
   case when the reconciliation query fails.
5. Build the new images first: `docker compose build`. Then recreate only
   `agentsoc-backend` and `agentsoc-worker` with `docker compose up -d`.
   Leave the existing data bind mount and Wazuh stack intact.

## Behavior and recovery

An additive `thehive_sync` SQLite table records case IDs, remote IDs, hashes,
leases and retry state. Completion and queue insertion share the same transaction.
Existing cases from before this upgrade are **not automatically backfilled**.
Use `python -m scripts.integrations --db PATH --case CASE_ID --queue-case` for explicit opt-in backfill.
New completed cases (including analysis failures requiring review) are queued.
Demo mode and replay runs do not trigger remote creation.

The worker checks one due entry per tick, cycling entries with a 60-second retry
interval. Its network operations occur after the local investigation transaction,
with 5-second HTTP timeouts. A TheHive outage does not change the local verdict or
approval status. At most three HTTP calls are made for an entry in one cycle.

The remote description mirrors the current verdict, evidence IDs and response
status (including dry_run, rejected, blocked or block_failed); it does not create
separate TheHive comments, tasks or observables. Changes are picked up on a later
poll. Human edits to the managed description may be replaced on the next local
change. The remote case status is not automatically closed.

Each remote case has tag `agentsoc-id:<local-case-id>`. Before creating, the worker
queries for this tag. It persists `creating` **before** sending the POST. If a
response is lost or a process crashes after that checkpoint, subsequent cycles
only reconcile and never blindly repeat the POST. This favors avoiding duplicates:
an ambiguous operation that never reached TheHive requires manual investigation.
Multiple matches are also left for manual review. Do not delete the reconciliation
tag or reuse this database/key against another TheHive organisation/instance
without reviewing the saved mappings.

A failed reconciliation query never clears an ambiguous `creating` checkpoint,
including authentication and rate-limit errors. Queue checkpoints and completion
updates require the sender's current, unexpired lease; a stale sender cannot reset
the state saved by its successor. HTTP requests already in flight cannot be recalled.

Inspect state using a local read-only SQLite connection:
`SELECT case_id, remote_id, state, error FROM thehive_sync;`
Errors store only exception type/HTTP status, never response bodies or keys.
A 401/403 requires checking the service account/key/permissions. A failed query
or PATCH retries. After an ambiguous create, search TheHive for the exact tag
before any operator resets the row. No automatic reset/delete is provided.

Restoration of local identity tokens happens only for this trusted case mirror;
SECRET tokens and known credential values stay redacted. The TheHive key is also
included in AgentSOC's LLM egress scanning, UI scrubbing and operational log masks.
Identity restoration and credential redaction occur before JSON serialization, so
quotes, Windows paths and escaped secrets retain valid, redacted description content.

## Verify before calling deployment complete

- A new alert completes locally and produces exactly one case with the matching tag.
- Restart the worker and confirm no duplicate; approve/reject a test proposal and
  check its response status in the remote description (dry-run is not a real block).
- Stop TheHive, complete another local investigation, restart TheHive and check
  that its queued entry synchronizes without repeating analysis.
- Verify the case remains after a TheHive stack restart. Do not use `down -v`.

To disable integration set both variables empty and recreate the AgentSOC
containers. Pending mappings remain for later resumption. To roll code back,
redeploy the prior images/commit; the additive table does not require dropping
any data. Keep the database backup for recovery. Shuffle and VirusTotal are documented separately in `integrations.vi.md`.
