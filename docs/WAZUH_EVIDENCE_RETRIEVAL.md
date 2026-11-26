# Scoped Wazuh Indexer evidence retrieval

The investigation worker can look up Sysmon process lineage when a forwarded alert has a process GUID but the supporting process creation event has not been forwarded. Retrieval is optional and disabled by default. It adds evidence to the investigation run without creating an inbox record, a case, or an action.

## Configuration

| Worker setting | Default | Accepted values |
| --- | --- | --- |
| `WAZUH_RETRIEVAL_ENABLED` | `0` | Set to `1` to enable. Demo and synthetic cases are excluded. |
| `WAZUH_INDEXER_URL` | Empty | HTTPS origin with a DNS hostname and optional port. Credentials, paths, query strings, and fragments are rejected. |
| `WAZUH_INDEXER_USERNAME` | Empty | Dedicated search-only reader identity. |
| `WAZUH_INDEXER_PASSWORD_FILE` | Empty | Readable file mounted into the worker. Initial validation checks that a path is configured. Read errors produce a sanitized retrieval failure at runtime. |
| `WAZUH_INDEXER_CA_FILE` | Empty | Mounted root CA used for chain and hostname verification. Invalid CA material produces a sanitized retrieval failure. |
| `WAZUH_INDEXER_INDEX_PATTERN` | `wazuh-alerts-*` | This exact pattern is the only accepted value. |
| `WAZUH_RETRIEVAL_TIMEOUT_SECONDS` | `3` | Shared network deadline from 0.05 to 3 seconds. |
| `WAZUH_RETRIEVAL_WINDOW_SECONDS` | `120` | From 1 to 120 seconds before the primary event. |
| `WAZUH_RETRIEVAL_MAX_ALERTS` | `20` | From 1 to 20 returned records across queries, limited by the free slots under `CAP`. |
| `WAZUH_RETRIEVAL_MAX_QUERIES` | `3` | From 1 to 3. The current lineage search performs at most two queries. |

The worker sends only POST searches to the fixed `/wazuh-alerts-*/_search` endpoint and refuses partial results. It disables redirects and environment proxies, verifies TLS, and uses Basic authentication. A request is limited to 4 KiB and each uncompressed response to 512 KiB. The retained normalized context is limited to 48 KiB in addition to the existing prompt limits. Review the shipped mapping and verify your staging index uses compatible field types. [Wazuh 4.9 index template](https://raw.githubusercontent.com/wazuh/wazuh/v4.9.0/extensions/elasticsearch/7.x/wazuh-template.json)

## Evidence lifecycle

1. A normal inbox alert triggers a case. The worker reserves retrieval for a new non-synthetic run, using only primary alert IDs from its initial snapshot and linked inbox rows for the configured `WAZUH_SOURCE_ID`.
2. The worker selects the first eligible Sysmon anchor in snapshot order. It requires an original Wazuh alert ID, manager, agent ID and name, verified endpoint fields, a timezone-aware timestamp, and a valid process GUID. The fixed query uses those endpoint fields and seeks Sysmon Event ID 1 with the same GUID before or at the anchor time and within the run cutoff.
3. The worker independently validates the index name, manager and endpoint, provider, time bounds, event ID and GUID of every hit. It can make one parent lookup when matching process creation evidence gives a consistent parent GUID. A primary Event ID 1 can supply the parent GUID directly. The parent cannot occur after the child, and the search never follows grandparents.
4. It deduplicates by Wazuh source and original alert ID before a row can supply a parent relationship. The run stores normalized rows in `indexer_context` and provenance in `indexer_provenance`. The current evidence tool combines them with the primary rows for analysis. The stored `alerts` list remains primary-only so the previous worker cannot mistake retrieved rows for primary evidence during rollback. Provenance includes source, index, endpoint, original ID, event time, retrieval time and correlation reason.
5. Retrieval is finalized before the first analyst reads that run. The existing run JSON and audit log store the frozen snapshot and sanitized counters. A job lease and one-time reservation prevent stale workers from replacing it. Retries reuse finalized evidence. If a worker dies after reserving the lookup, recovery finalizes the primary snapshot as interrupted instead of making a fresh lookup. Replay copies the stored snapshot and cutoff and does not contact Indexer.

New retrieval-enabled runs record prompt version `net-host-judge-v4`. The Host Agent and Judge distinguish contextual and primary alerts. Contextual IDs can be cited when they passed validation. Prior investigations and related local alerts remain non-citable history. An attack verdict still requires support tied to primary evidence in a current analyst finding. Only the original current network evidence can supply an eligible containment target, and the existing human approval gate applies.

The Indexer response is projected to an explicit allowlist before normalization. Commands and descriptions remain untrusted log data, and the existing anonymization and egress guard apply before provider calls. Index and endpoint provenance is stored separately from the model payload. The client keeps connection material out of snapshots and errors, and drops contextual evidence that would fail the privacy preflight. Pattern-based redaction still has the limits of the existing privacy policy.

No match, exhausted capacity, missing anchor, interrupted collection, authentication, rate limits, malformed or partial responses, timeout, TLS and connection errors have distinguishable outcomes. Failure uses the original primary evidence. No match can reflect ingestion lag, field mapping differences, an ineligible endpoint or the search bounds. It does not establish that a process event never happened. Duration, query and record counts, and accepted correlation reasons are stored independently of model timings.

## Future staging configuration

Use a worker-only Compose override in an isolated staging project. Keep the feature disabled in shared production configuration. The example is for a separately approved staging exercise. It shows the pre-existing reader account and the hostname that matches the certificate SAN.

```yaml
services:
  agentsoc-worker:
    extra_hosts:
      - "wazuh.indexer:10.8.0.1"
    environment:
      WAZUH_RETRIEVAL_ENABLED: "1"
      WAZUH_INDEXER_URL: "https://wazuh.indexer:9200"
      WAZUH_INDEXER_USERNAME: "agentsoc_reader"
      WAZUH_INDEXER_PASSWORD_FILE: "/run/agentsoc-indexer/password"
      WAZUH_INDEXER_CA_FILE: "/run/agentsoc-indexer/root-ca.pem"
      RESPONSE_MODE: "dry-run"
      PFSENSE_LIVE_ENABLED: "0"
      VT_SHA256_ENABLED: "0"
    volumes:
      - /etc/agentsoc/wazuh-indexer/staging-reader-password:/run/agentsoc-indexer/password:ro
      - /opt/soc/wazuh-docker/single-node/config/wazuh_indexer_ssl_certs/root-ca.pem:/run/agentsoc-indexer/root-ca.pem:ro
```

Grant the worker running as UID 10001 read access to only these two files. The existing production password at `/etc/agentsoc/wazuh-indexer/password` is root-owned with mode `0600` and stays in place. Have the authorized secret provisioner create a separate staging file owned by the worker's mapped UID with mode `0400`, or use a root-owned file with mode `0440` and a dedicated mapped group. Verify the effective GID before using group permissions and keep the parent credential directory restricted. Use a read-only staged copy of the root CA if the original file is inaccessible to the service account. Verify access from the non-root worker and keep the password out of Compose, environment variables and diagnostics. Mount no admin certificate or private key. The override needs no additional ports, privileges or Docker socket. The existing role need only search `wazuh-alerts-*`.

Stage with a disposable database and sanitized alerts first. Check TLS identity and the exact search against the target Wazuh 4.9 mappings, then verify the two lineage links and the cutoff in the run snapshot. Measure worker timings under load and check that a temporary Indexer outage still completes investigations. To turn off retrieval, disable the worker flag and remove the two mounts in the staging override. There is no schema migration or historical snapshot rewrite. A rollback image check on a staging DB copy remains advisable before any production rollout.

## Local implementation verification

The repository started with a clean `feat/ai-core-evidence-hardening` checkout at `7ad131ac8df47e285e0e57b3d9eff1516024b439`. After fetch, `origin/main` was `4b6c461447acc3ee4a9ef232871ba02fb2a94f2a`. The new work is local and uncommitted on `feat/wazuh-evidence-retrieval`. Local validation uses Python 3.12.13 and the installed `requirements-dev.lock` dependencies.

| Check | Result |
| --- | --- |
| Baseline Python suite on fetched main | 400 passed, 1 skipped in 77.44 seconds |
| Original implementation before security preflight | 454 passed, 1 skipped, 1 warning in 123.47 seconds |
| Ruff, offline replay | Passed |
| Frontend dependency install, lint, typecheck, production build | Passed |
| Playwright | 3 passed |
| Docker build and live Indexer/VPS | Unexecuted. The local machine has no Docker CLI. |

The mocked fixture uses fictional endpoint identities, process GUIDs, commands and a hash. It checks the two lineage lookups, wrong manager/source/endpoint/GUID, time bounds and deduplication, privacy, pagination-free size and time limits, durable failure state, replay, and containment eligibility. The full regression suite includes the existing SQLite migration and rollback fixtures, Assistant, Telegram, Shuffle, TheHive and pfSense. Schema version remains 4 and evidence normalization remains version 2. Existing warnings include the Starlette/httpx deprecation and npm's ESLint deprecation. The paid provider test remains skipped.

The settings, worker and snapshot changes are in `src/settings.py`, `src/service.py`, and `src/storage.py`. The fixed search client is in `src/wazuh_retrieval.py` and model integration is in `src/agents.py` and `src/llm.py`. Example configuration and documentation are in `.env.example`, `README.md` and this guide. The fixture and tests are `tests/fixtures/wazuh_indexer_lineage.json` and `tests/test_wazuh_retrieval.py`.

The search is intentionally limited to one eligible anchor and one parent. Results can be lost to Indexer lag, field or naming differences, or lack of free evidence slots. The three-second deadline limits network collection, while scheduling, local file access and storage work contribute separately to end-to-end latency. The 10–15 second end-to-end target and live Wazuh 4.9 query behavior still need measurement in staging.

See the [security preflight](WAZUH_EVIDENCE_PREFLIGHT.md) for exact sanitized requests, rollback evidence and updated test results after the security fixes.
