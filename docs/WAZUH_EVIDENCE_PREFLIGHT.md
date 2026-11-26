# Wazuh evidence retrieval security preflight

**Recommendation: GO for a separate PR and staging review.** Production readiness remains unverified. The repository is `https://github.com/boi1707/AgentSOC.git`. The local feature branch is `feat/wazuh-evidence-retrieval`. Its HEAD and fetched `origin/main` both resolve to `4b6c461447acc3ee4a9ef232871ba02fb2a94f2a`. The review started with seven tracked modifications and four untracked feature files. The final changes are unstaged and uncommitted.

## Findings

| Severity | Finding | Correction and evidence |
| --- | --- | --- |
| Critical | None found in scope. | The Indexer method, target, query template, evidence intake and response approval are separate controls. |
| High | The previous worker reads the run's `alerts` array without classifying retrieved context. Storing context in that array removed the new grounding distinction during rollback. | Keep `alerts` primary-only, store context separately, and combine only in the current tool. An archived previous-release subprocess reopens the actual new fixture database and replays with only the primary citation. [Snapshot writer](../src/storage.py#L453) · [Evidence tool](../src/tools.py#L83) · [Rollback test](../tests/test_wazuh_retrieval.py#L570) |
| Medium | A duplicate returned alert could supply a parent GUID before it was rejected as duplicate or for lack of space. A Windows event time after the trigger could also pass when the trigger lacked `systemTime` and the run cutoff was later. | Reject primary and contextual ID collisions and enforce the retained byte budget before creating a parent candidate. Bound the Windows event time by the trigger and then the child, using the alert timestamp if the Windows timestamp is absent. [Correlation](../src/wazuh_retrieval.py#L334) · [Regression tests](../tests/test_wazuh_retrieval.py#L226) |
| Medium | A successful HTTP response with early termination or missing shard-completeness fields could be treated as complete evidence. | Request `allow_partial_search_results=false` and independently reject early termination, shard failures, malformed completion metadata and timeouts. [Response validation](../src/wazuh_retrieval.py#L214) · [Response tests](../tests/test_wazuh_retrieval.py#L366) |
| Low | The password file limit previously compared decoded length after stripping newlines. The retained-row limit also counted bytes before adding citation metadata. | Enforce the 4 KiB secret bound before decoding and trimming. Count each contextual row with its final citation ID and classification. [Secret loader](../src/wazuh_retrieval.py#L88) · [Row validation and budget](../src/wazuh_retrieval.py#L377) |

## Verified evidence flow and security

- Retrieval runs once during snapshot preparation for a lease-owned investigation. The configured local Wazuh source must match a linked primary inbox record. The response is tied back to that source through the configured Indexer and a matching manager, agent ID, agent name, and any anchor IP and computer name. Local Wazuh source IDs are not fields asserted by OpenSearch. Configure one trusted source per Indexer connection. A bare hostname, user, image name or PID cannot establish lineage. [Snapshot reservation](../src/storage.py#L416) · [Event matching](../src/wazuh_retrieval.py#L127)
- The first eligible host alert in snapshot order anchors collection. At most one same-process query and one parent query are supported. Conflicting accepted parent GUIDs suppress the parent hop. With a primary Event ID 1 and a valid parent GUID, the worker uses a direct parent query instead. Event timestamps must fit the backward correlation window and run cutoff. Timestamp strings must be timezone-aware. Source and original alert ID drive deduplication, and a namespaced citation ID cannot replace a primary ID. [Lookup scope](../src/wazuh_retrieval.py#L315)
- A single monotonic deadline wraps connection setup over the network, TLS, receipt of the streamed body, and the optional second request. Each request also receives the remaining HTTP and OpenSearch time budget. Request payloads are capped at 4 KiB, streamed responses at 512 KiB, and retained normalization at 48 KiB. The accepted records share the configured result budget and available evidence slots. Deeply nested or malformed JSON fails closed. The slow-body and two-query tests exercise cancellation with mocked I/O. Live network timing is unexecuted. Local file access, scheduling and database operations add separate elapsed time. [Deadline and limits](../src/wazuh_retrieval.py#L214) · [Mocked deadline tests](../tests/test_wazuh_retrieval.py#L387)
- Transport uses an HTTPS origin, configured CA and mandatory hostname verification. It reads a mounted reader password, uses Basic auth and disables redirects and inherited proxies. Only the fixed search API and fixed query structure are reachable. Normalization filters raw fields, the lookup rejects echoed connection material including the Basic token, and the existing privacy guard tests contextual rows before freezing them. Passwords are not stored as configuration values, audit fields or prompt input. Redaction of event data remains subject to the existing pattern-based policy. [Client and projection](../src/wazuh_retrieval.py#L276) · [Snapshot privacy preflight](../src/service.py#L227)
- HTTP 401, 403, 429, 5xx, TLS and connection errors, timeouts, malformed responses and no matches produce distinct sanitized metadata. If a lookup fails, the analysis receives primary evidence and the failure status. The code does not choose a benign verdict on retrieval failure. It does not retry the lookup indefinitely or create a new incident. [Failure handling](../src/wazuh_retrieval.py#L434)
- Snapshot state changes are fenced by the job owner, lease and attempt. Once frozen, a model retry reads the same snapshot. Provenance survives reopening the database. Historical runs are not rewritten. Retrieval-disabled runs retain primary-only behavior and prompt version v3. Current replay copies the stored snapshot and does not query Indexer. Schema remains SQLite v4 and normalization v2. [Snapshot and replay](../src/storage.py#L349)
- Host and Judge receive primary/contextual classification, while historical alerts and prior runs remain outside current citation IDs. A suspicious current analyst finding must cite primary evidence supporting an attack. Context remains host-role evidence and cannot be the source of a containment target. The response path still independently requires a cited primary network source and approver permissions. The model has no influence over the search endpoint or filters. No response, Assistant, Telegram, Shuffle or pfSense control was changed. [Grounding](../src/agents.py#L119) · [Network source guard](../src/response.py#L7) · [Approver route](../src/api/v1.py#L484)

## Wazuh 4.9 mapping review

The published v4.9 template defines `timestamp` as a date and `id`, `manager.name`, `agent.id`, `agent.name`, and `agent.ip` as keywords. It dynamically maps string fields to keyword, which covers the sampled Sysmon string paths in a default index. Staging must confirm the actual matching indices use these mappings. In particular, inspect the exact term fields `data.win.system.eventID`, `data.win.system.providerName`, `data.win.system.computer`, and `data.win.eventdata.processGuid`. `parentProcessGuid` is fetched from `_source` and validated locally. Its value feeds the next exact query on `processGuid`. The `id` mapping also needs sortable values across the matching indices. [Wazuh v4.9.0 index template](https://raw.githubusercontent.com/wazuh/wazuh/v4.9.0/extensions/elasticsearch/7.x/wazuh-template.json)

The client searches the observed GUID spelling plus uppercase and lowercase forms. Local comparison ignores case, but an arbitrary mixed-case value in a case-sensitive index can be missed. Missing endpoint metadata or malformed timestamps make a record ineligible. Mapping differences can yield no matches or a sanitized search failure. Windows command lines containing backslashes are projected as JSON values and passed through normalization and pseudonymization. They do not contribute to the query DSL. The request explicitly disables partial search results and the local response parser verifies the outcome. [OpenSearch Search API](https://docs.opensearch.org/latest/api-reference/search-apis/search/)

## Docker and rollback

The Dockerfile installs the existing locked dependencies and runs the application as `soc`, UID 10001. The source and scripts are copied without normalizing restrictive host file modes. Their files and parent directories must therefore be readable and traversable by the non-root user in the actual staging build. The checked-in paths are regular Git files and the Dockerfile, Compose file, lockfiles and existing build context are unchanged. Windows file inspection cannot prove Unix container permissions. [.dockerignore](../.dockerignore) · [Dockerfile](../Dockerfile#L14)

The implementation guide gives a worker-only override with `wazuh.indexer:10.8.0.1`, the TLS hostname `https://wazuh.indexer:9200` and read-only mounts for the reader password and root CA. Use an independently provisioned staging copy readable only by the worker's mapped UID or dedicated group. Keep the production root-owned `0600` password untouched. Mount only the root CA certificate alongside the credential. The guide also lists defaults, snapshot schema and rollback steps. [Implementation and staging guide](WAZUH_EVIDENCE_RETRIEVAL.md)

An archived source checkout at the baseline revision passed SQLite integrity checks, opened a newly populated schema-v4 database, retained the stored contextual rows and replayed using only primary evidence. This verifies the old Python behavior with the additive JSON structure. It does not exercise the previous image, its mount permissions or the live VPS. Docker is unavailable locally. In staging, build and import as UID 10001, verify TLS and role scope, run both exact searches against actual mappings, check worst-case latency and replay, then test the real previous image on a disposable copy of a retrieval-enabled database.

## Validation and Git status

The JavaScript checks passed `npm ci`, lint, typecheck, production build and all three Playwright tests. Ruff lint and formatting, offline replay and whitespace checks passed. The existing Starlette/httpx warning and npm ESLint deprecation remain. Docker, the live Indexer and the production VPS were not used.

On Python 3.12.13 with the locked dependencies, the final full suite finished with **463 passed, 1 skipped, 1 warning** in 125.98 seconds. The focused retrieval suite had **63 passed**, included in that total. The skipped test requires an opt-in live provider.

The reviewed diff excludes production credentials, databases, configuration and generated build outputs. No changes were committed, pushed, published as a PR, merged or deployed.

| Changed file | Added lines | Removed lines |
| --- | ---: | ---: |
| `.env.example` | 11 | 0 |
| `README.md` | 1 | 0 |
| `docs/WAZUH_EVIDENCE_PREFLIGHT.md` | 450 | 0 |
| `docs/WAZUH_EVIDENCE_RETRIEVAL.md` | 82 | 0 |
| `src/agents.py` | 17 | 7 |
| `src/llm.py` | 2 | 1 |
| `src/service.py` | 40 | 1 |
| `src/settings.py` | 34 | 0 |
| `src/storage.py` | 99 | 4 |
| `src/tools.py` | 3 | 0 |
| `src/wazuh_retrieval.py` | 499 | 0 |
| `tests/fixtures/wazuh_indexer_lineage.json` | 49 | 0 |
| `tests/test_wazuh_retrieval.py` | 615 | 0 |
| **Total (13 files)** | **1902** | **13** |

## Sanitized requests

All examples use the fictional lineage fixture. The URL is `https://indexer.fixture.invalid:9200/wazuh-alerts-*/_search?allow_partial_search_results=false`. Each example is a POST with `Content-Type: application/json` and `Accept-Encoding: identity`. The Authorization header is omitted. Size and timeout reflect illustrative values for the remaining budgets.

### Same process

```json
{
  "_source": [
    "id",
    "timestamp",
    "manager.name",
    "agent.id",
    "agent.name",
    "agent.ip",
    "rule.id",
    "rule.level",
    "rule.description",
    "data.win.system.eventID",
    "data.win.system.eventRecordID",
    "data.win.system.providerName",
    "data.win.system.channel",
    "data.win.system.systemTime",
    "data.win.system.computer",
    "data.win.eventdata.processGuid",
    "data.win.eventdata.parentProcessGuid",
    "data.win.eventdata.sourceProcessGuid",
    "data.win.eventdata.targetProcessGuid",
    "data.win.eventdata.processId",
    "data.win.eventdata.parentProcessId",
    "data.win.eventdata.sourceProcessId",
    "data.win.eventdata.targetProcessId",
    "data.win.eventdata.image",
    "data.win.eventdata.parentImage",
    "data.win.eventdata.sourceImage",
    "data.win.eventdata.targetImage",
    "data.win.eventdata.targetFilename",
    "data.win.eventdata.originalFileName",
    "data.win.eventdata.targetObject",
    "data.win.eventdata.user",
    "data.win.eventdata.parentUser",
    "data.win.eventdata.commandLine",
    "data.win.eventdata.parentCommandLine",
    "data.win.eventdata.utcTime",
    "data.win.eventdata.creationUtcTime",
    "data.win.eventdata.sourceIp",
    "data.win.eventdata.destinationIp",
    "data.win.eventdata.sourcePort",
    "data.win.eventdata.destinationPort",
    "data.win.eventdata.queryStatus",
    "data.win.eventdata.integrityLevel",
    "data.win.eventdata.protocol",
    "data.win.eventdata.initiated",
    "data.win.eventdata.eventType",
    "data.win.eventdata.type",
    "data.win.eventdata.grantedAccess",
    "data.win.eventdata.hashes",
    "data.win.eventdata.queryName",
    "data.win.eventdata.queryResults",
    "data.win.eventdata.details"
  ],
  "size": 20,
  "track_total_hits": false,
  "sort": [
    {
      "timestamp": "desc"
    },
    {
      "id": "asc"
    }
  ],
  "timeout": "2900ms",
  "query": {
    "bool": {
      "filter": [
        {
          "term": {
            "manager.name": "fixture-manager"
          }
        },
        {
          "term": {
            "agent.id": "045"
          }
        },
        {
          "term": {
            "agent.name": "fixture-workstation"
          }
        },
        {
          "term": {
            "agent.ip": "10.91.0.15"
          }
        },
        {
          "term": {
            "data.win.system.computer": "fixture-computer"
          }
        },
        {
          "term": {
            "data.win.system.providerName": "Microsoft-Windows-Sysmon"
          }
        },
        {
          "term": {
            "data.win.system.eventID": "1"
          }
        },
        {
          "terms": {
            "data.win.eventdata.processGuid": [
              "{11111111-AAAA-2222-3333-444444444444}",
              "{11111111-aaaa-2222-3333-444444444444}"
            ]
          }
        },
        {
          "range": {
            "timestamp": {
              "gte": "2025-03-03T11:58:05+00:00",
              "lte": "2025-03-03T12:00:05+00:00"
            }
          }
        }
      ]
    }
  }
}
```

### Parent after a matching process creation hit

```json
{
  "_source": [
    "id",
    "timestamp",
    "manager.name",
    "agent.id",
    "agent.name",
    "agent.ip",
    "rule.id",
    "rule.level",
    "rule.description",
    "data.win.system.eventID",
    "data.win.system.eventRecordID",
    "data.win.system.providerName",
    "data.win.system.channel",
    "data.win.system.systemTime",
    "data.win.system.computer",
    "data.win.eventdata.processGuid",
    "data.win.eventdata.parentProcessGuid",
    "data.win.eventdata.sourceProcessGuid",
    "data.win.eventdata.targetProcessGuid",
    "data.win.eventdata.processId",
    "data.win.eventdata.parentProcessId",
    "data.win.eventdata.sourceProcessId",
    "data.win.eventdata.targetProcessId",
    "data.win.eventdata.image",
    "data.win.eventdata.parentImage",
    "data.win.eventdata.sourceImage",
    "data.win.eventdata.targetImage",
    "data.win.eventdata.targetFilename",
    "data.win.eventdata.originalFileName",
    "data.win.eventdata.targetObject",
    "data.win.eventdata.user",
    "data.win.eventdata.parentUser",
    "data.win.eventdata.commandLine",
    "data.win.eventdata.parentCommandLine",
    "data.win.eventdata.utcTime",
    "data.win.eventdata.creationUtcTime",
    "data.win.eventdata.sourceIp",
    "data.win.eventdata.destinationIp",
    "data.win.eventdata.sourcePort",
    "data.win.eventdata.destinationPort",
    "data.win.eventdata.queryStatus",
    "data.win.eventdata.integrityLevel",
    "data.win.eventdata.protocol",
    "data.win.eventdata.initiated",
    "data.win.eventdata.eventType",
    "data.win.eventdata.type",
    "data.win.eventdata.grantedAccess",
    "data.win.eventdata.hashes",
    "data.win.eventdata.queryName",
    "data.win.eventdata.queryResults",
    "data.win.eventdata.details"
  ],
  "size": 19,
  "track_total_hits": false,
  "sort": [
    {
      "timestamp": "desc"
    },
    {
      "id": "asc"
    }
  ],
  "timeout": "2700ms",
  "query": {
    "bool": {
      "filter": [
        {
          "term": {
            "manager.name": "fixture-manager"
          }
        },
        {
          "term": {
            "agent.id": "045"
          }
        },
        {
          "term": {
            "agent.name": "fixture-workstation"
          }
        },
        {
          "term": {
            "agent.ip": "10.91.0.15"
          }
        },
        {
          "term": {
            "data.win.system.computer": "fixture-computer"
          }
        },
        {
          "term": {
            "data.win.system.providerName": "Microsoft-Windows-Sysmon"
          }
        },
        {
          "term": {
            "data.win.system.eventID": "1"
          }
        },
        {
          "terms": {
            "data.win.eventdata.processGuid": [
              "{55555555-BBBB-6666-7777-888888888888}",
              "{55555555-bbbb-6666-7777-888888888888}"
            ]
          }
        },
        {
          "range": {
            "timestamp": {
              "gte": "2025-03-03T11:58:05+00:00",
              "lte": "2025-03-03T12:00:00+00:00"
            }
          }
        }
      ]
    }
  }
}
```

### Direct parent when primary evidence is process creation

```json
{
  "_source": [
    "id",
    "timestamp",
    "manager.name",
    "agent.id",
    "agent.name",
    "agent.ip",
    "rule.id",
    "rule.level",
    "rule.description",
    "data.win.system.eventID",
    "data.win.system.eventRecordID",
    "data.win.system.providerName",
    "data.win.system.channel",
    "data.win.system.systemTime",
    "data.win.system.computer",
    "data.win.eventdata.processGuid",
    "data.win.eventdata.parentProcessGuid",
    "data.win.eventdata.sourceProcessGuid",
    "data.win.eventdata.targetProcessGuid",
    "data.win.eventdata.processId",
    "data.win.eventdata.parentProcessId",
    "data.win.eventdata.sourceProcessId",
    "data.win.eventdata.targetProcessId",
    "data.win.eventdata.image",
    "data.win.eventdata.parentImage",
    "data.win.eventdata.sourceImage",
    "data.win.eventdata.targetImage",
    "data.win.eventdata.targetFilename",
    "data.win.eventdata.originalFileName",
    "data.win.eventdata.targetObject",
    "data.win.eventdata.user",
    "data.win.eventdata.parentUser",
    "data.win.eventdata.commandLine",
    "data.win.eventdata.parentCommandLine",
    "data.win.eventdata.utcTime",
    "data.win.eventdata.creationUtcTime",
    "data.win.eventdata.sourceIp",
    "data.win.eventdata.destinationIp",
    "data.win.eventdata.sourcePort",
    "data.win.eventdata.destinationPort",
    "data.win.eventdata.queryStatus",
    "data.win.eventdata.integrityLevel",
    "data.win.eventdata.protocol",
    "data.win.eventdata.initiated",
    "data.win.eventdata.eventType",
    "data.win.eventdata.type",
    "data.win.eventdata.grantedAccess",
    "data.win.eventdata.hashes",
    "data.win.eventdata.queryName",
    "data.win.eventdata.queryResults",
    "data.win.eventdata.details"
  ],
  "size": 20,
  "track_total_hits": false,
  "sort": [
    {
      "timestamp": "desc"
    },
    {
      "id": "asc"
    }
  ],
  "timeout": "2900ms",
  "query": {
    "bool": {
      "filter": [
        {
          "term": {
            "manager.name": "fixture-manager"
          }
        },
        {
          "term": {
            "agent.id": "045"
          }
        },
        {
          "term": {
            "agent.name": "fixture-workstation"
          }
        },
        {
          "term": {
            "agent.ip": "10.91.0.15"
          }
        },
        {
          "term": {
            "data.win.system.computer": "fixture-computer"
          }
        },
        {
          "term": {
            "data.win.system.providerName": "Microsoft-Windows-Sysmon"
          }
        },
        {
          "term": {
            "data.win.system.eventID": "1"
          }
        },
        {
          "terms": {
            "data.win.eventdata.processGuid": [
              "{55555555-BBBB-6666-7777-888888888888}",
              "{55555555-bbbb-6666-7777-888888888888}"
            ]
          }
        },
        {
          "range": {
            "timestamp": {
              "gte": "2025-03-03T11:58:00+00:00",
              "lte": "2025-03-03T12:00:00+00:00"
            }
          }
        }
      ]
    }
  }
}
```
