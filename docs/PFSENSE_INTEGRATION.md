# pfSense managed response

Verified source baseline on 2026-11-24 (Asia/Bangkok): `boi1707/AgentSOC`,
`origin/main` at `2a2c1f9f9360f841ec8ad76d5bf0427e507e9402`. Local branch:
`feat/pfsense-managed-response`. The starting working tree was clean. The latest main includes the
README work from PR #6. The work below uses no lab credentials, VPS access or firewall calls.

## Repository audit

| Classification | Findings |
| --- | --- |
| IMPLEMENTED | Wazuh ingestion and correlation, durable analysis jobs, DeepSeek provider mode, host/network/judge agents, anonymization and grounding with the deterministic verifier. Web sessions with CSRF and signed Telegram callbacks converge on the same approval service. SQLite WAL, actions, audit records, execution recovery and durable Shuffle notification/results already exist. |
| REUSE | `src/approvals.py` checks the current completed non-replay run, proposal age and incident state. `src/storage.py` repeats checks in the approval transaction. `src/response.py` resolves the cited network source and applies protection policy. Web and Telegram already require approver/admin privileges. Actions have `verification_status`. The existing `Service.tick` and worker provide analysis and integration delivery. |
| IMPLEMENTED IN SIMULATION | Web/Telegram managed intent, independent worker lane, runtime observation, lease overlap and expiry, owned-only removal, retry and recovery, audit, UI status and local outbox. Migration v3 stores the lifecycle. |
| PARTIAL | `PfSenseAdapter` supports explicit operator-only read diagnostics. Its write operations remain disabled. |
| MISSING | Safe scoped remote write/apply, installed lab API acceptance, traffic verification, and live result delivery. |
| OUT OF SCOPE | Production Compose, `.env`, DeepSeek credentials/configuration, live firewalls and gateways, existing Telegram/Shuffle workflow, TheHive, VirusTotal, frontend redesign and legacy SSH behavior. |

### Phase 3 security audit

Reviewed the working-tree diff against `2a2c1f9`, including the untracked adapter tests, managed
worker, diagnostics CLI and this document. The findings below affect the staged development
lifecycle. There is no remotely selectable managed-write mode in the reviewed build.

| Severity | Finding and fix |
| --- | --- |
| High | Verification time previously started the full block TTL, so a lost acknowledgement could extend blocking. The worker now journals `block_requested_at` before the first possible write and derives a hard expiry from it. A draft v3 row with its own marker and no timestamp uses approval time as a conservative bound. [Worker](../src/managed_response.py#L330) · [Migration](../src/migrations.py#L181) |
| High | Post-I/O stage, retry and completion writes could rely only on the local file lock. Each claim now has a new token. SQL write transactions check both the token and its deadline before accepting a result. Worker revalidation also checks the current proposal deadline. [Claim and fencing](../src/managed_response.py#L222) |
| High | Positional alias mutation and global apply cannot meet the scope and concurrency requirements. Actual REST mutation stays blocked. Simulated transport refuses a changed firewall or alias identity, unexpected change, or pending change it does not own. [Observation gate](../src/managed_response.py#L205) |
| Medium | TheHive could select a case before a simulated approval and then read simulated status after approval. It now captures the eligible case snapshot in the same transaction as its sync claim. Shuffle rechecks simulation markers before sending scheduled rows. The legacy Telegram notifier stays silent in injected simulation. [TheHive](../src/thehive.py#L75) · [Shuffle](../src/shuffle.py#L35) · [Telegram notifier](../src/service.py#L219) |
| Medium | The CLI disabled wire logging, but direct adapter callers could enable HTTP traces that include echoed credentials. The adapter suppresses HTTP wire traces during its request thread's diagnostics and validates the HTTPS origin with a restricted grammar. [Adapter](../src/response_adapters.py#L89) |

Web CSRF, signed Telegram callbacks and role checks still converge on the same approval
transaction. The AI Assistant stays read-only. No external deployment vulnerability or exposure was
verified. The residual authorization race between the final local check and receipt of a remote
operation needs a bounded, server-enforced admission rule in any future write transport.

## Verified pfREST contract

The upstream release is **v2.11.1**, commit **`9024718c0dc2df7b21ffe9816612b49cd8888cd9`**.
The model/endpoint declarations drive the generated OpenAPI schema. The OpenAPI endpoint on an
installed firewall is `/api/v2/schema/openapi`. This review used the pinned upstream schema
generator and endpoint/model sources. The lab instance's generated schema was not fetched.
[Release](https://github.com/pfrest/pfSense-pkg-RESTAPI/releases/tag/v2.11.1)
[OpenAPI guide at the reviewed commit](https://github.com/pfrest/pfSense-pkg-RESTAPI/blob/9024718c0dc2df7b21ffe9816612b49cd8888cd9/docs/SWAGGER_AND_OPENAPI.md)
[Schema generator](https://github.com/pfrest/pfSense-pkg-RESTAPI/blob/9024718c0dc2df7b21ffe9816612b49cd8888cd9/pfSense-pkg-RESTAPI/files/usr/local/pkg/RESTAPI/Schemas/OpenAPISchema.inc)

| Operation | Contract and meaning |
| --- | --- |
| `GET /api/v2/firewall/aliases?name=AGENTSOC_BLOCKLIST` | The success envelope has integer `code` and a `data` list. Accept exactly one matching host alias with numeric `id` and an `address` array. Its positional object ID is diagnostic only. |
| `GET /api/v2/firewall/apply` | `data.applied` and `data.pending_subsystems` describe global pending firewall changes. This is a separate observation from alias configuration and PF table membership. |
| `GET /api/v2/diagnostics/table?id=AGENTSOC_BLOCKLIST` | `data.id` and `data.name` identify the PF table and `data.entries` contains runtime entries. The adapter recognizes exact IP and enclosing CIDR entries. Runtime membership alone cannot establish whether traffic was denied. |
| Alias write and firewall apply | Reviewed but disabled. The single-alias PATCH identifies the object by its numeric configuration position. The alias's ordered `address` and `detail` arrays are writable. `apply` and `async` are boolean control parameters. Alias apply and `POST /api/v2/firewall/apply` both dispatch a global filter reload. |

Sources: [alias model](https://github.com/pfrest/pfSense-pkg-RESTAPI/blob/9024718c0dc2df7b21ffe9816612b49cd8888cd9/pfSense-pkg-RESTAPI/files/usr/local/pkg/RESTAPI/Models/FirewallAlias.inc),
[apply model](https://github.com/pfrest/pfSense-pkg-RESTAPI/blob/9024718c0dc2df7b21ffe9816612b49cd8888cd9/pfSense-pkg-RESTAPI/files/usr/local/pkg/RESTAPI/Models/FirewallApply.inc),
[apply dispatcher](https://github.com/pfrest/pfSense-pkg-RESTAPI/blob/9024718c0dc2df7b21ffe9816612b49cd8888cd9/pfSense-pkg-RESTAPI/files/usr/local/pkg/RESTAPI/Dispatchers/FirewallApplyDispatcher.inc),
[PF table model](https://github.com/pfrest/pfSense-pkg-RESTAPI/blob/9024718c0dc2df7b21ffe9816612b49cd8888cd9/pfSense-pkg-RESTAPI/files/usr/local/pkg/RESTAPI/Models/Table.inc),
[control parameters](https://github.com/pfrest/pfSense-pkg-RESTAPI/blob/9024718c0dc2df7b21ffe9816612b49cd8888cd9/docs/COMMON_CONTROL_PARAMETERS.md).

The reviewed authorization model grants privileges by endpoint and method. Give a separate operator
diagnostic credential only the three GET privileges above within the existing Read Only policy.
`X-API-Key` carries that dedicated credential. An endpoint PATCH privilege does not confine access
to one alias. The reviewed API exposes no verified atomic guard tying a positional PATCH to this
alias's name and version, and no alias-scoped filter apply. An administrator could reorder aliases
or stage other firewall changes between a read and a write/apply. An AgentSOC-local mutex and a
last-second check cannot close those races. A future writer needs an enforceable firewall-side
scope and concurrency contract covering identity, preservation of simultaneous edits and apply.
[Authentication and privileges](https://github.com/pfrest/pfSense-pkg-RESTAPI/blob/9024718c0dc2df7b21ffe9816612b49cd8888cd9/docs/AUTHENTICATION_AND_AUTHORIZATION.md)
[Endpoint dispatch](https://github.com/pfrest/pfSense-pkg-RESTAPI/blob/9024718c0dc2df7b21ffe9816612b49cd8888cd9/pfSense-pkg-RESTAPI/files/usr/local/pkg/RESTAPI/Core/Endpoint.inc)
[Configuration object identity](https://github.com/pfrest/pfSense-pkg-RESTAPI/blob/9024718c0dc2df7b21ffe9816612b49cd8888cd9/pfSense-pkg-RESTAPI/files/usr/local/pkg/RESTAPI/Core/Model.inc)

Additional findings from the same pinned revision:

| Capability | Source finding |
| --- | --- |
| Stable alias ID, name-based mutation, conditional update | The name is available for discovery. The PATCH handler uses model update with an ID and the configuration path uses that numeric position. The reviewed path does not expose name-based writes, an expected revision or an HTTP conditional update. |
| Configuration history | The diagnostics revision endpoint can read or delete history records. Inspection of historical revisions does not make an alias PATCH conditional on a revision. |
| Server-side lock | `Model::write_config` checks a package lock file before writing the configuration. The lock is reached after model lookup and preparation of the change and does not bind them together with apply. Coordination with WebGUI edits and other writers was not established. |
| Scoped apply, runtime mutation | Alias apply and firewall apply call the global filter dispatcher. The diagnostics table endpoint exposes inspection and a table flush. It does not expose a supported targeted entry update. |
| Object-level access | The reviewed authorization grants endpoint/method privileges. No privilege scoped to a named alias was established. |

[Configuration history endpoint](https://github.com/pfrest/pfSense-pkg-RESTAPI/blob/9024718c0dc2df7b21ffe9816612b49cd8888cd9/pfSense-pkg-RESTAPI/files/usr/local/pkg/RESTAPI/Endpoints/DiagnosticsConfigHistoryRevisionEndpoint.inc)
[Diagnostics table endpoint](https://github.com/pfrest/pfSense-pkg-RESTAPI/blob/9024718c0dc2df7b21ffe9816612b49cd8888cd9/pfSense-pkg-RESTAPI/files/usr/local/pkg/RESTAPI/Endpoints/DiagnosticsTableEndpoint.inc)

Exact review points include the [alias endpoint methods](https://github.com/pfrest/pfSense-pkg-RESTAPI/blob/9024718c0dc2df7b21ffe9816612b49cd8888cd9/pfSense-pkg-RESTAPI/files/usr/local/pkg/RESTAPI/Endpoints/FirewallAliasEndpoint.inc#L11-L18),
the [PATCH handler](https://github.com/pfrest/pfSense-pkg-RESTAPI/blob/9024718c0dc2df7b21ffe9816612b49cd8888cd9/pfSense-pkg-RESTAPI/files/usr/local/pkg/RESTAPI/Core/Endpoint.inc#L1262),
the [positional update](https://github.com/pfrest/pfSense-pkg-RESTAPI/blob/9024718c0dc2df7b21ffe9816612b49cd8888cd9/pfSense-pkg-RESTAPI/files/usr/local/pkg/RESTAPI/Core/Model.inc#L2317),
the [package write lock](https://github.com/pfrest/pfSense-pkg-RESTAPI/blob/9024718c0dc2df7b21ffe9816612b49cd8888cd9/pfSense-pkg-RESTAPI/files/usr/local/pkg/RESTAPI/Core/Model.inc#L754),
the [global dispatcher](https://github.com/pfrest/pfSense-pkg-RESTAPI/blob/9024718c0dc2df7b21ffe9816612b49cd8888cd9/pfSense-pkg-RESTAPI/files/usr/local/pkg/RESTAPI/Dispatchers/FirewallApplyDispatcher.inc#L16),
and [PF table inspection and flush](https://github.com/pfrest/pfSense-pkg-RESTAPI/blob/9024718c0dc2df7b21ffe9816612b49cd8888cd9/pfSense-pkg-RESTAPI/files/usr/local/pkg/RESTAPI/Models/Table.inc#L48-L67).

The existing block rule, interface, destination and logging configuration remain operator-owned.
Existing PF connections may remain established through a ruleset reload. The reviewed state
model describes source/destination pair removal and full-state reset, neither of which is part of
this integration. Validate the rule and traffic independently in an authorized lab.
[Firewall state model](https://github.com/pfrest/pfSense-pkg-RESTAPI/blob/9024718c0dc2df7b21ffe9816612b49cd8888cd9/pfSense-pkg-RESTAPI/files/usr/local/pkg/RESTAPI/Models/FirewallState.inc)

## Read-only diagnostics

The diagnostic CLI resolves the expected HTTPS hostname with a supplied CA trust file. It reads a
bounded key file, rejects reuse of existing integration credentials, disables proxies and redirects,
uses bounded HTTP timeouts and a response size limit, and reports sanitized transport/schema errors.
The credential is sent only as a header to the configured origin. The diagnostic emits booleans
and the observed alias ID, with `traffic_verified=false`. Its three observations are separate
reads, so concurrent changes can make them describe different instants.

| Setting | Default or lab value |
| --- | --- |
| `RESPONSE_MODE` | `dry-run` for this deployment. Existing SSH deployments retain their legacy configuration. |
| `PFSENSE_LIVE_ENABLED` | `0`. Any other value and `RESPONSE_MODE=pfsense` are rejected. |
| `PFSENSE_URL`, `PFSENSE_HOSTNAME` | Empty. For an authorized read check, the URL origin and expected TLS hostname must match. |
| `PFSENSE_API_KEY_FILE`, `PFSENSE_CA_FILE` | Empty. Supply paths to a dedicated credential and a trusted CA bundle for the lab check. |
| `PFSENSE_ALIAS` | `AGENTSOC_BLOCKLIST`, the only accepted alias. |
| `PFSENSE_TIMEOUT` | 5 seconds per HTTP timeout phase. Maximum 15. |
| `PFSENSE_BLOCK_TTL_SECONDS` | 86400. Plan validation uses this maximum; it does not schedule removal. |
| `PFSENSE_ALLOWED_NETWORKS` | `10.100.27.10/32`. Cannot be expanded beyond the initial authorized target. |

The adapter additionally rejects management/LAN/WAN/gateway ranges including `10.8.0.0/24`,
`172.22.50.0/24`, `192.168.119.0/24`, and `10.100.27.254/32`, loopback/link-local/multicast/
reserved addresses, and configured protected ranges. The application response policy must still
bind future mitigation to server-side evidence and an individually authenticated decision.

`PROTECTED_NETWORKS` is an additive denylist shared by the general response candidate
guard and the pfSense adapter. Configure it as comma-separated IPv4 CIDRs in the shared
Compose `.env`; the built-in ranges and the configured `GATEWAY` host remain protected.
Malformed CIDRs or a non-IPv4 gateway fail startup in both the backend and worker,
including dry-run. See the deployment example and rollback notes in
[DEPLOYMENT.md](DEPLOYMENT.md#mạng-được-bảo-vệ-khi-xét-đích-phản-ứng).

The pfSense adapter also requires a target to be in `PFSENSE_ALLOWED_NETWORKS` and the
fixed lab scope `10.100.27.10/32`. A source in a protected range is rejected even if it
matches the allowed scope. For the reviewed topology, protect `10.100.27.254/32` to
cover the gateway while leaving the lab source outside the added ranges. pfSense writes
remain disabled.

For later, separately authorized read-only acceptance, use a disposable diagnostic container or
one-shot lab override. Keep key and public CA files outside Git and mount both read-only. Restrict
host key-file access to the intended container UID and operators. Example override fragment for the
diagnostic service, using placeholders for the reviewed host file locations:

```yaml
extra_hosts:
  - "pfSense-6ae040084f22f:10.8.0.5"
environment:
  RESPONSE_MODE: dry-run
  PFSENSE_LIVE_ENABLED: "0"
  PFSENSE_URL: https://pfSense-6ae040084f22f
  PFSENSE_HOSTNAME: pfSense-6ae040084f22f
  PFSENSE_API_KEY_FILE: /run/secrets/pfsense-read-key
  PFSENSE_CA_FILE: /run/pfsense/ca.pem
volumes:
  - /secure/path/pfsense-read-key:/run/secrets/pfsense-read-key:ro
  - /secure/path/pfsense-ca.pem:/run/pfsense/ca.pem:ro
```

Use the hostname in the URL to retain TLS hostname verification over WireGuard. The optional
check is `python -m scripts.pfsense_readiness --source-ip 10.100.27.10`. It makes actual GET calls
when supplied a reachable origin, so it was not invoked against the firewall during development.

## Approval and lease lifecycle

The standard application keeps Web and Telegram approvals on the existing Dry-Run or configured
SSH path. Dry-Run reports `dry_run`, `blocked=false` and `not_verified`. Local tests explicitly
inject `ManagedTransport` into the application or service. The deterministic transport lives in
`tests/test_managed_response.py`. There is no environment flag or HTTP parameter to select it.
The read-only CLI runs separately from approval.

1. **Intent.** An enabled named Web or Telegram approver approves the current proposal. In the
   same SQLite write transaction the shared approval claim writes the action and managed lease,
   with unique action/proposal IDs. The policy checks a completed live, non-replay run, trusted
   original Wazuh evidence, the stored verdict and confidence, the cited IP, proposal expiry,
   protected ranges and the initial target scope. Demo, synthetic and legacy provenance are
   ineligible. Legacy shared credentials cannot enqueue managed execution.
2. **Execution.** A dedicated worker lane claims a durable lease independently of AI analysis.
   A local advisory file lock serializes response operations across workers sharing one database.
   Use a shared local filesystem and keep the lock file in place while any worker runs.
   Approval eligibility is checked again before activation. SQLite write transactions close
   before transport calls. Progress is stored as pending, executing, configured, applied and
   runtime verified, with unknown or failed outcomes on error.
3. **Recovery.** Ownership is journaled before configuration. The mock contract provides a
   coherent revision, pending/configured/runtime ownership, conditional writes and operation
   deadlines. A retry starts with a fresh observation. After an interrupted claim, the next
   worker reconciles configuration and runtime state. It can apply a known pending change or
   complete a previously applied operation without repeating the write.
4. **Expiry.** The activation deadline is the earlier of five minutes from approval or proposal
   expiry. A new transport change may use at most a 30-second operation deadline. The persisted
   block TTL defaults to 86400 seconds. For an AgentSOC write, its clock starts at the first
   possible mutation, before any acknowledgement. The verification timestamp is separate.
   A new lease sharing verified membership starts its own TTL. An old lease cannot use late
   verification to extend its original TTL. An uncertain activation past either its proposal
   deadline or its hard TTL enters cleanup if an ownership marker may exist.
   Disabling new execution cancels pending activations and still processes existing leases
   with the same injected transport.
5. **Cleanup.** At expiry, the worker checks observed membership and ownership. It preserves
   pre-existing membership and entries needed by another unexpired lease. It records runtime
   unblock verified only after configuration and runtime absence are both observed. After five
   failed attempts, or a permanent failure, it retains an unresolved state and warns. If the
   transport is unavailable, the persisted obligations remain and the worker logs a warning.
   A worker outage can delay cleanup past the planned expiry. Exhausted cleanup requires
   operator reconciliation before attempting another removal.
6. **Results.** Action history exposes simulated verification, expiry and sanitized errors.
   The existing outboxes hold `response.completed`, `response.expired` and
   `response.unblock.completed` for local inspection. Simulation payloads carry
   `simulated=true`, `blocked=false` and `traffic_verified=false`. They are unscheduled and
   excluded from delivery. TheHive skips managed simulation cases. Legacy Dry-Run and SSH
   delivery keep the existing event contract.

Migration **v3** creates or upgrades `managed_block_leases` with activation deadlines and
persisted TTL, alongside the existing links and indexes. The transaction preserves existing
rows. The table remains unused by approval in the standard runtime with no injected transport.

## Controlled-lab operating model

A separately approved lab write procedure would need a dedicated alias, one target, an exclusive
firewall maintenance window and an operator who can verify that administrators, WebGUI automation
and third-party writers have paused. Before any write, confirm the expected alias identity and
shape, save its entries and check for unexpected pending firewall configuration. Preserve
unrelated entries. Afterward, compare the complete alias configuration with the expected change
and check runtime PF membership. Suspend immediately on unexpected pending changes, an alias
identity mismatch, an ambiguous result or a runtime mismatch. Verify actual traffic and rule logs
separately. A local worker lock and repeated reads do not eliminate races with external firewall
administrators. These procedures offer operational isolation during an authorized window.

| Alternative | Cost and limitation |
| --- | --- |
| Operator performs approved alias changes through the existing firewall workflow | Low engineering cost. Apply and cleanup stay manual and require coverage throughout the lease window. |
| Dedicated lab firewall with exclusive configuration ownership | Requires separate infrastructure and a documented maintenance window. Global apply persists and the maintenance rule relies on operator compliance. |
| Firewall-side service that owns one dedicated runtime table and exposes conditional changes | Highest engineering and maintenance cost. Needs a stable rule/table contract, privilege isolation, persistence or native expiry across reloads, and a separately reviewed recovery procedure. A proxy that only forwards current pfREST PATCH/apply cannot supply these guarantees. |

### Proposed narrow integration for approval

For automated response, use a firewall-local lease broker with exclusive ownership of a dedicated
PF table referenced by a pre-provisioned lab rule. The operator decision is whether to permit a
separately reviewed broker and dedicated rule/table on the isolated academic firewall. If that
change is declined, keep AgentSOC in Dry-Run and use operator-performed, explicitly authorized
lab changes. Broadening pfREST v2.11.1 credential scope leaves the identity and global-apply
blockers unresolved. An exclusive maintenance window alone also cannot enforce safe unattended
cleanup after the window ends.

- **Authority.** Bind the broker to private lab management traffic, authenticate AgentSOC Worker
  with a dedicated mTLS client identity and bind the service to one stable firewall/rule/table
  identity and `10.100.27.10/32`. Keep the backend, AI tools, pfREST credential and external
  integrations outside write authority. The broker accepts structured lease operations only.
- **Transport contract.** Use an observation request returning a coherent table identity,
  revision, effective membership, matching lease ownership and suspension status. A lease
  create request carries a unique lease ID, scope, expected revision, absolute admission
  deadline and hard expiry. A revoke request identifies the same lease and expected revision.
  Check client identity, scope, revision and deadline inside the broker's serialized operation.
  Reuse the same lease ID for reconciliation. Preserve an immutable payload per ID and reject
  conflicting retries. This is a proposed adapter contract for a new service.
- **Runtime and durability.** The broker journals before changing the dedicated table, verifies
  runtime membership after each change, and owns a local expiry watchdog independent of AgentSOC
  and WireGuard. Record a scope-wide hold on unexpected membership, table/rule drift, or ownership
  mismatch. Reconcile after a crash or ruleset reload before accepting writes. Keep active peer
  leases and external membership intact. A readback confirms runtime table state, with traffic
  acceptance separate.
- **Implementation gate.** Confirm a supported PF rule/table binding and reload behavior on the
  actual pfSense CE release in a disposable lab, review the narrowly privileged execution boundary,
  and define recovery for clock jumps, restart and offline expiry. A remote timeout or admission
  deadline does not retract a request already accepted. The broker must enforce expiry itself.
  This broker and its real transport are outside this branch.

## Isolated Docker verification

The current Dockerfile uses `python:3.12-slim` and UID 10001. Backend and Worker use one
`AGENTSOC_IMAGE`, and Compose forces Dry-Run for both. Ordinary containers require no pfSense
credential or CA mount. The optional one-shot diagnostic uses the private hostname mapping
shown above and read-only key/CA mounts, outside the build context. The private key file must be
readable by the diagnostic UID and inaccessible to unrelated users. Preserve CA validation even
when supplying a host mapping.

Use an operator-authorized **isolated Linux** Docker daemon. Run these from a reviewed candidate
checkout with Python 3.12 and the repository's locked development dependencies installed. The
revision label below explicitly identifies a local candidate based on the current commit.

```bash
set -euo pipefail
git diff --check
lab_dir=$(mktemp -d)
base=$(git rev-parse --short HEAD)
candidate="agentsoc:phase3-local-$base"
docker build --build-arg SOURCE_REVISION="$base-phase3-local" -t "$candidate" .
mkdir "$lab_dir/previous"
git archive 0022d28 | tar -x -C "$lab_dir/previous"
docker build -t agentsoc:rollback-0022d28 "$lab_dir/previous"
python3.12 -m scripts.validate_docker --image "$candidate" \
  --previous-image agentsoc:rollback-0022d28 \
  --report "$lab_dir/docker-validation-result.json"
```

The validator uses synthetic environment values, a Docker internal network, real container-local
API requests, a temporary v1 DB, and a consistent migrated backup copy. Inspect its stage report
for Python version, Backend/Worker health and shared image, Dry-Run and the SSH sentinel,
migration markers and the v3 timestamp column, and both historical-image exercises. The historical
fixture is a CI compatibility gate. Characterize and test the exact archived deployment images
separately before authorizing an actual rollback.

## Verification and operational gates

1. **Operator-supplied lab evidence.** Host read-only access, TLS validation, HTTP 403 on a write
   attempt, manual alias insertion/removal, ICMP interruption/restoration and matching firewall
   logs were previously observed. These observations do not establish container connectivity or
   automated write/apply.
2. **Local development.** Mocked pfREST reads exercise API shape, TLS configuration, scope and
   key isolation. The simulated write contract covers approval races, restart, timeout,
   expiry, ownership, overlap, retry exhaustion and blocked external delivery. Disposable
   SQLite tests cover migration preservation, repeatability and failure rollback.
3. **Read-only acceptance.** With separate authorization, run the diagnostic from an isolated
   lab container, validate WireGuard routing and the pinned lab certificate, verify endpoint
   privileges and compare configuration, apply status and PF table observations with the
   firewall UI. Confirm a read-only credential stays read-only.
4. **Future managed-write acceptance.** First resolve the real write/apply scope and obtain
   separate approval of the operational constraints. Then authorize a one-target test. Verify both
   approval paths, concurrent external changes, timeout recovery, unmanaged/shared membership,
   runtime block/removal, actual traffic and logs, expiry after restart, audit, and Shuffle
   delivery. Keep Dry-Run until those checks have evidence and activation is authorized.
5. **Rollback and cleanup.** This branch creates no real AgentSOC-owned membership. Keep
   simulation databases local and disposable. An application rollback can retain the additive
   table. Back up SQLite consistently before any authorized
   rollout and validate the exact old image on a copy. A future live rollout must stop new
   approvals first, preserve its ownership ledger, and reconcile and verify removal of only
   its owned entries before retiring credentials or the cleanup worker. Never flush the alias
   or the PF state table to roll back.

For a future approved live lab, require the following additional evidence:

- **Traffic.** Have the lab operator record baseline connectivity and fresh test connections from
  the authorized source to the protected victim. After application, compare configuration,
  runtime membership, fresh probes and matching block-rule logs. Observe pre-existing connections
  separately. Restore reachability and verify logs and runtime removal after cleanup.
- **Automatic expiry.** Test the deadline through restart, loss of AgentSOC/management
  connectivity, and overlapping approvals. Observe the original expiry and verified removal.
  Demonstrate that an unrelated or operator-owned entry survives. Include one ambiguous result
  and one overdue cleanup alert.
- **Emergency stop.** Suspend admission of new writes at the operator-controlled broker guard.
  Preserve journals and verified owned cleanup capability. If identity or observed state is
  inconsistent, stop automated writes and reconcile with the firewall operator. Revoke write
  credentials after safe cleanup or an explicit transfer of cleanup responsibility. Record
  before/after state and verify absence before retiring the rule or table.

This change is ready for local testing. Dry-run rollout of this revision still needs its container
validation. Controlled lab writes and live mitigation remain blocked.

### Local validation results

| Check | Result |
| --- | --- |
| Full pytest suite with Windows Python 3.12.13 and 3.14.4, using `-q -s` | 266 passed and 1 skipped on each interpreter. The skipped test is the opt-in live provider. Dependency deprecation warnings came from Starlette on 3.12 and websockets/Uvicorn on 3.14. |
| Focused pfSense, managed response, migration and integration tests | 104 passed on Python 3.12, including 13 new cases for stale claims, expiry and delayed verification, old v3 rows, unsafe observations, apply failure, runtime mismatch, credential logging and integration isolation. |
| `python -m ruff check src scripts tests integrations` and `python -m ruff format --check src scripts tests integrations` | Passed. |
| `python -m compileall -q src scripts tests integrations` and `git diff --check` | Passed. |
| Frontend `npm.cmd run typecheck`, `npm.cmd run lint` and `npm.cmd run build` | Passed. |
| Frontend `npm.cmd run test:e2e` | 3 passed in Phase 3 using Windows Python 3.12 and the isolated mock/dry-run fixture. |
| Docker image/runtime, GitHub CI and real pfSense API | Not run on this branch. The host has no Docker Engine or WSL installation, and the branch was not pushed. The local Python 3.12 run verifies the interpreter series used by the Dockerfile. |
