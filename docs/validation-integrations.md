# Integration change validation

Base: `aafe968558516211ab8e3b2bd35d9f73e021761d`.

Local review on Windows, 2026-11-09. The combined patch was checked with
`git apply --check` and applied once on `feat/soc-integrations`; the initial
working tree was clean and HEAD exactly matched the base above. No applicable
`AGENTS.md` was found in the repository or its parent directories. The standalone
`integrations.vi.md` matched the guide installed by the patch after newline normalization,
before the review notes below were added.

Dependencies were synchronized with `uv pip sync --python .venv/Scripts/python.exe
requirements-dev.lock` (this venv has no pip module) and `npm ci`:

- `python -m pytest -q`: **142 passed, 1 skipped**. The skipped test is the opt-in paid LLM provider test.
- `python -m ruff check src scripts tests`: passed.
- `python -m ruff format --check src scripts tests`: passed (49 files).
- `npm run typecheck`: passed.
- `npm run build`: passed after a clean `npm ci` (TypeScript and Vite production build).
- `npm run test:e2e`: **2 passed**, using installed Chrome and the new production build.
- `npm run lint`: passed.
- Prettier check for frontend source and browser tests: passed.
- `npm ci`: passed; its audit reported zero vulnerabilities.
- `git diff --check`: passed.

A Starlette/httpx deprecation warning is present in the test harness; no final test failed.
The original build attempt was blocked because Windows Application Control rejected
the Tailwind Oxide native addon with
`ERR_DLOPEN_FAILED: An Application Control policy has blocked this file`. Both Node
25.9.0 and Node 22.23.4 encounter the restriction; the package's supported WASM fallback
also stalled. The stalled test processes were stopped. The build now uses the
Tailwind JavaScript compiler with explicit `source(none)` / `@source inline(...)`
utilities instead of the native scanner. Tailwind and its Node compiler are pinned
to 4.3.4. No Windows security policy was changed and no dependencies were downgraded.

Earlier browser attempts against the previous `frontend/dist` failed to find the new
panels. After the successful rebuild, both tests passed, including the Case integrations
and External integrations panels, the HTTP ingestion/worker/review flow, and mobile
navigation/session isolation. Desktop and mobile screenshots were also inspected.
The new Vite build was verified with Node 25.9.0 and Node 22.23.4. Emitted JavaScript is
311.85 kB (96.39 kB gzip); CSS is 25.34 kB (6.88 kB gzip). These are bundle sizes, not
VPS RAM or throughput measurements.

Integration tests use HTTP mocks and real temporary SQLite databases. They cover private-IP exclusion,
VT cache and durable budgets, 429/backoff, error isolation, outbox leases, notification retries with stable
IDs, dry-run labels, crash recovery to action_unknown, synthetic/demo/replay isolation, secret masking,
and the authenticated AgentSOC API pipeline through review.

Review fixes on top of the supplied patch preserve the TheHive `creating` checkpoint
when a later reconciliation query fails (401/403/429/503), fence queue updates from
workers that lost their leases, validate newly returned remote IDs, and restore/redact
TheHive content before JSON serialization. Eight additional regression cases cover
these paths, including escaped credentials and Windows paths. Existing response
authorization, protected-IP checks and SSH execution policy are unchanged.

No paid LLM requests, VirusTotal calls, real Shuffle workflows, real TheHive mutations, SSH blocking,
or changes to the VPS were performed by these tests. Actual external API compatibility, delivery,
persistence and reboot recovery still need deployment verification.

The frontend build condition is now satisfied. Only relevant source, tests and
documentation are included in the integration commit. No push or deployment was
performed. Commit title and the manual push command are:

```bash
git commit -m "feat: add durable TheHive, Shuffle and VirusTotal integrations"
git push -u origin feat/soc-integrations
```

This package contains the complete TheHive + Shuffle + VirusTotal change. Do not also apply the earlier
TheHive-only patch. Use `git apply --check` against the base commit before applying; merge manually if
local code has diverged. Credentials, deployment `.env`, SQLite data and generated build outputs are excluded.
