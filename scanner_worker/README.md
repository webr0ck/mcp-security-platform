# scanner-worker (CR-14 / WP-B1)

Isolated, unprivileged execution environment for scanning untrusted,
submitter-controlled repository content. Runs OUTSIDE the proxy container.

## Why this exists

Before this service, clone + scanner execution (trufflehog, pip-audit,
mcp_checker/semgrep) ran inside the `proxy` container — the same process
holding DB-admin creds, the Vault token, and the gateway shared secret. A
malicious `setup.py`/`package.json` prescript in a submitted repo executed
with access to those secrets. See
`docs/superpowers/plans/2026-07-06-platform-finalisation-PRD.md` (PRD-6) and
the original finding at
`Codex_review/___issue-14-scanner-worker-isolation.md` (CR-14).

## Execution / adjudication split (non-negotiable)

This worker executes scanners and writes **raw output only**, to the
`scan_raw_results` table. It never computes or writes `block`,
`scan_status`, or any other authorization-relevant state — there is no
column in any table this process can write to that holds a verdict. A
trusted evaluator living in the proxy (`proxy/app/services/scan_evaluator.py`
— a process that never touches attacker-controlled repo content) reads
`scan_raw_results`, applies policy, and writes the verdict.

This is enforced at the DB-role level (`infra/db/migrations/V063__scanner_worker_queue.sql`),
not just in application code:
- `scanner_worker_app` has **INSERT-only** on `scan_raw_results` (no SELECT/UPDATE/DELETE).
- `scanner_worker_app` may **UPDATE only** its own claim/heartbeat/attempt
  columns on `scan_jobs` (`status`, `attempts`, `claimed_by`, `claimed_at`,
  `heartbeat_at`, `last_error`, `updated_at`) — it cannot alter job identity
  (`server_id`, `github_url`, `job_type`, `force`).
- `scanner_worker_app` has no grant whatsoever on `server_registry`,
  `platform_secrets`, `credential_store`, `audit_events`, `api_keys`, or
  `oidc_sessions`.

A corrupted/compromised worker can therefore at worst produce a parse
error or a crashed job, which the evaluator maps to `scan_status='error'`
(fail closed) — it can never forge a `PASS`.

## Multi-ecosystem dependency CVE gate (CR-12 / WP-B2)

Three more scanner layers run here alongside pip-audit:
`dependency_scanners.py::run_osv_scanner` (broad Go/npm/PyPI/etc. via
OSV-Scanner), `run_npm_audit` (Node, requires a lockfile — deliberately uses
`--package-lock-only`, NEVER `npm install`, which would execute the
submitted package's own install scripts here), and `run_govulncheck` (Go
reachability analysis; a module load/build failure is a forced
`review_required` signal, never a silent pass — see the module's docstring
for why this is the package's core security property). All four dependency
scanners emit `block: false` unconditionally — policy (severity threshold,
alias-collapse across scanners, waivers) is decided entirely by
`proxy/app/services/dependency_policy.py` on the evaluator side, because no
single scanner layer has the full picture (pip-audit's own output carries no
severity at all). See `docs/spec/05-integrations.md` §4 step 1b for the full
design and `infra/db/migrations/V066__scan_waivers.sql` for the waiver
table's DB-role grants (same execution/adjudication split as the rest of
this document: `scanner_worker_app` has zero grant on `scan_waivers`).

## What this container has (and does not have)

Has:
- `git`, `trufflehog`, `pip-audit`, `semgrep`, `syft`, vendored `mcp_checker`.
- `osv-scanner`, `npm`/`node`, `go` + `govulncheck` (CR-12 / WP-B2).
- Its own narrow DB role (`scanner_worker_app` via `SCANNER_WORKER_DATABASE_URL`).
- Its own, separately-scoped git clone token(s), e.g. `GIT_CLONE_TOKEN_GITHUB`
  — a read-only, provider-scoped credential. This is NOT the same secret
  store as the proxy's `platform_secrets`/`credential_store` tables; the
  worker has no DB access to either.

Does NOT have:
- The proxy's DB-admin connection, Vault token, or gateway shared secret.
- Any of `platform_secrets`/`credential_store` (Jira/Entra/other
  integration secrets) — a git clone token is the only credential type this
  process handles.
- Write access to any adjudication-relevant column anywhere.

## Isolation (container/network)

See `docker-compose.yml` (`scanner-worker` service) for the concrete wiring:
- Read-only checkout dir (`/work/checkout`, tmpfs, wiped per job) and a
  separate `/work/output` scratch dir.
- CPU/memory/pids/no-new-privileges limits (mirrors the `x-mcp-hardening`
  anchor pattern already used for lab MCP servers).
- Egress restricted to configured git provider hosts + vulnerability-feed
  hosts via the same allowlisting egress-proxy pattern as
  `lab/egress-proxy/squid.conf` (see `lab/egress-proxy/squid-scanner.conf`).
- No proxy secrets in its environment (verified by
  `proxy/tests/unit/test_scanner_isolation.py`).

## Known limitation (recorded, not silently dropped)

The git clone token is passed via the worker's own env var rather than
resolved from `platform_secrets` at request time (which would require
granting the worker DB access to the proxy's secret store — a strictly
larger blast radius than the isolation this change is trying to achieve).
This mirrors the pre-existing `GITHUB_CLONE_TOKEN` env-var fallback that
already existed in `submission_scanner.py`, so it is not a regression, but
it does mean per-provider token rotation from the admin UI
(`platform_secrets` name `git-<provider>`) does not yet reach this worker.
A future hardening step would have the proxy mint a short-lived,
job-scoped credential and pass it at claim time instead of a long-lived
static env var — out of scope for WP-B1.
