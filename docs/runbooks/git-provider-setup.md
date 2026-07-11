# Runbook: Registering a New Git Provider

## Symptom

- A submitter tries to submit an MCP server whose repo lives on a git host
  that isn't GitHub (e.g. corporate Bitbucket) and the submission scanner
  rejects the clone, or `git_providers` has no row / `enabled=false` for that
  provider.
- Scanner-worker logs show a host-validation rejection (`GitHostError`) for a
  hostname that should be legitimate.
- An admin needs to rotate or set the clone token for an existing provider.

## Diagnosis

```bash
# What providers are currently configured (admin/platform_admin only)?
curl -s -H "Authorization: Bearer $ADMIN_TOKEN" \
  http://localhost:8000/api/v1/admin/git-providers | python3 -m json.tool

# Direct DB check
podman exec mcp-db psql -U mcp_app -d mcp_security -c \
  "SELECT provider, enabled, host, clone_account, allow_private, updated_at FROM git_providers;"

# Is a per-provider clone token actually present in the scanner-worker's own env
# (NOT the proxy's platform_secrets — the worker never reads that table)?
podman exec mcp-scanner-worker env | grep '^GIT_CLONE_TOKEN_'
```

## Resolution

Only two provider identifiers are accepted today:
`{"github", "bitbucket"}` — see `_PROVIDERS` in
`proxy/app/routers/admin_git.py`. Adding a third provider type requires a
code change there and in `scanner_worker/git_clone.py`'s validation
(deliberately a standalone re-implementation of
`proxy/app/services/git_providers.py`'s SSRF logic — kept in lock-step by
convention, not by shared import, because the worker must never be able to
reach `platform_secrets`/`credential_store`).

To register/update a provider (admin or platform_admin role required):

```bash
# 1. Set host/account/enabled/allow_private (validates the host NOW if enabled=true)
curl -s -X PUT -H "Authorization: Bearer $ADMIN_TOKEN" -H "Content-Type: application/json" \
  http://localhost:8000/api/v1/admin/git-providers/bitbucket \
  -d '{
    "host": "bitbucket.corp.example.com",
    "clone_account": "svc-mcp-scanner",
    "enabled": true,
    "allow_private": false
  }'

# 2. Set the clone token (write-only — never returned by GET, stored encrypted
#    in platform_secrets under name "git-<provider>")
curl -s -X PUT -H "Authorization: Bearer $ADMIN_TOKEN" -H "Content-Type: application/json" \
  http://localhost:8000/api/v1/admin/git-providers/bitbucket/token \
  -d '{"token": "<personal-or-service-account-token>"}'
```

Field semantics (from `admin_git.py` / `git_providers.py`):
- `host` — validated via `git_providers.validate_host()` at write time, not
  just at first clone. Loopback/link-local/cloud-metadata ranges (127/8,
  169.254/16, AWS/GCP metadata equivalents) are **always** rejected,
  regardless of `allow_private`.
- `allow_private` — required to accept a host resolving into RFC1918/CGNAT
  ranges (10/8, 172.16/12, 192.168/16, 100.64/8). Setting this **emits a
  high-visibility WARN audit event** (`git_provider_allow_private`) because
  it's a deliberate SSRF-surface widening — expect it to show up in security
  review of `audit_events`.
- `clone_account` — informational identity used for the clone URL's user
  segment; not itself a secret.
- The token you PUT is **never** the same credential the scanner-worker
  actually clones with in the worker process — the worker reads its own
  `GIT_CLONE_TOKEN_<PROVIDER_UPPER>` environment variable (e.g.
  `GIT_CLONE_TOKEN_BITBUCKET`), a narrowly-scoped, read-only credential set
  at deploy time, not pulled from `platform_secrets` at runtime (no DB grant
  to do so — see `infra/db/migrations/V063__scanner_worker_queue.sql`'s
  worker-isolation grants). If you update the provider via the API but never
  set the matching env var on the `scanner-worker` container/service, clones
  for that provider will fail with a missing-token error even though the
  admin API reports `token_set: true`.

## Verification

```bash
# Confirm the provider row and token presence
curl -s -H "Authorization: Bearer $ADMIN_TOKEN" \
  http://localhost:8000/api/v1/admin/git-providers | python3 -m json.tool

# Confirm the worker env actually has the matching token
podman exec mcp-scanner-worker printenv GIT_CLONE_TOKEN_BITBUCKET | wc -c   # non-zero

# Submit a test server from that provider's host and confirm the scan_jobs
# row transitions queued -> running -> completed (not stuck at 'queued' or
# dead_letter'd on a clone failure — see scanner-failure.md)
podman exec mcp-db psql -U mcp_app -d mcp_security -c \
  "SELECT job_id, status, last_error FROM scan_jobs ORDER BY created_at DESC LIMIT 5;"
```

## Prevention / Related

- Any change to `allow_private=true` is a security-relevant event — review
  `admin_config_events` (via `emit_admin_config_event`) whenever a new
  private host is enabled, per `docs/runbooks/private-cidr-allowlisting.md`'s
  same threat model (private-network SSRF surface).
- `docs/runbooks/scanner-failure.md` — what to do if the clone itself starts
  failing after a provider change.
- Keep `scanner_worker/git_clone.py`'s SSRF block-lists in lock-step with
  `proxy/app/services/git_providers.py` if either changes — they're
  intentionally duplicated, not shared, for worker isolation.
