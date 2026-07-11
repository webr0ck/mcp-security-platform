# Runbook: Releasing a Quarantined Tool (CR-07 Evidence-Gated Release)

## Symptom

- A reviewer calls `POST /api/v1/tools/{tool_id}/release` and gets a 422
  `RELEASE_DENIED`, a 403 `FORBIDDEN`, a 409 `NOT_QUARANTINED`, or a 502
  `UPSTREAM_UNREACHABLE`, and the tool stays `quarantined`.
- A tool was critical-risk at registration (or MCP-005 name-collision
  quarantined) and needs a human-reviewed path back to `active`.

## What this endpoint actually requires (read before opening a ticket)

`POST /api/v1/tools/{tool_id}/release` (`proxy/app/routers/tools.py`,
`release_tool`) is the **only** path from `quarantined` → `active` for both
platform-deployed and self-hosted tools. It is deliberately stricter than
the generic `PATCH /tools/{tool_id}` (which has its own inline evidence gate
for the same transition, but a plain `admin` role suffices there). The
release endpoint requires, in order:

1. **Role**: caller must have `admin`, `platform_admin`, or
   `security_reviewer` — a bare `admin` is not special-cased above the
   others; all three are equally accepted here. Enforced twice: once inline
   in `release_tool`, and once in `proxy/app/middleware/rbac.py`'s
   `PATH_ROLE_MAP` (`POST /api/v1/tools/{tool_id}/release` rule) — the RBAC
   rule for the parameterized `/release` path is listed **before** the
   generic `POST /api/v1/tools` prefix rule (which only allows
   `admin`/`platform_admin`) specifically so a `security_reviewer`-only
   principal isn't 403'd by the broader rule matching first. This ordering
   bug was found and fixed live during WP-B3 acceptance testing — if a
   `security_reviewer` gets 403'd again, check that this rule is still
   listed ahead of the plain `/api/v1/tools` rule in `PATH_ROLE_MAP`.
2. **Tool must currently be `quarantined`** — else `409 NOT_QUARANTINED`.
3. **Evidence gate** — the parent server (`tool_registry.server_id` →
   `server_registry`) must be:
   - `server_registry.status == 'approved'`, AND
   - `server_registry.scan_status IN ('passed', 'not_applicable')`.
   A scan status of `'review_required'` is **deliberately insufficient**
   here — that state exists precisely so a human clears the underlying scan
   concern first, not by rubber-stamping the release.
4. **Live invocation probe** — the endpoint sends a real MCP `initialize`
   JSON-RPC handshake to the tool's `upstream_url`, reusing the exact
   SSRF-validated, DNS-rebind-revalidated, pinned-IP connection path
   `discover_tools` uses (`validate_server_url` +
   `revalidate_upstream_ip_at_invoke` + `PinnedIPTransport`). If the probe
   fails or the upstream is unreachable, the tool is **never** released
   regardless of scan/approval state — paperwork alone is not enough.

On success: `status='active'`, `released_by`, `released_at`,
`release_notes` are recorded (distinct, immutable attribution — separate
from the generic `TOOL_STATUS_CHANGED` path), and a dedicated
`TOOL_RELEASED` audit event is emitted (so an auditor can find every
deliberate quarantine release without pattern-matching generic status
changes).

## Diagnosis

```bash
# What's actually blocking release? Check tool + parent server state directly.
podman exec mcp-db psql -U mcp_app -d mcp_security -c \
  "SELECT t.tool_id, t.name, t.status AS tool_status, t.server_id,
          s.status AS server_status, s.scan_status
   FROM tool_registry t LEFT JOIN server_registry s ON s.server_id = t.server_id
   WHERE t.tool_id = '<tool_id>';"

# Confirm caller's realm roles actually include one of admin/platform_admin/security_reviewer
# (decode the access_token's roles claim, or check Keycloak's role mapping — see
# docs/runbooks/keycloak-client-setup.md)

# If you got UPSTREAM_UNREACHABLE / 502: is the upstream actually up right now?
curl -s -X POST <upstream_url> -H "Accept: application/json, text/event-stream" \
  -d '{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2024-11-05","capabilities":{},"clientInfo":{"name":"manual-probe","version":"1.0.0"}}}'

# If you got RELEASE_DENIED with "Invocation probe rejected upstream" — check
# the SSRF/CIDR path (upstream may resolve to a private IP not in the allowlist)
```

## Resolution

Fix whichever gate is failing, in this order:

1. **Wrong role** — grant the caller `admin`, `platform_admin`, or
   `security_reviewer` in Keycloak (see
   `docs/runbooks/keycloak-client-setup.md`); do not work around this by
   escalating to a broader role than the task needs.
2. **Server not approved** — the parent server submission needs to go
   through `POST /api/v1/admin/submissions/{server_id}/approve` first (see
   the submission review flow in `proxy/app/routers/submission.py`).
3. **Scan not passed** — resolve the underlying scan finding; see
   `docs/runbooks/scanner-failure.md` for `scan_status='error'` (missing
   tool) vs a genuine `blocked`/`review_required` finding that needs
   remediation in the submitted repo itself.
4. **Invocation probe failing** — confirm the upstream server is actually
   running and reachable from the proxy's network position (not just from
   your workstation); check
   `docs/runbooks/private-cidr-allowlisting.md` if it's self-hosted on a
   private range.

Once all gates are clear, retry:
```bash
curl -s -X POST -H "Authorization: Bearer $REVIEWER_TOKEN" -H "Content-Type: application/json" \
  http://localhost:8000/api/v1/tools/<tool_id>/release \
  -d '{"notes": "Cleared after re-scan; server approved 2026-07-07."}'
```

## Verification

```bash
# Tool status flips to active, release_* columns populated
podman exec mcp-db psql -U mcp_app -d mcp_security -c \
  "SELECT status, released_by, released_at, release_notes FROM tool_registry WHERE tool_id = '<tool_id>';"

# TOOL_RELEASED audit event present
podman exec mcp-db psql -U mcp_app -d mcp_security -c \
  "SELECT event_type, client_id, event_ts FROM audit_events
   WHERE event_type = 'TOOL_RELEASED' AND event_ts > now() - interval '1 hour'
   ORDER BY event_ts DESC;"

# Tool is actually invocable end-to-end now
curl -s -X POST -H "Authorization: Bearer $USER_TOKEN" \
  http://localhost:8000/api/v1/tools/<tool_id>/invoke -d '{...}'
```

## Prevention / Related

- Don't try to bypass this endpoint via `PATCH /tools/{tool_id}
  {"status":"active"}` to skip the invocation probe — the PATCH path has its
  own copy of the server-approved/scan-passed evidence gate (same fields,
  same logic) and will 422 the same way; it just never runs the live probe,
  so it is not actually a lighter-weight release path, only a
  less-audited one. Prefer `/release` for any real quarantine clearance.
- `docs/runbooks/scanner-failure.md` — the most common blocker in practice.
- `docs/runbooks/private-cidr-allowlisting.md` — second most common blocker,
  for self-hosted tools.
