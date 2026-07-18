# PRD-0011 — Profiles MVP + reproducible onboarding

Status: **Design approved, pre-implementation**
Date: 2026-07-18
Source: `acceptance-test-report-2026-07-18.md` (findings #2, #3, #5, #6, #7)
plus WS-5 Codex OAuth issuer workaround (see [[codex-oauth-iss-regression]]).

## Problem

The 2026-07-18 onboarding acceptance test proved the end-to-end MCP integration
flow works live, but surfaced five gaps that block a *reproducible* MVP where an
MCP client (Claude Code / Codex over OAuth PKCE) can connect **scoped to a named
profile**:

- **#7** — Named-profile scoping never engages for MCP SDK clients. The filter
  machinery (`mcp_server.py` / `tools.py`, keyed on `request.state.profile_uuid`)
  already exists, but `profile_uuid` is populated **only** on the browser-session
  path (`middleware/auth.py:356`). The external OIDC **bearer** path
  (`auth.py:285`) never sets it, and a Keycloak access token carries no `profile`
  claim to read from. Result: profiles are invisible to every SDK client.
- **#6** — `self-service-mcp` is registered as one `tool_registry` row whose name
  matches none of its 5 real upstream functions
  (`get_profile`/`enable_mcp`/`disable_mcp`/`enable_function`/`disable_function`),
  so profile management via the MCP client always fails `Unknown tool`.
- **#2** — `server_registry.self-service.upstream_allowlist_entry` ships as the
  literal template placeholder `__SELF_SERVICE_UPSTREAM_CIDR_PLACEHOLDER__`,
  SSRF-blocking every self-service tool call on a fresh install.
- **#3** — The WAF 931100 (RFI) field-scoped exemption for `json.upstream_url`
  was live-patched but not committed, so a fresh gateway build re-blocks any
  `http://<ip>/...` submission body.
- **#5** — No `oauth_provider_policy` row exists for any Entra issuer, so
  `entra-id-directory` fails closed (`422 OAUTH_POLICY_VIOLATION`) at reviewer
  approval.

## Goals

1. An MCP SDK client authenticated by OAuth PKCE bearer can connect scoped to a
   named profile and see only the tools that profile enables.
2. Profile state is manageable from that client via the 5 real self-service
   functions.
3. The full onboarding flow (submit → scan → approve → discover → invoke) works
   on a **fresh install**, not just the current lab instance.
4. `entra-id-directory` can be approved through the real reviewer gate.
5. A current Codex client (≥0.143) connects over OAuth without a client downgrade
   (platform-side workaround).

## Non-goals

- Changing the browser-session profile path (it works; untouched).
- Introducing per-user profile **ownership** — profiles are platform-level and
  only ever *narrow* visibility (a `profile_mcp_bindings` filter layered on top of
  entitlements; it cannot grant a tool the caller lacks). No escalation surface,
  so no ownership model is warranted. (Confirmed against `V036`.)
- The taint-floor mode/delegation work (tracked separately in PRD-0010).

## Design

### WS-1 — Profile scoping on the bearer path (#7)

The bearer path must resolve a client-supplied **profile GUID** into
`request.state.profile_uuid`, after which the existing filter machinery does the
rest unchanged.

- **Client signal:** `?profile=<uuid>` on the `/mcp` URL (static per connection).
  A **GUID, not a name** — unguessable, prevents profile-name enumeration /
  bruteforcing. `X-MCP-Profile: <uuid>` header accepted as a fallback.
- **Shared resolver:** extract `_resolve_active_profile_uuid(uuid) -> str | None`
  (`SELECT id FROM profiles WHERE id = :uuid AND is_active = TRUE`). The browser
  path's inline name-based lookup stays as-is; the resolver is UUID-based and used
  by the bearer path only (name enumeration is the browser path's own concern and
  out of scope).
- **Wiring:** in `middleware/auth.py`, after identity resolution, when
  `auth_method == "oidc"` (bearer) and `_session_profile_uuid` is unset, read the
  profile GUID from query/header and resolve it into `_session_profile_uuid`
  (which line 356 already promotes to `request.state.profile_uuid`).
- **Fail-closed (trust boundary — no shortcuts here):**
  - No `?profile` supplied → `profile_uuid = None` → legacy full-visibility path
    (unchanged, backward compatible).
  - Supplied but unknown/inactive GUID → **`403`**. It must NOT fall back to the
    no-profile path — "no profile" grants *more* visibility than the profile
    would, so a silent fallback is fail-open against a restriction.
  - DB error during resolution → **`503`** (mirrors browser path INV-015).
- **Portal "copy connection URL" (browser):** the profiles view in `ui/` gains a
  copy-to-clipboard affordance that yields the scoped connection URL
  `{proxy}/mcp?profile=<uuid>` for a profile, so a user can paste a ready-made,
  GUID-embedded link into their MCP client config. Reuses the profile UUID the
  portal already loads; no new API. (Detailed wiring in the plan.)

### WS-2 — self-service-mcp → 5 real tool rows (#6)

Replace the single `self-service-mcp` `tool_registry` row with 5 rows named for
the real upstream functions. Schemas derived from `lab/tests/test_self_service_mcp.py`:

| tool name | required | optional |
|---|---|---|
| `get_profile` | — | `mcp_name`, `target_profile` |
| `enable_mcp` | `mcp_name` | `target_profile` |
| `disable_mcp` | `mcp_name` | `target_profile` |
| `enable_function` | `mcp_name`, `function_name` | `target_profile` |
| `disable_function` | `mcp_name`, `function_name` | `target_profile` |

`upstream_url = http://<self-service host>:8000/mcp`, `injection_mode` per the
existing rows. Applied in three places for consistency:

1. `lab/seeder/sql/tools.sql` (line ~225) — lab seed.
2. `infra/db/migrations/V052__self_service_default_seed.sql` (line ~41) — default
   platform seed (new installs).
3. **New forward migration `V0xx__self_service_profile_tools.sql`** — for existing
   installs: delete the old `self-service-mcp` row, insert the 5 rows (idempotent
   `ON CONFLICT`).

### WS-3 — Fresh-install fixes (#2, #3)

- **#2:** The placeholder is meant to be substituted at deploy time. First check
  whether the substitution belongs in `lab-setup.sh` (precedent: the
  `init-db-roles.sh` fix) rather than a hardcoded migration — the CIDR is
  environment-specific (`10.89.0.0/16` podman lab vs. the docker bridge subnet),
  so a blind hardcode in a shared migration would be wrong for one of them.
  Decision recorded in the implementation plan.
- **#3:** The field-scoped `SecRuleUpdateTargetById 931100 "!ARGS:json.upstream_url"`
  exemption is already present in the working tree of
  `lab/modsecurity-crs/modsecurity-override.conf` (uncommitted). Verify and commit.

### WS-4 — Entra oauth_provider_policy row (#5)

Add the Entra issuer trust-anchor row to `oauth_provider_policy` so
`entra-id-directory` passes the reviewer-time OAuth gate. This is a **new IdP
trust anchor** — a genuine security-posture change, not a mechanical fix — so it
is reviewed by the `appsec-reviewer` agent before commit and may land as its own
commit (or be held) independently of WS-1..3.

### WS-5 — Codex OAuth "missing required issuer" workaround (platform-side)

Current Codex (≥0.143, rmcp PR896 / openai/codex#31573) fails OAuth against the
platform with "missing required issuer". The fix is **platform-side** — we do NOT
force clients to downgrade to 0.141.0 (the prior stopgap).

Likely cause (confirm by reproduction, not assumption): the proxy serves
`{proxy}/.well-known/oauth-authorization-server` with `issuer =
OIDC_ISSUER_URL` (Keycloak), not the proxy origin — while pointing
`authorization_servers` at the proxy so it can filter `scopes_supported`. Strict
RFC 8414 clients validate `issuer == fetch-origin`; and the protected-resource
metadata (`_protected_resource_metadata`) currently carries no `issuer` field at
all. Either is a plausible trigger.

Approach (**RCA first — systematic-debugging**):

1. Reproduce with a current Codex client; capture the exact metadata document and
   field the client rejects (401/WWW-Authenticate chain + which `.well-known` doc
   fails to deserialize).
2. Apply the **minimal** accommodation in `proxy/app/routers/oauth_metadata.py`
   that satisfies current Codex without breaking Claude Code — e.g. add `issuer`
   to the protected-resource metadata and/or align the AS-metadata `issuer` with
   the fetch origin. The file already carries client-specific accommodations
   (see the `resource`-path note for Codex), so this is in-pattern.
3. Fallback only if no clean platform accommodation exists: document the 0.141.0
   pin as a known-issue. This is the last resort, not the plan.

Constraint: the change must not regress Claude Code's working OAuth flow, and must
keep the scope-filtering behavior (`scopes_supported` override) intact.

## Composition

`get_profile` (WS-2) returns a profile's UUID → that UUID goes into the MCP client
URL `?profile=<uuid>` (WS-1) → the connection is scoped → `profile_mcp_bindings`
filters tool visibility. WS-3/WS-4 make the whole flow reproducible on a clean build.

## Acceptance criteria

Verification bar: **full live end-to-end proof on a fresh lab boot** (unit /
integration tests in addition, not instead).

1. **WS-1 unit/integration:** bearer request with valid `?profile=<uuid>` →
   `request.state.profile_uuid` set; unknown/inactive GUID → 403; DB error → 503;
   no param → None. Tests in `proxy/tests/`.
2. **WS-1 live:** an OAuth-PKCE MCP client connecting with `?profile=<uuid>` sees
   only the profile's enabled tools; a `disable_mcp`'d server is **absent** from
   `tools/list` for that connection and present without the profile.
3. **WS-2 live:** all 5 functions callable by real name via the MCP client
   (`get_profile`, `enable_mcp`/`disable_mcp`, `enable_function`/`disable_function`);
   no `Unknown tool`.
4. **WS-3 live:** on a fresh `lab-up`, a self-service tool call succeeds (no
   `upstream_revalidation_failed`) and a `provide-url` with an `http://<ip>/...`
   body is not WAF-blocked — **without** any manual live patch.
5. **WS-4 live:** `entra-id-directory` reaches an approvable state through the real
   reviewer gate (no `422 OAUTH_POLICY_VIOLATION`).
6. **WS-1 browser:** the portal profiles view offers a "copy connection URL"
   action that yields `{proxy}/mcp?profile=<uuid>` for the selected profile.
7. **WS-5 live:** a current Codex client (≥0.143, not downgraded) completes the
   OAuth flow and connects — no "missing required issuer"; Claude Code's OAuth
   flow still works unchanged.
8. **Regression:** `make security-check` green; a no-`profile` bearer connection
   behaves exactly as before (full legacy visibility).

## Risks

- **Browser-path divergence:** bearer uses UUID, browser uses name. Acceptable —
  they are distinct entry points with distinct threat models; unifying is a larger
  change and out of scope.
- **WS-4 trust anchor:** adding an IdP trust anchor widens who can be approved.
  Gated on `appsec-reviewer` sign-off.
- **WS-3 #2 env-specificity:** the CIDR fix must not hardcode one environment's
  subnet into a shared migration. Resolved by the substitution-vs-migration
  decision in the plan.
