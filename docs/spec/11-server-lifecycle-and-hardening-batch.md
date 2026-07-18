# 11 — Server lifecycle ops-agent + onboarding/isolation hardening batch

Status: **Approved — implementation in progress (2026-07-18)**
Source: user request (server management gap) + external acceptance run
`ExternalTestResults/2026-07-18_21_40_results.md` (findings 1–7) + compose
port-exposure finding (finding 8).

This is a multi-workstream batch. Each workstream below is implemented by a
dedicated agent on a non-overlapping file set. Shared cross-cutting docs
(`README.md`, `docs/ARCHITECTURE.md`, `CLAUDE.md`, `AGENTS.md`) are owned by
the orchestrator and updated after merge — no workstream touches them.

## WS-A — Server lifecycle via a thin ops-agent (feature)

The security proxy must never hold the container runtime socket (least-privilege
/ fail-closed thesis). A separate isolated `ops-agent` holds it; proxy/UI call
it over an authenticated internal API.

- **`ops-agent/`** — small FastAPI service. Mounts `/run/podman/podman.sock`
  + bind-mounts the compose file/build context. **No gateway ingress** —
  reachable only by the proxy on the internal network. Auth: shared secret
  `X-Ops-Token`. **Name allowlist**: refuses any container not matching the
  `mcp-`/`lab-mcp-` prefix (fail-closed) so even a bypassed proxy cannot drive
  it into arbitrary host control. Endpoints:
  `GET /ops/logs?container=&tail=` (`podman logs --tail`, capped ≤1000) ·
  `POST /ops/restart {container}` · `POST /ops/rebuild {service}`
  (`podman-compose up -d --build <svc>`). No host port published.
- **proxy `routers/admin_ops.py`** — authz in front, forwards to agent,
  fail-closed 503 if `OPS_AGENT_URL` unset/unreachable.
  `GET /api/v1/admin/servers/{id}/logs?tail=N` — **gated on `debug_mode=TRUE`**;
  authz platform_admin **or** owner/maintainer. `POST …/{id}/restart`,
  `POST …/{id}/rebuild` — same authz, emits admin-audit event. Container derived
  via `urlparse(upstream_url).hostname`. Config: `OPS_AGENT_URL`,
  `OPS_AGENT_TOKEN` in `core/config.py`.
- **UI `ServerRegistryPanel`** — Edit modal (PATCH `upstream_url`/`service_name`/
  `trust_tier`; backend already supports it), Restart/Rebuild row actions
  (approved servers), View-logs (shown only when `debug_mode` on).
- **Lab wiring** — `lab-ops-agent` service; `OPS_AGENT_TOKEN` in
  `.env.lab.example`; proxy gets `OPS_AGENT_URL`/`OPS_AGENT_TOKEN`. Survives wipe.
- Scoped out (lazy): rebuild = rebuild image from build context + recreate.
  True per-server `git pull latest` needs a repo-path mapping — follow-up.

## Fixes from the acceptance run

1. **Named-profile default-allow footgun** — named profiles (bound at login via
   `?profile=`) are the access-restriction mechanism but default-allow any tool
   with no explicit binding row. Change to **default-deny once the named profile
   has any binding row**: in `invocation.py`, when `profile_uuid` is set and the
   tool has no row but the profile has ≥1 binding, synthesize
   `{"enabled": False}` so OPA denies with `mcp_disabled_for_profile`. Empty
   profile (zero rows) keeps allow-all (avoids bricking an unconfigured profile).
   Proxy-side only — no `authz.rego` change (avoids bundle re-sign).
2. **Entitlement principal not validated** — `POST /servers/{id}/entitlements`
   accepts a bare-username `principal_id` (`human:keycloak:alice`) with 201 that
   never matches the computed `human:keycloak:alice@corp` and silently grants
   nothing. Validate `principal_id` shape (`type:issuer:subject`, non-empty
   subject) before accepting; reject malformed with 422.
3. **`search-kb` broken** — listed `active` + `enabled_for_your_profile: true`
   but every invoke returns `Unknown tool: search-kb`. Root-cause and fix
   (registry/routing/seed mismatch) or remove the phantom catalog entry.
4. **`data_categories` undeclared enum + name-consuming failure** — unknown
   category fails submission *after* claiming the name permanently (no resubmit).
   Make an unknown-category (and other pre-scan validation) failure
   **non-name-consuming**, and surface the valid enum in the error and a
   discoverable spot. `submission.py:_VALID_CATEGORIES`.
5. **"profile" naming collision** — per-identity self-service meta-tools
   (`enable_mcp`/`disable_mcp`/`get_profile`, `target_profile`) vs session-bound
   named profiles (REST-only, no MCP tool). Docs + tool descriptions must
   disambiguate so nobody builds against the wrong system.
6. **Credential-upload has no discoverable route** — `PUT /admin/credentials/{tool_id}`
   only found by reading a test. Surface it in the UI (CredentialsPanel) and/or
   onboarding docs for `entra_client_credentials`-style servers.
7. **Audit taint semantics misleading** — `taint_floor_notice:…` appears under
   `deny_reasons` on an `outcome: allow` event. Keep `deny_reasons` empty for
   allow outcomes; surface the taint notice in a dedicated advisory/notices
   field end-to-end (audit SDK + SIEM/wazuh path).
8. **Lab compose publishes unauthenticated control-plane ports to loopback** —
   `docker-compose.dev.yml` republishes OPA `:8181` (full Rego + grants, no
   auth) and MCP backends `:8100–8113` (raw listener = invocation-path bypass)
   because compose-merge doesn't let a later file *remove* an earlier publish.
   (a) Remove OPA `:8181` ports from `docker-compose.dev.yml`. (b) Remove the
   MCP-backend `ports:` from `podman-compose.lab.yml` (move to a git-ignored
   `docker-compose.override.yml` if host debugging is wanted). (c) Extend
   `scripts/check_network_isolation.py` to fail if OPA or any MCP backend
   publishes a host port under the default lab-up layering. Postgres/Redis/Vault
   loopback ports left as documented dev conveniences (out of scope).
