# Onboarding a new MCP server — architecture, best practice, gotchas

This is the canonical reference for adding a new MCP server to the platform
(self-service flow or admin/UI path). It exists because a full-functionality
audit of the gateway (2026-07-04, see "Audit findings" below) surfaced six
concrete gaps — most caused by a new server not following a pattern the rest
of the platform assumes. Read this **before** onboarding a server, not after
debugging why it's half-visible.

## 1. The two ways a server gets exposed

1. **Self-service** (`lab-mcp-self-service` backend, tools `plan_mcp_server` →
   `get_auth_mode_recommendation` → `submit_mcp_server` → `check_submission_status`).
   Produces a `server_registry` row + a supply-chain scan; a human reviewer
   approves it.
2. **Admin/UI path** (`proxy/app/routers/server_registry.py` +
   `proxy/app/services/server_onboarding.py`, driven from the admin portal).
   Same end state, skips the submission/scan workflow.

Both converge on the same three tables — get these right and discovery,
entitlement, and invocation all just work:

| Table | Purpose | Gotcha |
|---|---|---|
| `server_registry` | The MCP server itself. `status` must be `'approved'` or nothing entitled to it is reachable. | A server stuck in `pending`/`draft` silently fails entitlement (see §3) — no error, just absence from `tools/list`. |
| `tool_registry` | One row per **callable name**. | See §2 — this is the single most common mistake. |
| `entitlement` (+ `server_role_grant`) | Per-principal or per-role grant to a `server_id`. | `principal_id` format is `human:{OIDC_ISSUER_ID}:{sub}` for OIDC users, `human:apikey:{client_id}` for API keys, `agent:{MTLS_CA_ID}:{cn}` for mTLS — get the prefix wrong and the grant silently never matches. |

## 2. Registry granularity: pick ONE pattern per server, not a mix

`tool_registry` supports two valid shapes. **Decide up front which one your
server uses — do not mix them**, or you reproduce Finding #4 below.

- **Pattern A — one row per function** (what `lab-mcp-self-service` does:
  `plan_mcp_server`, `get_auth_mode_recommendation`, `submit_mcp_server`,
  `check_submission_status` are each their own `tool_registry` row, all
  sharing one `server_id`). Every function gets independent OPA/quarantine/
  risk_score treatment and is individually visible in `tools/list` and
  directly callable (`tool_name="check_submission_status"`).
- **Pattern B — one row for the whole server** (what `notes-store`,
  `rag-assistant`, `search-kb` do: a single registry row; the server's real
  sub-tools — `create_note`, `list_notes`, etc. — only exist on the upstream
  and are discovered live via `tools/list` proxying).  For these,
  `invoke_tool(tool_name="notes-store", method="tools/call",
  arguments={"name": "create_note", "arguments": {...}})` is the *only*
  supported call shape — `tool_name` identifies the registry row to
  authorize against; `arguments.name` is forwarded to the upstream. There is
  no top-level `create_note` function and there never will be — don't expect
  one, and don't tell users to call sub-tools directly.

If you want per-function quarantine/audit granularity for a multi-tool
backend, register each function individually (Pattern A) instead of
half-registering it and expecting the gateway to infer sub-tool structure.

## 3. Entitlement + profile: know the actual default, and keep the display honest

- `server_registry.status` must be `'approved'` for entitlement to ever
  return `entitled=True` (`proxy/app/services/entitlement.py`), regardless of
  how many `entitlement`/`server_role_grant` rows exist. Check this first
  when a newly-onboarded server "isn't showing up."
- **Absence of an `mcp_profiles` row is a platform-wide default-ALLOW**, not
  default-deny (`_lookup_profile_row` in `mcp_server.py` — this is
  deliberate, documented behavior, not a bug). A tool only becomes
  unreachable for a principal once an explicit `enabled=false` row exists.
  Any UI/meta-tool that *displays* enabled/disabled state (`list_available_mcps`,
  `/api/v1/profiles`) **must default absent rows to `true`** to match — two
  places (`mcp_server.py::_handle_list_available_mcps`,
  `profiles.py::list_available_mcps`) got this backwards and showed
  "disabled" for tools a real call would actually allow. If you add a new
  display surface for profile state, default it the same way.

## 4. Ingress: backend containers cannot call the proxy directly — except by explicit exception

`proxy/app/middleware/ingress.py` (SEC-05) rejects any inbound peer to
`proxy:8000` that isn't the gateway or loopback, because Podman bridge
networks are bidirectional and a backend dialing the proxy back would bypass
gateway-level enforcement. **If your new server needs to call back into the
proxy's REST API** (like `lab-mcp-self-service` calling
`/api/v1/design-assist` and `/api/v1/submissions` over its dedicated
`mcp-self-service-net` pairwise network), it will get a 403
`INGRESS_DENIED` unless its container hostname is added to
`PROXY_INGRESS_TRUSTED_HOSTS` on the `proxy` service (see
`podman-compose.lab.yml`). This is a deliberate, narrow exception — only add
a hostname here if the backend authenticates every such call with its own
credential (API key, forwarded OAuth token); ingress-trust is a network-layer
allowance, not an authn bypass.

Most servers never need this — only ones that are themselves a client of the
proxy's REST API (onboarding/self-service-style backends), not plain tool
providers.

## 5. `invoke_tool` denials must be legible, not "internal error"

`invoke_tool` and its direct-registry sibling both call into the same OPA
policy path (`proxy/app/services/policy.py::OPADenyError`). Catch this
exception explicitly and surface `exc.reasons` — don't let it fall into a
generic `except Exception` that returns "internal error" indistinguishable
from an actual crash. (Both call sites in `mcp_server.py` now do this —
follow the same pattern for any new dispatch path you add.)

## 6. OAuth / MCP client discovery (RFC 9728) — exact-match `resource`

If your server (or the gateway itself) is a protected MCP resource, some
clients (Codex, notably) require:

- `/.well-known/oauth-protected-resource` **and** a path-suffixed variant
  matching the resource path exactly (e.g.
  `/.well-known/oauth-protected-resource/mcp` for a resource living at
  `/mcp`) — both public, unauthenticated, 200 JSON.
- The `"resource"` field in that JSON must be the **exact** URL the client is
  calling (`https://host/mcp`, not just `https://host`) — an origin-only
  value causes some clients to conclude the resource "doesn't support OAuth"
  and abort before ever trying the flow.
- The `401` on the protected path must point its `WWW-Authenticate:
  resource_metadata=` at that same path-suffixed URL.

See `proxy/app/routers/oauth_metadata.py` and
`proxy/app/middleware/auth.py` for the reference implementation.

## 7. ModSecurity vs. free-text fields describing your own server's URL

`plan_mcp_server`/`submit_mcp_server`/`get_server_scaffold` accept free-text
`intent`/`description` fields where a submitter naturally writes their new
server's own upstream URL — often `http://127.0.0.1:PORT` for local dev/testing.
CRS rule 934110 ("SSRF: cloud provider metadata URL in parameter") flags any
loopback/IP-literal URL in ARGS and blocks the request with a raw nginx 403
(not a JSON-RPC error) *before* it reaches the app. This is scoped narrowly in
`lab/nginx/conf.d/mcp-proxy-lab.conf` (rule id 9006) to requests whose body
references one of these specific tool names — do not widen it to all of `/mcp`.
**Gotcha when writing a `modsecurity_rules` regex containing a literal `"`:**
nginx's ModSecurity connector unescapes `\"` in the directive value before
ModSecurity's own parser sees it, silently truncating the rule and crash-
looping the gateway on every reload. Avoid needing literal quotes in the
regex (match bare identifier strings instead of `"key": "value"` shapes).

## 8. Passthrough injection_mode ≠ "forward the caller's gateway token"

`injection_mode='passthrough'` (used by `lab-mcp-self-service`'s tools) does
**not** automatically forward the caller's own `Authorization` bearer token
to the upstream. It forwards whatever the *client* explicitly set in the
`X-Downstream-Authorization` header on its original `/mcp` request
(`proxy/app/services/invocation.py` — `inbound_auth`) — a mechanism for
OAuth-passthrough tools (e.g. a client presenting its own M365/Bitbucket
token), not for "identify me to the downstream service." For a normal MCP
client that never sets that header, `inbound_auth` is `None` and **no**
Authorization header reaches the upstream at all. `lab-mcp-self-service`
handles this by falling back to its own `SELF_SERVICE_API_KEY` service
credential when no user token is present (see `_oauth_headers()` in
`lab/mcp-servers/self-service/server.py`) — if you rely on this fallback,
make sure the key is actually valid (see the seeder gotcha below).

**Seeder key rotation vs. running containers:** `lab/seeder/seed.py`'s
`_seed_self_service_api_key()` is designed to revoke-and-rotate this key on
every seeder run, rewriting `.env.lab`. But a container only reads `.env.lab`
at *create* time — re-running the seeder without recreating
`lab-mcp-self-service` leaves the running container holding a now-revoked
key, so its passthrough-fallback calls back into the proxy start failing
with 401 (surfaced to the end user as a generic `"scaffold_unavailable"` /
similar swallowed-error message, since these tools intentionally never leak
raw internal errors to the caller). If you re-run the seeder, always
`podman-compose ... up -d --force-recreate lab-mcp-self-service` (or restart
whatever container holds this key) immediately after.

## 9. Enrollment tracking must list every OAuth-gated service

`_OAUTH_SERVICES` in `mcp_server.py` drives what `enrollment_status` reports
as pending. Every downstream that can raise `CredentialEnrollmentRequiredError`
(check `tool_registry.injection_mode = 'user'`) belongs in that list — a
service missing from it will still block calls with a real enrollment URL,
but the meta-tool a user checks won't warn them it's needed. Add your new
server here the moment it uses per-user OAuth injection.

## Audit findings this doc is derived from (2026-07-04 functional check)

1. **Fixed** — `list_available_mcps`/`/api/v1/profiles` defaulted absent
   profile rows to `enabled_for_your_profile: false`, contradicting the
   platform's actual default-allow enforcement. → §3.
2. **Fixed** — `invoke_tool` returned a generic "internal error" for OPA
   policy denials (indistinguishable from a real crash). → §5.
3. **Investigated, closed as not-a-bug** — `self-service-mcp`, `rag-assistant`,
   `search-kb`, `notes-store` returned client-side "Unknown tool" for direct
   top-level calls in the audit. DB inspection (2026-07-04) showed
   `server_registry.status='approved'`, valid `entitlement` rows for
   `alice@corp`, and no restricting `mcp_profiles` row for all four. Confirmed
   by directly invoking `_registered_tools_for_client()` in-process inside the
   `mcp-proxy` container with alice's exact principal/roles — the real
   `tools/list` result **does include all four**. The gateway's discovery
   logic is correct; the audit's "Unknown tool" errors were a client-side
   artifact (most likely a stale/cached function list from earlier in that
   MCP client session), not a reproducible server defect. No code change was
   needed.
4. **Fixed** — `invoke_tool`'s `tools/call` looked up `arguments.name` (the
   sub-tool) directly in `tool_registry`, which only works for Pattern-A
   servers. Now falls back to the parent `tool_name` row for Pattern-B
   servers. → §2.
5. **Fixed** — `netbox` used the same per-user OAuth injection path as
   `dex`/`m365`/`bitbucket` but was missing from `_OAUTH_SERVICES`. → §9.
6. **Fixed** — `check_submission_status`/`submit_mcp_server` hit
   `INGRESS_DENIED` calling the proxy over the legitimate
   `mcp-self-service-net` pairwise network; added to
   `PROXY_INGRESS_TRUSTED_HOSTS`. → §4.
7. **Fixed (separate request, same day)** — Codex `mcp login` reported "No
   authorization support detected" because `/.well-known/oauth-protected-resource`
   returned `resource` as the bare origin instead of the exact `/mcp` URL,
   and no path-suffixed variant existed. → §6. (Two further layers under the
   *same* symptom, found once OAuth login itself started working: CRS rule
   931100 also blocked `POST /oauth/register`'s loopback `redirect_uri`, and
   codex's own TLS client didn't trust the local mkcert dev CA — both fixed;
   the latter required the user to run `sudo mkcert -install`.)
8. **Fixed (live Codex end-to-end test, same day)** — `plan_mcp_server` /
   `submit_mcp_server` calls 403'd at the nginx layer (CRS 934110 flagging the
   caller's own `http://127.0.0.1:PORT` description text as SSRF), and
   `get_server_scaffold` silently returned `"scaffold_unavailable"` because
   `lab-mcp-self-service`'s fallback `SELF_SERVICE_API_KEY` was stale/revoked
   in the DB relative to `.env.lab` (seeder rotated it on a later run without
   the container being recreated). → §7, §8.
