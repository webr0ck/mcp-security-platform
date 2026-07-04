# Implementation Lessons: How to Get It Right

**Status: matches code at HEAD (`4dfa7b5`).**

This is the "pitfalls a re-implementer WILL hit" chapter. Each lesson is written as **Symptom → Root
cause → Rule** (the rule is language-agnostic and normative, RFC 2119 keywords). Every lesson is
grounded in code and/or a specific fix commit in this repo. Nothing here is aspirational — it is the
list of things that actually broke and how the design now prevents them. Where a control is not
enforced today it is marked **(roadmap)**.

The unifying principle is at the end: the **fail-closed catalogue** — when a security dependency is
unavailable, refuse service.

---

## 1. OAuth enrollment URL must be in the human-visible error message

**Symptom.** A tool needs a delegated credential the caller hasn't enrolled. The proxy returns a
JSON-RPC error whose `data` field carries the enrollment URL — but the MCP client shows the user only
"OAuth enrollment required" with no clickable link. The user is stuck.

**Root cause.** MCP clients render the JSON-RPC error **`message`** string; most **ignore the
structured `data`** object. Putting the actionable URL only in `data` hides it.

**Rule.** Any error whose remediation is "open this URL" **MUST** put the **absolute** URL in the
human-visible `message` string, not only in `data`. Duplicate it into `data` for programmatic clients,
but the `message` is the source of truth. Reference implementation: `proxy/app/routers/mcp_server.py`
`_route_to_registry` error mapping (~L786–L810) and the `invoke_tool` path (~L1101–L1120), error code
**`-32010`**. Fixed in commit **`bee8465`** ("surface OAuth enrollment URL in the -32010 message on the
direct tools/call path").

**Related — `-32000` / "no browser opens".** This is not an enrollment problem; it means the client
never entered the OAuth flow at all. Two causes: (a) the client is configured with transport
`"type": "sse"` instead of `"http"` (Streamable HTTP) — SSE skips the OAuth discovery path; (b)
`PROXY_BASE_URL` is unset, so discovery URLs fall back to the `Host` header (often `localhost`) and
break for remote clients. **Rule:** MCP clients **MUST** use `"type": "http"`, and the server
**MUST** have `PROXY_BASE_URL` set to a client-reachable address. Reference: README "Connecting Claude
Code" + troubleshooting table.

---

## 2. Never fall back to your own client_id for inbound audience verification

**Symptom.** After enabling RFC 7591 dynamic client registration, **every** client gets `401` at the
proxy. Tokens are otherwise valid. Logs show the token's `aud` is `dyn-<uuid>` (or `claude-code`)
while the proxy demanded `mcp-proxy`.

**Root cause.** The proxy used its own OAuth `client_id` as the expected inbound audience. But a
dynamically-registered client receives tokens minted **for that client** — the audience is the
client's id, not the proxy's. Demanding the proxy's own id rejects every dynamic client. Worse, an
"empty audience → substitute my client_id" fallback turns a *disabled* check into a *wrong* check.

**Rule.**
- The proxy's own outbound `client_id` **MUST NEVER** be used as the expected inbound audience.
- An empty/unset audience configuration **MUST** *disable* the audience check explicitly
  (`verify_aud=false` + a logged warning), **MUST NOT** silently substitute any other value.
- Audience validation **MUST** be enabled in production (startup blocked if `OIDC_AUDIENCE` is empty
  while OIDC is enabled).

Reference: `proxy/app/middleware/auth.py::_validate_oidc_jwt` (~L576–L607, the `expected_aud` /
`OIDC_CLIENT_ID` comment block); `proxy/app/core/config.py` production guard (~L506). Normative rule
also in [01-authentication.md](01-authentication.md) §4.2.

---

## 3. Derive callback/enrollment URLs from the host the user actually reached

**Symptom.** Login and enrollment work from `localhost` but break when the lab is reached over a LAN
IP or Tailscale IP: the browser lands on a callback URL for the wrong host, or the enrollment link is
relative/points at `localhost` and 404s.

**Root cause.** Base URLs were hardcoded (or derived from a single configured value) instead of from
the request. In a multi-IP/lab environment the browser can reach the gateway on several addresses; a
hardcoded base URL only matches one.

**Rule.**
- Browser-facing redirect/enrollment URLs **MUST** be derived from the host the request actually
  arrived on — priority `PROXY_BASE_URL` when set, else validated `X-Forwarded-Host`/`Host` — and the
  derived host **MUST** be validated against an allowlist + strict regex (Host-header-injection guard).
- The **public** issuer/base URL (browser redirects) and the **internal** URL (server-to-server
  JWKS/introspection/token fetches over the container network) **MUST** be separate config values.
  Internal fetches use container-network hostnames; discovery docs fetched internally **MUST** be
  rewritten to public URLs before being handed to a browser.

Reference: `oidc_browser.py::_derive_callback_url` (~L91) and `_issuer_url_internal`/`_external`
(~L45); `oauth_metadata.py::_fetch_idp_discovery` rewrite (~L126); `mcp_server.py::_absolute_enrollment_url`
+ `core/public_url.py::derive_public_base_url`. Fix commits: **`6da6913`** ("derive callback URL from
request host for multi-IP lab access"), **`69e369a`** ("enrollment URL is absolute and uses the host the
user reached the gateway on"), **`f74417f`** ("browser auto-redirect to KC login + post-login redirect
to origin").

---

## 4. Implement the MCP protocol state machine once, in the shared invocation path

**Symptom.** Tool calls fail intermittently or with "server not initialized"; or a tool is invoked
but its arguments arrive empty/misplaced.

**Root cause.** Two mistakes: (a) skipping the mandatory MCP handshake ordering; (b) mis-nesting the
`tools/call` parameters.

**Rule.**
- The MCP handshake ordering is mandatory: **`initialize` → `notifications/initialized` → tool
  calls**. Notifications (no `id`) **MUST NOT** produce a response. Reference:
  `mcp_server.py::_dispatch` (~L1324–L1352): `initialize` returns `protocolVersion`/`serverInfo`/
  `capabilities`; `notifications/*` return `None`.
- The `tools/call` params shape is **`{"name": <str>, "arguments": <obj>}` at the top level of
  `params`** — `arguments` is **not** nested under another key. Reference: `_dispatch` tools/call
  (~L1389–L1391) reads `params["name"]` / `params["arguments"]`; `_route_to_registry` builds the
  same shape (~L731–L736).
- This handshake and param handling **MUST** be implemented **once**, in the shared server-to-server
  invocation path, so every backend call goes through it identically (this repo funnels both the REST
  and `/mcp` paths through `services/invocation.py`). Duplicating the handshake per call site is how
  drift and "works here, fails there" bugs appear.

---

## 5. Upstream DNS-rebinding protection rejects container hostnames (HTTP 421)

**Symptom.** The proxy calls a backend MCP server by its container name and gets **HTTP 421
Misdirected Request**; the same server works when called from a browser.

**Root cause.** MCP server SDKs ship DNS-rebinding protection that validates the `Host` header
against an allowlist. Container-network hostnames (e.g. `netbox:8080`) aren't in the default allowlist,
so server-to-server calls are rejected.

**Rule.** For server-to-server calls **behind** the proxy (backend on an isolated network, no browser
access), DNS-rebinding protection **MUST** be disabled **or** the container hostname added to the
server's `allowed_hosts`. It **MUST** stay enabled for any browser-facing server. Backends behind the
proxy also require `stateless_http=True` so the proxy's per-request identity ContextVars reach the
tool (a stateful server is otherwise always-anonymous). Reference: `lab/mcp-servers/netbox/server.py`
(~L90–L93 `enable_dns_rebinding_protection=False`, "LAB ONLY — never disable in production"),
`self-service/server.py` (~L108–L115 stateless_http comment + ~L682), `rag-assistant/server.py`
(~L487). Fix commit for the identity half: **`266b6ef`** ("self-service server needs stateless_http=True
so proxy X-User-Sub identity reaches tools").

---

## 6. Every invoking client needs BOTH a role and a grant

**Symptom.** A client with the right role still gets denied at invoke (or vice versa): RBAC passes but
OPA denies, or the tool isn't visible.

**Root cause.** Two independent authorization layers must both pass. RBAC (role × route) is coarse;
OPA per-tool grants (`client_grants`: `max_risk_level` + tool allowlist) are fine-grained and
**deny-by-default**. Having only one is insufficient.

**Rule.**
- An invoking client **MUST** have **both** a role-based invoke permission (RBAC) **and** a matching
  grant entry (OPA `client_grants`). Reference: `middleware/rbac.py::PATH_ROLE_MAP` (invoke row ~L61)
  + `policies/rego/authz.rego` (`default allow = false`, `data.mcp_grants`).
- **DB roles are authoritative.** JWT-carried roles are a lab convenience and **MUST NOT** augment DB
  roles outside development. Reference: `auth.py` ~L338 (`auth_method == "oidc" and ENVIRONMENT !=
  "development"` → drop JWT roles).
- Grants are pushed to OPA's data API on every mutation, fail-closed (503 if the push fails), with a
  reconcile loop and a startup push. Reference: `services/opa_data_sync.py`, `routers/admin_grants.py`;
  [ARCHITECTURE.md](../ARCHITECTURE.md) §6.

---

## 7. Containerized runtime pitfalls worth recording

**Symptom.** Works in one container engine, breaks in another; nginx returns 502 after a
`compose` recreate; a config edit from inside a container corrupts a bind-mounted file; a container
can't resolve a peer by name.

**Root causes & rules.**

- **nginx upstream DNS caching.** nginx resolves an upstream hostname **once at startup** and caches
  the IP; after a `compose` recreate the backend's IP changes and nginx 502s. **Rule:** configure a
  `resolver` **and** put the upstream in a `set $var` so nginx re-resolves per request. **The resolver
  IP is engine-specific:** Docker's embedded DNS is `127.0.0.11`, which is **NOT present in rootless
  Podman** — use the **subnet gateway** from the container's `/etc/resolv.conf` (e.g. `10.89.6.1`)
  instead. Reference: `lab/nginx/conf.d/mcp-proxy-lab.conf` (~L36–L40: `resolver 10.89.6.1 valid=5s`
  + `set $upstream_proxy http://proxy:8000` + the comment "Podman internal DNS = subnet gateway").
- **Never `sed -i` / rename-write a bind-mounted file from inside a container.** An in-place edit that
  renames-then-replaces breaks the bind-mount inode the host is sharing; the host sees a stale or
  detached file. **Rule:** edit bind-mounted config on the **host**, or write in place without an
  inode swap.
- **Cross-network container name resolution requires a shared network.** Two containers can resolve
  each other by name **only** if they share a network. This platform *deliberately* isolates backends
  onto pairwise networks with the proxy (so a compromised backend can't reach peers) — a direct
  consequence is that backends cannot name-resolve each other, which is intended, not a bug. **Rule:**
  when name resolution "mysteriously" fails, check shared-network membership before DNS. Reference:
  [ARCHITECTURE.md](../ARCHITECTURE.md) §4 + `scripts/check_network_isolation.py`.

These are engine-portability lessons; the lab runs **rootless Podman**, the `engine` tier runs
**Docker** — a re-implementer targeting either must not assume the other's DNS/mount semantics.

---

## 8. Route handlers returning raw/streaming responses must opt out of schema introspection

**Symptom.** The web framework raises at startup or first request on a handler that returns a
union/streaming type — e.g. FastAPI tries to build a response model from a
`JSONResponse | StreamingResponse` return annotation and fails.

**Root cause.** Frameworks introspect a handler's return type to generate a response schema. A handler
that returns a raw or streaming response (the MCP transport can return either a single JSON-RPC object
or an SSE stream) has no coherent schema to introspect, and the framework chokes on the union.

**Rule.** Any handler that returns a raw/streaming response **MUST** opt out of framework
response-schema introspection (in FastAPI: `response_model=None` on the route decorator). Generalize:
transport endpoints are not typed DTOs — tell the framework not to model them. Reference:
`mcp_server.py` `@router.post("/mcp", response_model=None)` (~L1505) and
`@router.get("/mcp", response_model=None)` (~L1580), both annotated `-> JSONResponse |
StreamingResponse`.

---

## 9. Key session taint on the authenticated client identity, not the auth method

**Symptom.** A client that has ingested untrusted (tainted) tool output — and should therefore be
blocked from high-sensitivity sinks — evades the taint floor by re-authenticating with a **different
auth method** (e.g. switch from session cookie to API key) and calls the sink anyway.

**Root cause.** The taint state was keyed on the session/auth-method rather than the stable logical
identity. Different auth methods for the same principal produced different taint keys, so the floor
didn't follow the client.

**Rule (LOGIC-005).** Session-taint state **MUST** be keyed on the **authenticated client identity**
(the logical `client_id`/principal), **not** on the auth method or session token. Switching auth
methods **MUST NOT** reset the taint floor. Reference: `services/invocation.py` ~L428
(`is_tainted_for_principal(client_id)` with the inline note "keyed on logical identity, not
auth-method (LOGIC-005)"), taint write at ~L1033–L1042, `services/taint_store.py`. The taint floor
itself is the RFC-0001 §8.1 trust-tier mechanism; keying is the security-critical detail.

---

## Fail-closed catalogue

The design's overriding rule: **when a security dependency is unavailable, refuse service.** The
implementation chooses `5xx`/deny over fail-open at every one of the following points. A faithful
re-implementation **MUST** preserve each.

| # | Dependency / condition unavailable | Response | Reference |
|---|---|---|---|
| 1 | **OPA unreachable** (policy engine down, or `null`/missing result) | `503 OPA_UNAVAILABLE` (deny); null normalised to deny (INV-004) | `services/policy.py`; `services/invocation.py` ~L482–L496 |
| 2 | **Audit emit failure** on any invocation/consent/enrollment path | `500`; no un-audited execution (INV-001) | `invocation.py` ~L1466–L1502 (`AuditEmissionError`); `routers/oauth.py` audit helpers |
| 3 | **Unknown/empty injection mode** | `CredentialInjectionError` — refuse to forward an unauthenticated upstream call; `""` ≠ `none` | `credential_broker/dispatcher.py` ~L170–L176 |
| 4 | **Session-JTI revocation store error** (Redis+DB) | deny (never allow a revoked/forged token), INV-014 | `middleware/auth.py::_is_session_jti_revoked` ~L401 |
| 5 | **MCP-profile lookup** DB error + cache miss | `503` (never an empty = unrestricted profile), INV-015 | `invocation.py::_lookup_profile_with_cache` ~L521–L539; `oidc_browser.py` ~L403–L419 |
| 6 | **Vault token empty** / broker not initialized at call time | deny credential injection (broker fail-closed) | `dispatcher.py` ~L181–L191; README "Credential broker" |
| 7 | **Weak/short master key** (< 256-bit entropy) | `KMSError` at load (HKDF would silently stretch a weak secret) | `credential_broker/kms.py` ~L37–L43 |
| 8 | **JWKS unavailable** during ID-token verify | `503` (never issue a session on unverified claims), AUTH-002 | `oidc_browser.py` ~L494–L508 |
| 9 | **Gateway shared secret** empty in production | startup blocked (mTLS-CN path would silently disable), F-001 | `core/config.py` ~L525 |
| 10 | **Rate-limiter (Redis) error** on `/oauth/register` | reject (`False` = fail-closed), not bypass | `oauth_metadata.py::_check_register_rate_limit` ~L74–L90 |
| 11 | **LLM (Ollama) audit** unreachable at registration, production | `503` when `REQUIRE_LLM_AUDIT=true` (no fail-open registration) | [ARCHITECTURE.md](../ARCHITECTURE.md) §5.4; `core/config.py` |
| 12 | **Server trust-tier lookup** DB error | treat as untrusted (taint floor deny), fail-closed | `invocation.py` ~L1123–L1124 |
| 13 | **Session DB write** fails after login | `503` (don't issue an unregisterable JWT) | `oidc_browser.py` ~L617–L625 |

> Normative principle: **no fail-open path.** Every dependency whose absence could weaken an
> authorization, identity, credential, or audit guarantee **MUST** cause a denial or a `5xx`, never a
> silent allow. Availability is deliberately traded for this guarantee.
