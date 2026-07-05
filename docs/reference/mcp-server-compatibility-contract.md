# MCP Server Compatibility Contract

Status: v0.1 draft (Codex review CR-06). This is the platform's security envelope on top of the
[Model Context Protocol specification](https://modelcontextprotocol.io/specification) — it defines
what an upstream server must do to be compatible with this platform's gateway, independent of the
language/framework it's written in. Generated scaffolds (`services/scaffold_generator.py`) are
**reference implementations of this contract**, not the contract itself — a server that never touches
the scaffold generator must still satisfy everything below to be onboarded.

## 1. Transport

- Streamable HTTP MCP endpoint (`POST /mcp`, `GET /mcp` for SSE) per the MCP spec.
- `GET /health` — see §5.

## 2. Protocol

Must implement, at minimum:

- `initialize` — returns `protocolVersion`, `serverInfo`, `capabilities`.
- `tools/list` — returns the server's tool manifest.
- `tools/call` — invokes a named tool with arguments.

## 3. Identity headers (inbound, platform → server)

The platform injects these on every forwarded request. A server MUST read identity from these
headers — **never from a tool argument** (a caller-supplied argument is not authorization evidence).

| Header | Meaning | Status |
|---|---|---|
| `X-User-Sub` | The authenticated caller's identity (`sub` from the OIDC token, or the shared client_id for service-account modes) | **Implemented** (`dispatcher.py`) |
| `X-Authorization` | The injected credential, mode-specific (see §4) | **Implemented** |
| `X-Gateway-Secret` | Shared secret proving the request came from the gateway, not a spoofed direct call | **Implemented** (`GATEWAY_SHARED_SECRET`) |
| `X-Principal-Id` / `X-Principal-Type` / `X-Principal-Issuer` | Typed principal (`human:{issuer}:{sub}`, `agent:{ca}:{cn}`, etc.) instead of a bare subject | **Not implemented** (Codex review CR-10 — currently only bare `X-User-Sub` is forwarded) |
| Correlation/request ID | Trace a call across gateway → proxy → upstream → audit | **Not implemented as a dedicated header** — the proxy's internal `request_id` is not currently forwarded upstream |

A server MUST tolerate the absence of the not-yet-implemented headers (they may be added later without
breaking existing servers) but MUST NOT treat their absence as a security signal either way.

## 4. Credential headers (inbound, mode-specific)

`X-Authorization`'s value depends on the server's configured `injection_mode` (see
`credential_broker/dispatcher.py::InjectionMode` — the canonical enum). A server only ever receives
the mode it was configured for; it does not need to handle modes it wasn't onboarded with.

| Mode | What the server receives |
|---|---|
| `none` | No `X-Authorization` header at all |
| `service` | A shared platform-managed API key / static bearer |
| `user` | Nothing extra beyond `X-User-Sub` — the server is expected to look up its own per-user state keyed by that subject |
| `service_account` | A Keycloak client_credentials access token for the tool's registered KC client |
| `kc_token_exchange` (alias `oauth_user_token`) | An RFC 8693 token-exchanged Keycloak access token scoped to this server's audience — only works when the server trusts the *same* Keycloak realm as the gateway |
| `entra_client_credentials` | A Microsoft Graph app-only access token |
| `entra_user_token` | A Microsoft Graph *delegated* access token acting as the signed-in user (broker refreshes the user's stored Entra refresh token per call) |
| `passthrough` (admin-only, roadmap for general use) | The caller's own inbound `Authorization` header, forwarded verbatim |

## 5. Healthcheck

`GET /health` is probed before tool discovery (`services/scaffold_generator.py`). It should check
whatever the server depends on to actually serve tool calls (upstream DB, downstream API reachability,
etc.) and return non-2xx on failure — a 200 with a broken dependency defeats the point of the probe.

## 6. Security requirements

- **Never trust a tool parameter as user identity.** Identity is `X-User-Sub` / the typed principal
  headers only. A tool argument named `user_id` or similar is caller-supplied data, not an
  authorization claim.
- **Never log the injected credential** (`X-Authorization`) or the raw `X-User-Sub` value in a way
  that could leak into shared logs — treat both as sensitive.
- **Do not call the platform's own control-plane API** (`/api/v1/admin/*`, `/api/v1/tools/*`, etc.)
  from within a tool implementation unless the server was explicitly designed and reviewed as a
  platform-internal meta-tool. A backend calling back into the platform's admin surface is a trust
  boundary violation, not a feature.

## 7. Error semantics

A server SHOULD distinguish, in its `tools/call` error responses, between:

- Upstream auth failure (the injected credential was rejected by the *server's own* downstream
  dependency — e.g. Graph API 401)
- Enrollment required (the calling user hasn't completed a per-user OAuth enrollment the server needs)
- Validation error (bad tool arguments)
- Backend transient failure (retry-safe)
- Platform missing credential (the platform never sent `X-Authorization` at all when the server
  expected one — distinct from "the platform sent one and the server's downstream rejected it")

The platform does not currently parse or route on these distinctions server-side — this is guidance
for a server author writing debuggable error messages, not an enforced contract yet.

## 8. Verification

Before a submitted/discovered server is treated as usable, the platform can run:

- `GET /health` (see §5)
- `tools/list` (confirms the manifest is retrievable and well-formed)
- A safe, representative `tools/call` (**roadmap** — no automated "smoke call a low-risk tool"
  verification step exists yet; discovery today only calls `tools/list`, then quarantines every
  discovered tool per INV-005, requiring a human release decision — see CR-07/`docs/ARCHITECTURE.md`
  §5.5 and the INV-006 release-evidence gate).

## What this contract is NOT (yet)

This document describes the current, honest state of the security envelope — it is not a formal
JSON/YAML-testable contract definition, and there is no automated conformance test suite that any
implementation (Python/TypeScript/Go/etc.) can run against it. Those are tracked as open work
(Codex review CR-06) — see `00_AI/mcp-security-platform/Codex_review/Claude_status.md`. Treat this
file as the source of truth for "what must a server do", and update it in the same commit as any
change to `dispatcher.py`'s injection modes, the identity headers actually forwarded, or the
discovery/verification pipeline.
