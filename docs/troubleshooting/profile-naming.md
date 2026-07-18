# Troubleshooting: "profile" means two different things

**Audience:** anyone integrating against `get_profile`/`enable_mcp`/`disable_mcp`, or against the
admin `POST /api/v1/profiles/named` REST API. Read this **before** picking one, since both are
seeded/described using the word "profile" and only one of them is what most people mean by it.

There are two entirely separate systems in this platform that both use the word "profile". They
do not share storage, do not share an API surface, and enabling/disabling one has **no effect** on
the other.

## 1. Per-identity self-service profile (MCP meta-tools)

- **What it is:** a per-caller, self-service on/off switch for which MCPs/functions *your own
  identity* can see and invoke. Every authenticated principal has exactly one of these, addressed
  implicitly as "you" unless you pass `target_profile` to act on someone else's (subject to the
  same RBAC checks the REST equivalents enforce — see `proxy/app/routers/profiles.py`).
- **How you reach it:**
  - As MCP tools (seeded by `infra/db/migrations/V078__self_service_profile_tools.sql`, described
    further by `V081__clarify_self_service_profile_tool_descriptions.sql`): `get_profile`,
    `enable_mcp`, `disable_mcp`, `enable_function`, `disable_function`. These are routed through
    the platform like any other tool call — the same identity/RBAC/quarantine/OPA gate chain
    applies (see `docs/troubleshooting/credential-injection.md`).
  - As REST, the identical functionality is exposed at `GET/POST /api/v1/profiles/me/...` and
    `GET/PUT/POST /api/v1/profiles/{principal}/...` (admin-only for a principal other than "me").
- **Storage:** `mcp_profiles` / `profile_mcp_bindings`, keyed by principal.
- **Task reference:** PRD-0011 / RFC Task 4.2.

## 2. Session-bound named profile (admin-managed, REST-only)

- **What it is:** an admin-defined, **named** allow/deny set (e.g. `contractor-readonly`,
  `finance-team`) that gets bound to a session **at OIDC login time** via the `?profile=<name>`
  query parameter on the login redirect. It is not tied to a specific identity — any session that
  authenticates through that login URL picks up that profile's bindings for the lifetime of the
  session.
- **How you reach it:** REST only, admin-role-gated (`proxy/app/routers/profiles.py`, `_assert_admin`):
  `GET/POST /api/v1/profiles/named`, `GET /api/v1/profiles/named/{name}`,
  `PUT /api/v1/profiles/named/{name}/mcps/{tool_name}`. **There is no MCP tool for this** — it
  cannot be read or changed from inside a tool call, by design (it would let a session mutate the
  very access boundary it's bound under).
- **Storage:** the named-profiles tables reached via `profile_uuid`, distinct from
  `mcp_profiles` above.
- **Default-allow footgun (fixed 2026-07-18):** a named profile with zero binding rows still
  allows every tool (avoids bricking an unconfigured profile at rollout). Once you add **any**
  binding row, the profile flips to default-deny for everything else — see finding 1 in
  `docs/spec/11-server-lifecycle-and-hardening-batch.md`. Don't assume "no explicit deny row" means
  allowed once you've started configuring a named profile.
- **Task reference:** Task 4.3.

## Which one do I want?

| If you're... | Use |
|---|---|
| Building an MCP tool/agent that lets a user self-manage what they personally can call | System 1 (`get_profile`/`enable_mcp`/`disable_mcp`, or the `/api/v1/profiles/me/*` REST equivalent) |
| An admin scoping what an entire class of login sessions (e.g. all contractor logins) can reach, enforced from the moment they authenticate | System 2 (`POST /api/v1/profiles/named` + `?profile=` at login) |
| Trying to programmatically read/write a named profile from inside a tool call | **Not possible** — no MCP tool exists for System 2. Use the REST API directly, outside the tool-call path. |

## Known follow-up

The external `self-service-mcp` server (the process behind the `get_profile`/`enable_mcp`/
`disable_mcp` tool calls, at `http://self-service:8000/mcp` — not part of this repo) has its own
docstrings that predate this disambiguation. Updating those is tracked as a separate follow-up
against that external repo; this document and the in-repo `tool_registry.description` suffix
(V081) are the fix for everything this repo controls.
