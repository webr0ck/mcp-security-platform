# Prompt Examples

Example prompts to paste into Claude Code (or any MCP client connected to this
platform's `mcp-gateway`) for the most common self-service workflows. Every
example below reflects a real, tested tool-call sequence — not aspirational
documentation — verified during the 2026-07-14 onboarding session (see
`KB/mcp-security-platform` in the operator's notes for the full log). Where a
step has a known gotcha, it's called out inline so you don't have to
rediscover it.

## "I want to see what I have access to"

> Show me every MCP server available to me, and which ones are actually enabled for my profile.

Behind the scenes this calls `list_available_mcps`. If you want the same
question for one specific server (and whether specific functions on it are
restricted), ask instead:

> Check my profile for the `grafana-query` server — is it enabled, and are there any per-function restrictions?

This calls `self-service-mcp`'s `get_profile` and `list_functions` under the
hood. An empty/`null` `allowed_functions` means **all** functions are
currently permitted — it does not mean none are.

## "Turn a server on/off for myself"

> Disable the `dex-calendar` server for my profile.
> Re-enable `dex-calendar` for my profile.

Calls `disable_mcp_server` / `enable_mcp_server` directly — these are
self-service, no admin role needed, and only affect *your own* profile.
Toggling always leaves a permanent explicit row behind (even re-enabling to
the same state as before creates a row) — this is a cosmetic detail, not a
functional issue.

To restrict just one function within an otherwise-enabled server rather than
the whole server:

> Disable the `update_dashboard` function specifically on `grafana-query` for my profile — leave everything else on that server enabled.

## "I want to build and onboard a new MCP server"

This is the big one — a full multi-step workflow. Ask it exactly like you'd
ask a colleague:

> I want to build an MCP server for our internal ticket system — it should let an agent create and list tickets on behalf of the calling user. What should I do?

What actually happens, step by step (you don't need to name these tools —
just answer the questions the agent asks you):

1. **`plan_mcp_server`** — returns a structured set of auth/data/backend
   questions. Answer them in plain language ("yes it needs upstream auth",
   "same Keycloak instance as the platform", "each user has their own
   session", "it exposes read-only ticket data, no PII").
2. **`get_auth_mode_recommendation`** — turns those answers into a concrete
   `injection_mode` recommendation (e.g. `kc_token_exchange` for
   same-Keycloak, `basic_auth`/`service` for a shared static credential,
   `entra_client_credentials` for an app-only Microsoft Graph integration).
3. **`get_server_scaffold`** — generates real starter code
   (`server.py` + `requirements.txt` + `Dockerfile` + `README.md`, and for
   `kc_token_exchange` also a fail-closed `jwt_validator.py`) for the
   recommended mode. Save these, fill in your actual tool logic, push to a
   **GitHub repo root URL** (`https://github.com/<owner>/<repo>` — a
   `/tree/<branch>` suffix will be rejected; merge onto the default branch
   instead) — self-hosted git (an internal Gitea, a raw IP) will also be
   rejected by the platform's SSRF allowlist, which currently only trusts
   `github.com`.
4. **`submit_mcp_server`** — registers the real submission. Give it a real
   backend URL if you have one; if you don't yet, say so and use
   `get_server_scaffold` alone first — a submission needs a `description`,
   `injection_mode`, `data_categories`, `has_write_ops`, and `upstream_url` at minimum.
5. **`check_submission_status`** — poll this until `scan_status: passed`.
   Real repos can trip real findings (SSRF-shaped fetch patterns, missing
   transport host-checks) — a `scan_blocked` result means the scanner found
   something real; fix the code and resubmit rather than trying to force it
   through.
6. Once `awaiting_review`, a **platform admin** approves it (two-step
   dual-control: the owner mints a consent token, the admin countersigns —
   ask the admin to run this, it's not self-service).
7. After approval, provide the **real, live** backend URL — this triggers
   automatic tool discovery. Every newly discovered tool starts
   **quarantined** by design, regardless of how clean the scan was; an admin
   must explicitly activate each one before it's callable.
8. Once active, if your server needs a stored credential (anything other than
   `injection_mode=none`), an admin uploads it via the credentials UI —
   **ask them to set an explicit `service_name` on the tool first** if this
   is a newly self-service-discovered tool; credential lookup never falls
   back to the tool's own name (a deliberate security control), so an
   unset `service_name` means the credential can never be found even after
   upload.
9. Grant yourself (or whoever needs to call it) an entitlement:

> Grant me an entitlement on the ticket-system server so I can actually call its tools.

   This calls `POST /api/v1/servers/{id}/entitlements` — note the
   `principal_id` must be the fully-typed form (`human:keycloak:<you>`), not
   your bare username.

10. Try calling one of the new tools. **Expect the first call to fail** with
    `Access denied: session restricted by trust policy` — every newly
    discovered tool starts at `trust_tier=0`, and calling one taints your
    session for up to an hour, denying your *next* call regardless of which
    tool it targets. This is documented, expected behavior, not a bug: the
    platform is correctly treating "a server nobody has verified yet" as
    untrusted.

    Once the server has actually been verified (you or an admin called its
    tools and confirmed they behave correctly), ask an admin to promote it
    instead of repeatedly working around the taint:

    > Set trust_tier to 2 (internal) on the ticket-system server — I've verified it works.

    This calls `PATCH /api/v1/admin/servers/{server_id}` with
    `{"trust_tier": 2}` (platform_admin only; SEP-1913 range 0-4 — 0/1 are
    still "public" tiers that taint the floor, 2 = "internal" is the floor
    for "trusted", 3 = "user", 4 = "system"). It's audited
    (`SERVER_TRUST_TIER_CHANGED`) since it changes the taint floor for every
    future caller of that server. Note this only stops *new* taints going
    forward — if your session was already tainted by an earlier call before
    the promotion, that existing taint still has to expire (or be cleared
    once) on its own.

## "I already have a running server, just register it"

If you skip straight to registration without going through `plan_mcp_server`
first:

> Register my ticket-system server — it's running at https://tickets.internal.example.com/mcp, uses kc_token_exchange auth, exposes internal ticket data, no PII, and it's read+write. The code is at https://github.com/myorg/ticket-mcp.

This is a single `submit_mcp_server` call with everything pre-specified —
faster if you already know your auth mode, but skips the guided
recommendation check. Still goes through the same scan → approve → discover
→ activate → entitle pipeline above.

## "Something that used to work just broke"

> Check whether the m365-graph tool is actually working right now — try get_me and tell me exactly what error you get.

Useful pattern generally: ask the agent to *actually invoke* the tool and
report the real error, rather than just checking its registration status —
several real bugs (see the 2026-07-14 platform fixes log) only showed up on
live invocation, never in the registry/health metadata.
