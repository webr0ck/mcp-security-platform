# PRD-0009 — Self-Service Wizard: Platform-Managed Backend for Microsoft 365 / Entra

- **Status:** DRAFT — plan only, **implementation deliberately deferred**. Do not start until the
  blocker below is cleared.
- **Date:** 2026-07-11
- **Author:** Claude, from a live user report + codebase research (session continuing the
  PRD-0008 gateway functional-sweep work).
- **Scope:** Let a non-expert submitter register a Microsoft 365 / Entra-backed MCP tool through
  the self-service submission wizard **without** knowing or supplying a "Backend URL" — narrowed
  from a general "any well-known SaaS provider" feature to Entra/M365 only, per explicit scoping
  decision (see Decision Log). Generalizing to other providers is an explicit non-goal of this PRD;
  see the Appendix for what a future generalization would touch.
- **Non-goals:** wiring the full `oauth_provider_profile` catalog into the wizard for every
  provider (that's the pre-existing, separately-tracked Finding 1 in
  `docs/spec/09-generic-oauth-test-findings-2026-07-07.md`); building a generic multi-tenant
  `service_adapter` framework; Jira/Slack/Zoom/etc. support (Appendix only, not this PRD).

## ⚠️ Blocker — read before starting any implementation

At the time this PRD was written, `git status` on `~/Code/mcp-security-platform` showed **active,
same-day, uncommitted changes** to the exact files this feature needs to touch:
`proxy/app/routers/portal.py` (the wizard), `proxy/app/routers/server_registry.py`
(`ServerRegister`), `proxy/app/services/oauth_provider_profile.py`, and three new migrations
(`V074__oauth_provider_profile_injection_mode.sql`, `V075__server_registry_description_requested_url.sql`,
`V076__oauth_provider_profile_injection_mode_check.sql` — the last one references a "2026-07-11
audit" by name, i.e. today). This is the in-progress completion of Finding 1 from the generic-OAuth
spec doc — the same feature area, not a coincidence.

**Before implementing this PRD:** re-run `git status`/`git log` on that host, confirm whether that
work has landed (committed) or is still an untracked WIP, and read its current state fresh — do not
assume the file contents described below are still current. If it's still active/uncommitted,
coordinate with whoever owns it (the user, in this case) before editing the same files, per the same
collision-avoidance approach used for the PRD-0008 parallel-agent fixes (one owner per file/area at
a time).

## Problem (user report, verbatim intent)

In the self-service submission wizard (portal, Step 1 · Basics), "Backend URL (where does/will this
run?)" is a hard-required field before a submission can proceed — the wizard's own validation
message says "a reviewer cannot approve a server they can't locate." For a non-expert user wanting
to register a Microsoft 365 / Microsoft Graph-backed tool, this is a fields-mismatch: Microsoft
Graph is a fixed SaaS API (`graph.microsoft.com`), not something the submitter hosts — they have no
"backend URL" to give, because conceptually there isn't a URL *they* control at all. The ask: make
this skippable specifically for Microsoft 365/Entra via a provider dropdown, and research whether
other providers share the same shape.

## Research findings (state as of 2026-07-11, before the blocker's WIP is accounted for)

1. **`oauth_provider_profile` (V070) already has `'entra'` as a first-class `provider_type`**, plus
   a `service_adapter` slug column and `server_registry.service_context` JSONB explicitly designed
   to hold post-OAuth-discovered, non-secret runtime context (e.g.
   `{"resource_id": "<tenant-id>"}`) — the right schema shape for this feature already exists.
   However, per the spec doc's own "Finding 1," none of this is wired into the actual submission
   wizard yet (`ServerRegister` still only takes raw `upstream_idp_type`/`upstream_idp_config`).
2. **The `service_adapter` registry (`adapters/service_adapter_registry.py`) only has `"generic"`
   registered** — no service-specific (M365, Jira, ...) post-OAuth resource-discovery adapter
   exists yet, despite the schema supporting one per profile.
3. **An `M365Adapter` (`adapters/m365.py`) and `JiraAdapter` (`adapters/jira.py`) already exist**,
   but they only handle the OAuth **token exchange** (authorize/exchange/refresh) against a single,
   platform-admin-configured app registration/tenant (env vars) — this is the same mechanism behind
   the lab's `lab-mcp-m365` fixture (`softeria/ms-365-mcp-server`, parameterized entirely by
   credentials, not a submitter-provided URL). Neither adapter resolves a tenant/cloud id
   automatically today; the Jira adapter's own docstring says that resolution is explicitly **not**
   implemented ("left to the downstream Jira MCP tool implementation").
4. **"Backend URL" and "which OAuth provider" are two separate problems.** Even with an
   Entra/M365 `oauth_provider_profile` fully wired into the wizard (Finding 1, done), the submitter
   would *still* need to say where their MCP server process runs — unless the platform itself hosts
   a shared, multi-tenant implementation of that adapter (proven technically viable by the lab's
   `lab-mcp-m365`, but not currently modeled as a reusable "platform-managed backend" concept
   anywhere in the production code).
5. **Microsoft Graph specifically doesn't need a submitter-typed tenant ID either** — a
   multi-tenant Entra app registration receives the tenant id in the token's `tid` claim at
   OAuth-consent time; asking the submitter to type it in would be redundant with what Microsoft
   already tells the platform.

## Proposed design (Entra/M365 only)

1. **Wizard (Step 1, `portal.py`):** add a provider selector before/alongside the Backend URL
   field. Default option keeps today's raw-URL flow unchanged. A new option, "Microsoft 365 / Entra
   (platform-managed — no backend URL needed)," hides the Backend URL input and its required
   validation, and replaces it with a short explanatory note (the platform runs a shared M365 Graph
   MCP adapter; the submitter's own tenant gets connected after approval via the existing
   `/auth/enroll` consent flow — no tenant ID typed in, it comes from the OAuth token).
2. **Backend (`server_registry.py::ServerRegister`/`register_server_self_service`):** when this
   option is selected, set `upstream_idp_type='entra'` and derive `upstream_url` from a new fixed
   settings constant (e.g. `PLATFORM_MANAGED_M365_ADAPTER_URL`, analogous to the lab's
   `lab-mcp-m365:8000/mcp`) instead of taking a submitter-provided value — `requested_upstream_url`
   (V075) can store a sentinel like `"platform-managed:m365"` so the reviewer UI (which already
   renders "Backend (requested)" vs. "Backend URL: n/a" per `portal.py` ~line 5575) shows something
   meaningful instead of a blank/URL.
3. **Reviewer UI:** the existing requested/live backend display block needs a third case —
   "Backend: platform-managed (Microsoft 365 Graph adapter)" — instead of falling through to the
   "not stated" warning path.
4. **No new migration should be needed** if V070/V075's existing columns
   (`oauth_provider_profile_id`, `service_context`, `requested_upstream_url`) are reused as
   described — confirm this once the blocker's WIP state is known, since it may have already added
   overlapping columns.
5. **Out of scope for this PRD:** actually implementing per-tenant `service_context.resource_id`
   discovery (reading the `tid` claim and persisting it) — worth a fast-follow once this lands, but
   the wizard-unblocking fix (skip Backend URL) doesn't strictly require it.

## Decision log

- User confirmed scope: **Entra/M365 only**, not the general "any well-known SaaS provider"
  dropdown — generalize later if this proves out.
- User confirmed: **do not implement yet** — save this plan, revisit once the concurrent
  oauth_provider_profile/wizard WIP's status is clear.

---

## Appendix — other providers with the same shape, if/when this generalizes

**Fits directly (fixed global API endpoint, tenant/org resolved automatically from the OAuth token
itself, zero manual entry ever needed):** Microsoft Graph/Entra (`tid` claim), Slack (`team_id` in
the OAuth response), Google Workspace APIs, Notion, GitHub.com (not Enterprise Server).

**Fits with one extra step (fixed endpoint, but needs a follow-up lookup call after OAuth — exactly
what `service_adapter`/`service_context` was designed for, and why `'jira_cloud'` is already
reserved as a `provider_type`):** Atlassian Jira/Confluence Cloud (`cloudId` via
`/oauth/token/accessible-resources`), Zoom, Dropbox Business, HubSpot.

**Does NOT fit — these have a per-customer subdomain/instance URL, so a real backend/instance URL
is unavoidable and the current wizard flow is already correct for them:** Salesforce, Okta,
ServiceNow, Zendesk, Workday.
