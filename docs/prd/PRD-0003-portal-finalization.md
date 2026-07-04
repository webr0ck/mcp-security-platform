# PRD-0003 — Portal & Platform Finalization

- **Status:** DRAFT v3 (v2 findings F-1..F-11 / requirements R-0..R-8 preserved as-is;
  this revision adds F-12..F-15 and R-9..R-13 for the remaining hardening pass —
  role-write UI scope, submission-review depth, SBOM inventory, and the
  approval→provisioning pipeline)
- **Date:** 2026-07-03
- **Author:** platform team (senior dev / UI-UX / lead architect review)
- **Scope:** UI implementation gaps, backend data gaps blocking UI, admin configurability
- **Non-goals:** new auth patterns (PRD-0002 complete), Helm/K8s, WORM audit, outbound Jira (remain roadmap)

## v3 status of v2 items (as of this revision, verified against the working tree)

R-0, R-1, R-2, R-3, R-6, R-7 are **DONE** (uncommitted, in the working tree, smoke-tested
against the live podman lab this session): scanner fail-closed fix + tool install, wizard
clipping fix, admin Access tab, profile page, my-submissions status chips, detections
drill-down + tool/server attribution. R-4 (real SBOM inventory), R-5 (LLM audit visibility),
and R-8 (docs hygiene) remain open; **R-4 is superseded for this pass by R-9 below** (see
R-9's note) rather than implemented as originally scoped (full syft sidecar) — the syft
sidecar is retained as the P2 follow-through. F-1/F-2/F-3/F-6/F-7/F-8/F-11 are resolved by
the above; F-4, F-5, F-9, F-10 remain open findings as originally written.

## 0. Architectural finding: two frontends

The platform ships **two parallel UIs**:

1. **HTMX portal** (`proxy/app/routers/portal.py`, 4,491 lines of server-rendered
   HTML-in-Python) — the *live* UI. Admin shell (Dashboard/Detections/SBOM/Identity/
   Servers/Submissions/Credentials/Limits), agent portal, submit wizard. This is what
   the acceptance tests target and what users actually use.
2. **React app** (`ui/src`, Vite, port 3100) — largely **non-functional**: the Security
   Dashboard and Admin→Servers render hardcoded mock data (`SecurityDashboard.tsx:8-21`,
   `AdminPanel.tsx:10-15`), and at least 6 buttons have no `onClick` (Test Connection,
   Register, Approve/Edit/Suspend, Upload Credential, Download .env). Only UserPortal
   (profile toggles), LimitsPanel, submission wizard, and SubmissionReview are wired live.

**Decision D-1 (owner: platform lead; deadline: before any P0 work starts, ≤ 1 week
from PRD approval):** pick one canonical frontend. Recommendation: **keep the HTMX
portal for finalization** (live, tested, role-aware); freeze the React app (option a) —
remove it from compose/docs or label it experimental. Falsifier for (a): if any single
portal requirement below (R-2/R-7) exceeds 2× its size estimate because of HTMX/
portal.py structural limits, revisit React (option b) before starting the next one.
All requirements assume (a).

## 1. Problem statement

The runtime security core (identity → RBAC → quarantine → OPA → credential broker →
audit) is enforced and tested, but the portal UI lags the backend: several implemented
backend capabilities (per-user MCP/tool enablement, submission scanning, LLM audit)
have no admin UI surface, and several portal views (submit wizard, Detections, SBOM)
are broken or empty. Review for this PRD also uncovered a **real security bug**: the
submission scanner fails open in the deployed container (F-11). Two backend data gaps
(SBOM package inventory, detection→server linkage) block the UI from ever being right
without schema/service work.

## 2. Findings

Each verified against code; F-1/F-4/F-7 also reproduced in a live browser session
(1366×768, alice/admin). Legend: **[UI]** portal-only, **[BE]** backend, **[BOTH]** full-stack.

### F-1 [UI] Submit wizard content clipped — "What your server needs to implement" unreadable
**Reproduced:** expanding the snippet puts its bottom at 867 px while the document
stays 768 px with `scrollMax=0`.
**Root cause:** `/portal/submit` wraps the wizard in `<div class="adm-layout">`
(`portal.py:3809`); `.adm-layout` is the admin-shell class with
`height:100vh; overflow:hidden` (`portal.py:503-506`); the inline `min-height:100vh`
does not override `height`. Any step content taller than the viewport is clipped with
no scrollbar — affects all seven per-mode snippets (`portal.py:3988-4111`) and long
guided-question panels.

### F-2 [UI] No admin UI for per-user enable/disable of MCP servers and tools
Backend APIs exist:
- Self-service: `POST /api/v1/profiles/me/mcps/{mcp}/enable|disable` + per-function
  toggles (`profiles.py:406-465`) — already surfaced in the agent portal. **Self-service works.**
- Admin per-principal: `/api/v1/profiles/{principal}/mcps/...` (`profiles.py:491-733`) — **no UI**.
- Per-server entitlements: `POST/DELETE /api/v1/servers/{id}/entitlements`
  (`entitlements.py:311/:517`) — **no UI**.
- Per-client tool/tag grants: `/api/v1/admin/grants` (`admin_grants.py`) — **no UI**.
**Hidden complexity (from critic review):** there is no principals table or list
endpoint (profiles appear only after first toggle), and the three layers are keyed by
*different identity types* — profiles by KC sub, client grants by OAuth client_id
(shared portal client for all PKCE humans), entitlements by (principal_id,
principal_type). See R-2 scoping.

### F-3 [UI] No profile page
Backend has `GET /api/v1/profiles/me` (`profiles.py:364`), `GET /session` and logout
(`oidc_browser.py`). The portal shows only an initials avatar + role chip; no page
with identity, roles (all of them), sessions, or sign-out.

### F-4 [BOTH] SBOM page shows no packages/components
**Reproduced:** admin → SBOM shows *21 registered tools, 0 with SBOM, 0 total components*.
Stacked causes:
1. Discovery-onboarded tools never got `sbom_records`/audit rows (fixed by the
   uncommitted AN-06 change in `tools.py:1478+` — must land).
2. Even with records, `services/sbom.py:76-113` emits CycloneDX with **one component
   per tool** (schema-digest attestation): no dependencies array, no package inventory.
   SPDX endpoint returns 501 (`tools.py:1057`).

### F-5 [BOTH] No admin-panel configuration/visibility for the local LLM
Ollama integration exists and is load-bearing (`core/config.py:114-130`,
`services/auditor.py`; `REQUIRE_LLM_AUDIT` enforced at startup in prod,
`config.py:539-551`) but is env-only: no admin UI to see model/thresholds, no health
indicator, no evidence in the UI that LLM audit ran. LLM is not used for detections today.

### F-6 [BOTH] Submission automated checks exist but are invisible to submitters
`scan_submission` (`services/submission_scanner.py`) is wired into submit, and the
uncommitted A-06 fix (`submission.py:401`) gates approval on scan pass. The reviewer
detail shows a scan-report table, but the **submitter** never sees scan status or
findings, so onboarding *looks* unchecked. See F-11 for why the scans currently don't
actually run.

### F-7 [UI] Detections page is a dead end
**Reproduced:** the Detections fragment (`portal.py:2429-2689`) renders summary cards
and three tables with **zero links and zero row actions** (only the 24h/7d/30d window
buttons). "Can't open anything" is accurate: there is nothing to open — no detail
view, no drill-down. (Navigation away still works; it is not a JS breakage.)

### F-8 [BOTH] Detections not attributable to an MCP server
The feed is built from `audit_events` (client_id, tool_name, opa_reasons —
`portal.py:2599-2605`). **Neither audit rows in this view nor `anomaly_alerts` carry
`server_id`**, and (critic-verified) `anomaly.py` persists alerts with an **always-empty
`invocation_ids` array** and drops `tool_name` — so the alert table currently has
*nothing* to join on. `audit_events.tool_id` (V028) and `tool_registry.server_id`
(V023/V031) exist and are the correct attribution keys; a `tool_name` join would be
ambiguous (UNIQUE(name, version); historically per-alias rows).

### F-9 [BE] Planning docs deleted; stale pointers
`docs/prd/`, `docs/ROADMAP.md`, RFCs, ADRs, `docs/RBAC.md`, `docs/API.md` deleted in
commit `2f6430c` (survive only in git history). `CLAUDE.md` points at
`specs/001-four-auth-poc/plan.md`, which does not exist.

### F-10 [UI] Portal/React code-quality debt (secondary)
React: mock data in prod paths, 6 dead buttons, only first role honored
(`AuthContext.tsx:21`), no sign-out, status-CSS class drift
(`SubmitServerWizard.css:168`). Portal: 4,491-line single file; inline styles per
fragment; detections tables not keyboard-accessible.

### F-11 [BE] **Security bug: submission scanner fails open and its tools are absent from the image**
Found during critic review. `proxy/Dockerfile` installs only curl + ca-certificates —
no git, no trufflehog, no pip-audit. `submission_scanner.py` treats a missing binary as
a skip-with-warning and the scan **passes** (`shutil.which` miss → `scan_status='passed'`,
lines 94/123-124/212-213). In the deployed container every repo submission is
rubber-stamped, and the A-06 approval gate is vacuous. Scans also run as subprocesses
*inside the security proxy*, so adding heavier tooling (syft) would mean parsing
attacker-controlled repos inside the enforcement point.

### F-12 [BE] No write path for role assignment anywhere in the platform
`role_assignments` has exactly one writer in the entire codebase: the login callback
mirrors Keycloak's token roles into the table with `INSERT ... ON CONFLICT DO NOTHING`
(`routers/oidc_browser.py:598-614`) — a read-through cache, not a management surface.
The only other references are read-only: `middleware/auth.py:712-751` (role lookup for
the auth gate) and `admin_grants.py:80-131` (`GET /api/v1/admin/principals`, which
LEFT JOINs `role_assignments` for display). `admin_grants.py`'s two `POST`/`DELETE`
routes (`:179`, `:258`) write `admin_grants` (per-client tool/tag grants) — a
*different* table with *different* semantics, not roles. There is no
`POST`/`PUT`/`PATCH` route in any router that changes a principal's role. Roles can
only be changed in Keycloak today, confirming the "no write path in this platform"
summary is accurate as of this revision.

### F-13 [UI] Admin submission review is shallow relative to what's already collected
`fragment_admin_submissions` (`portal.py:4031-4179`) `SELECT`s only `server_id, name,
owner_sub, submission_status, scan_status, injection_mode, data_categories,
has_write_ops, github_repo_url, scan_report, review_notes, updated_at`
(`portal.py:4038-4042`) — **`upstream_idp_config` is not even in the query**, so the
reviewer cannot see the audience/client-id/scopes a submitter configured in the wizard
before approving. Scan findings render only `if st == "scan_blocked"`
(`portal.py:4092`) — a `passed` scan shows no report at all, so a reviewer cannot see
*what* trufflehog/pip-audit actually found on a clean repo, only that it didn't block.
The only code-visibility affordance is a raw `https://` link opened in a new tab
(`portal.py:4120-4128`); there is no in-portal diff/file viewer and no SBOM link (SBOM
is empty anyway per F-4, but even a stub link is absent).

### F-14 [BE] Dead "Target audience" field; approval never provisions a tool_registry row
Two unrelated columns exist for the same concept and only one is ever read at
invocation time:
- The wizard's `kc_token_exchange` step writes `cfg.audience` from
  `#cfg-audience` (`portal.py:4424-4426` render, `:4573` collection) into
  `server_registry.upstream_idp_config` via `PATCH /api/v1/submissions/{id}`
  (`submission.py:145,225-227`, `upstream_idp_config = CAST(:idp_config AS jsonb)`).
- The runtime dispatcher's `kc_token_exchange` injector reads
  `tool_record.get("kc_token_audience")` (`credential_broker/dispatcher.py:435`) — a
  **column on `tool_registry`**, set only via the separate admin Credentials panel
  (`admin_credentials.py:288-338`, `PATCH .../credentials`) or the manual "Register
  Tool" form (`portal.py:3009-3061` → `POST /api/v1/tools/register`). Nothing copies
  `server_registry.upstream_idp_config.audience` into
  `tool_registry.kc_token_audience` — the wizard's value is never read by anything.
- Root cause: `approve_submission` (`submission.py:395-420`) only flips
  `server_registry.submission_status`; `provide_running_url`
  (`submission.py:478-527`) only sets `upstream_url`/`status='approved'`. Neither
  creates or touches a `tool_registry` row. The only path from `server_registry` to a
  live, invocable `tool_registry` row is `POST /servers/{id}/discover-tools`
  (`tools.py:1500-1524`, admin-only, INV-005 quarantine-on-insert) — grepping the
  entire `proxy/app` tree, nothing calls it automatically; `submission.py` uses
  `BackgroundTasks` only for `scan_submission` (`:297`), never for discovery. The
  `"next": "Tool discovery will run shortly."` message returned by `provide_running_url`
  (`submission.py:527`) is aspirational — no scheduler, webhook, or code path fulfills
  it. An admin must manually run discover-tools *and* separately either audit-approve
  the resulting quarantined tool or use the disconnected "Register Tool" form, which
  re-collects name/version/upstream_url/injection_mode from scratch with no link back
  to the submission it came from.

### F-15 [BOTH] `approved_pending_url` is a structural dead end for no-code submissions
A no-code submission has `github_repo_url IS NULL` (`submission.py:120`, "None =
no-code path") and its scan is `not_applicable` (no repo to scan), so it clears the
A-06 gate and `approve_submission` moves it to `approved_pending_url`
(`submission.py:409`) exactly like a repo submission. But `provide_running_url`
requires a caller-supplied `upstream_url` (`submission.py:482-484`, 422 if blank) —
for a no-code submission there is no server anywhere to supply a URL for; nothing was
built. Confirmed no portal UI ever calls `POST /api/v1/submissions/{id}/provide-url`:
grepping `portal.py` for `provide-url`/`upstream_url` finds only read-only status-chip
labels for `approved_pending_url` (`portal.py:1797` my-submissions strip, `:4063` admin
queue) and the unrelated manual tool-registration form (`:3028`). A no-code submission
that reaches `approved_pending_url` today has no portal affordance to progress and no
URL to ever legitimately provide — it is indistinguishable in the UI from a repo
submission that's simply waiting on its owner, even though the two need entirely
different resolutions.

## 3. Requirements

Sizes: S ≤ ½ day, M ≤ 2 days, L ≤ 1 week. Every requirement states its failure mode (FM).

### R-0 Scanner integrity: fail closed, tools present (F-11) — P0, M — *prerequisite for R-6/R-4*
- Missing scanner binary ⇒ `scan_status='error'` (blocks approval), never `'passed'`.
- Ship git + trufflehog + pip-audit in a **separate scanner image/sidecar** (compose
  service) rather than the proxy image; proxy dispatches scans to it. Interim step
  (acceptable for lab): install tools in the proxy image, keep subprocess isolation
  (timeouts, rlimits, clone dir quota) — but the enforcement-point separation is the
  P1 follow-through.
- FM: scanner service down ⇒ submissions stay `scan_running/error` and cannot be
  approved (fail closed); admin sees scanner health on the dashboard.
- AC: with trufflehog absent, a repo submission cannot reach `passed`; with tools
  present, a planted secret yields `blocked` + finding.

### R-1 Fix wizard clipping (F-1) — P0, S
Wizard page gets its own scrollable wrapper (drop `.adm-layout` or override
`height:auto; overflow:visible`).
- FM: none meaningful; pure CSS containment change on a standalone page.
- AC: at 1366×768 and 375×667 every expanded snippet is fully reachable; Playwright
  asserts `scrollHeight > innerHeight` when open and the snippet's last line is visible
  after scroll.

### R-2 Access-management admin UI (F-2) — P0, L (UI) + M (BE resolver)
New admin "Access" tab:
- **Principal source (scoped):** union of `role_assignments.client_id`,
  `mcp_profiles` principals, and active `oidc_sessions` subjects — a new
  `GET /api/v1/admin/principals` endpoint. Keycloak admin-API sync is explicitly out
  of scope (P2).
- Per-principal server/tool toggles via the existing profiles admin API; per-server
  entitlement grant/revoke on the server card; per-client tool/tag grants stay on a
  separate "API clients" panel **keyed by client_id and labeled as such** (they cannot
  target an individual human — the portal client is shared; the UI must say so).
- **Effective access** = entitlement ∧ profile-enabled (per principal), displayed with
  which layer denies. Client grants shown as a separate, honestly-labeled dimension.
- FM: layers disagree with cached OPA data (60s grant sync) ⇒ UI shows "pending sync"
  when a change is < sync interval old; effective-access display is validated against
  a live OPA `POST /evaluate` for the AC.
- AC: admin disables tool X for user bob in UI → bob's `tools/list` omits X and invoke
  is denied (audit event visible); the UI's "denied by profile" matches the actual
  OPA/entitlement deny reason; re-enable restores.

### R-3 Profile page (F-3) — P0, M
Portal page: principal id, display name, **all** roles, session info, sign-out button
(existing logout endpoint), plus the existing "My access" toggles.
- FM: session endpoint unavailable ⇒ page renders identity from `/profiles/me` only.
- AC: alice sees admin+agent roles; sign-out invalidates the session and redirects to login.

### R-4 Real SBOM inventory (F-4) — P1, L
- Prereq: land uncommitted AN-06 (discovery audit/SBOM) and R-0 (scanner sidecar).
- BE: scanner sidecar runs syft (CycloneDX JSON) on repo-backed submissions; results
  merged into the tool's SBOM as `components` + `dependencies`; schema-digest
  attestation component kept. **Budget: syft step ≤ 120 s and ≤ 512 MB per scan
  (enforced timeout/rlimit); exceeding ⇒ `scan_status='error'`, not pass.** Syft
  binary pinned by digest. Syft parses untrusted repos ⇒ runs only in the sidecar
  (R-0), never in the proxy.
- UI: per-tool SBOM detail — component table (name, version, purl, license), search,
  clear empty-state ("attestation-only — no source repo") for non-repo tools.
- FM: syft crash/timeout ⇒ submission scan errors (fail closed); UI shows "inventory
  unavailable" state distinctly from "no repo".
- AC: repo-backed tool shows ≥ 1 real dependency with version+purl; header counters
  become non-zero; a syft-killed scan cannot be approved.

### R-5 LLM audit visibility + bounded configuration (F-5) — P1, M
Admin "AI / Audit" card, hardened per security review:
- **Read-only:** Ollama host/port (env-only — **never DB/UI-settable**; the host is an
  unvalidated egress target and must not become a PATCH-able SSRF/audit-downgrade
  primitive), model name, health status, last-N audit outcomes (score, llm_unavailable).
- **Writable (bounded):** `OLLAMA_HIGH_RISK_THRESHOLD` / `OLLAMA_CRITICAL_RISK_THRESHOLD`
  via `PATCH /api/v1/admin/settings/llm` — platform_admin + interactive (non-service)
  session, clamped to [40, 95] / [60, 100] with high < critical, audited via
  `emit_admin_config_event` (same pattern as `admin_limits.py`).
- **`REQUIRE_LLM_AUDIT` is not runtime-settable.** Displayed read-only from env; the
  settings resolver must ignore any DB row for this flag; a unit test asserts the
  resolver returns the env value regardless of DB contents (keeps the prod startup
  gate meaningful).
- FM: Ollama down ⇒ health shows red; with REQUIRE_LLM_AUDIT, registration blocks with
  a clear UI error (existing fail-closed behavior surfaced, not changed).
- AC: threshold change in UI is clamped, audited, and used by the next
  `POST /tools/{id}/audit/rerun`; a threshold override cannot push a known-high-risk
  fixture tool below the quarantine gate (regression test); stopping Ollama flips the
  indicator.

### R-6 Surface submission scanning to submitters (F-6) — P0, M (after R-0)
- Wizard result + "my submissions" show scan status chip
  (pending/running/passed/blocked/error/not_applicable) with findings on expand.
- Reviewer queue: approve disabled with reason until scan `passed`/`not_applicable`
  (mirrors server-side A-06 gate; requires landing the uncommitted submission.py diff).
- FM: scan stuck in `running` (worker died) ⇒ visible as stale with timestamp; approval
  stays blocked (server-side gate already refuses).
- AC: planted-secret repo shows `blocked` + finding to the submitter; reviewer cannot
  approve while scan pending; no-repo submission shows `not_applicable`, approvable.

### R-7 Detections drill-down + server attribution (F-7, F-8) — P0, L
**Attribution mechanism (decided): IDs, not names.**
- BE: detections feed selects `audit_events.tool_id` and joins
  `tool_registry.server_id → server_registry` (no tool_name joins — ambiguous under
  UNIQUE(name, version)). Where `tool_id` is NULL (legacy rows), display unattributed —
  no backfill guessing.
- BE: `anomaly.py` persistence fixed to record real `invocation_ids` and `tool_id`s
  (today it writes an always-empty array and drops tool_name); alert detail endpoint
  `GET /api/v1/anomaly/alerts/{id}` resolves them to tools/servers. Existing alerts
  remain unattributed (documented; no backfill).
- UI: feed rows clickable → detail drawer (time, principal, tool, server link, deny
  reasons, hashed digest); top-detections rows filter the feed; `?server_id=` filter;
  server detail card gets a "Detections" tab.
- FM: tool deleted after event ⇒ drawer shows tool id + "unregistered"; join failure
  degrades to today's unlinked row, never a 500.
- **INV-001 test (explicit):** Playwright/API assertion that drawer/detail responses
  contain no raw argument substrings — only hashed digests and reason codes
  (deny-reason strings audited once for arg-derived content as part of implementation).
- AC: from a detection row, two clicks reach the MCP server it fired on; a server page
  lists only its detections; legacy/NULL rows render as "unattributed" without error.

### R-8 Docs & repo hygiene (F-9, F-10) — P1, S
Restore/refresh `docs/ROADMAP.md`, land this PRD, fix the CLAUDE.md pointer, execute
D-1 follow-through (remove React app from compose/docs or mark experimental), commit
the two locally-modified routers (prereqs for R-4/R-6/SBOM counters).

### R-9 SBOM inventory — interim, no-syft, manifest-parsed (F-4; supersedes R-4 for this pass) — P0, M
**Scoping call, made explicit:** a real syft sidecar (R-4 as originally written) is an
L-sized, new-service change (new compose entry, new image, new trust-boundary
contract) — too large to land safely in this pass alongside R-10. The tradeoff taken
here: ship a **textual-only** manifest parser (no `pip install`, no `npm install`, no
code execution — strictly regex/line parsing of dependency-declaration files) that
runs in the *same* already-accepted trust boundary as R-0's trufflehog/pip-audit
(the proxy container, on the same shallow clone `submission_scanner.py` already makes
at `_clone_repo`/`scan_submission` — no second clone). This is honestly a **partial**
SBOM (declared dependencies, not a resolved/transitive graph or license data) — R-4's
full syft sidecar remains the P2 upgrade path for a real transitive-dependency SBOM.
- BE: new `services/sbom_inventory.py` (or a function in `submission_scanner.py`,
  dev's call) parses `requirements.txt` (`name==version` / `name>=version` lines,
  skip comments/`-r`/`-e`/VCS refs) and, best-effort, `pyproject.toml`
  `[tool.poetry.dependencies]`/`[project.dependencies]` and `package.json`
  `dependencies`/`devDependencies` if present in the cloned repo. Emits a list of
  `{name, version, purl}` — version may be `"*"` if unpinned; that's surfaced, not
  hidden.
- BE: at the point R-10 creates a `tool_registry` row (see R-10), pass the parsed
  component list into `services/sbom.py:generate_cyclonedx_sbom` — extend its
  `components` list beyond the single schema-digest component (`sbom.py:76-92`) with
  one CycloneDX `library` component per parsed dependency (`purl`, `version`, no
  `hashes` — we didn't resolve/download anything, so no real hash exists; omit the
  `hashes` array for these rather than fabricate one). Existing signature/attestation
  component and HMAC signing (`sbom.py:116-130`) are unchanged.
- UI: SBOM tab per-tool detail shows the component table (name, version, purl,
  "declared, unresolved" badge); empty-state text distinguishes "no manifest found in
  repo" from "attestation-only — no source repo" (F-4's original empty-state ask).
- FM: malformed/huge manifest (e.g. minified `package.json` with 10k lines) ⇒ parser
  is bounded (max file size read, e.g. 2 MB; max components emitted, e.g. 500) and
  degrades to "manifest present but not fully parsed" rather than hanging or OOMing;
  never blocks scan approval (this is inventory, not a security gate — unlike R-0's
  scanners, a parse failure here is `not_applicable`, not `error`).
- AC: a repo submission with a `requirements.txt` of 5 pinned packages, once
  provisioned via R-10, shows exactly those 5 components with versions in the SBOM UI;
  a no-repo (no-code) submission's resulting scaffold-only record (R-10) shows the
  "no source repo" empty state, not "no manifest found"; a 3 MB fuzzed `package.json`
  does not crash the scan worker or block approval.

### R-10 Approval → provisioning pipeline (F-14, F-15) — P0, L — *prerequisite for R-9's UI, R-12*
Defines precisely what "approved and running" means per submission type, and closes
the gap where approval never produces an invocable tool.
- **Repo path:** on `provide_running_url` reaching `status='approved'`
  (`submission.py:514-525`), synchronously (same request, not a background task —
  the submitter is waiting on this response) call the existing discovery logic
  (`tools.py:1500-1524`'s body, refactored into a callable used by both the HTTP route
  and this call site) against the just-saved `upstream_url`. Each discovered tool is
  inserted into `tool_registry` **quarantined** (INV-005 unchanged — auto-provisioning
  is not an INV-005 bypass) with `server_id` set, and — this is the F-14 fix —
  `kc_token_audience` populated from `server_registry.upstream_idp_config.audience`
  when `injection_mode='kc_token_exchange'` (the wizard field becomes live). SBOM
  generation (R-9) runs at this same insertion point. Response to the submitter
  reports `{"submission_status": "active", "tools_provisioned": N, "quarantined": true}`
  — "provisioned" is explicitly not "invocable yet"; quarantine release is a separate,
  existing admin action (unchanged from today's discover-tools flow) and is *not*
  auto-approved by this requirement — auto-provisioning + auto-quarantine-release
  together would be a real INV-005 weakening; auto-provisioning alone is not.
- **No-code path:** `provide_running_url` cannot apply (F-15) — a no-code submission
  never has an `upstream_url`. Replace its post-approval terminal state: on
  `approve_submission` when `github_repo_url IS NULL`, set
  `submission_status='scaffold_ready'` directly (skip `approved_pending_url` for this
  branch only) instead of the current identical treatment. `scaffold_ready` is a new,
  clearly-distinct-from-"active" status: the portal must never render it with an
  "Approved — Needs URL" or any "running" language. My-submissions strip
  (`portal.py:1791-1799` `_SUB_CHIP`) and admin queue (`portal.py:4057-4066`
  `_STATUS_COLOR`) get a `scaffold_ready` entry reading "Approved — scaffold only (not
  running)" with a link to the existing `GET /api/v1/submissions/{id}/scaffold`
  download (`submission.py:348+`), and copy explaining the submitter must build and
  self-host it, then submit *that* as a **new**, repo-backed submission to actually
  go live. This is a deliberate non-goal to auto-build/auto-host no-code scaffolds —
  that would mean executing submitter-controlled code inside platform infrastructure,
  a materially larger and separate security surface than this pass.
- Migration: `submission_status` is a free-text column already carrying ad hoc values
  (no enum/CHECK found in `server_registry` migrations) — `scaffold_ready` is a new
  string value, no schema migration needed; confirm no downstream code does an
  exhaustive `IN (...)` match that would silently drop it (grep `submission_status`
  call sites as part of implementation, not just the portal ones cited above).
- FM: discovery call fails mid-`provide_running_url` (upstream unreachable at the
  moment of approval) ⇒ `upstream_url`/`status='approved'` still commit (submitter
  isn't blocked by a flaky upstream at save time), `tools_provisioned=0` is returned
  with a clear message, and the existing manual `discover-tools` admin route remains
  available as a retry path (not removed — it becomes the recovery mechanism, not the
  primary one).
- AC: approving + providing a URL for a repo submission results in ≥ 1 quarantined
  `tool_registry` row with `server_id` set and (for `kc_token_exchange` mode)
  `kc_token_audience` matching the wizard's "Target audience" input, with no separate
  manual "Register Tool" step; a no-code submission approval never reaches
  `approved_pending_url` and never shows "running"/"active" language anywhere in the
  portal; the existing manual discover-tools endpoint still works unchanged for the
  retry/legacy case.

### R-11 Admin UI for maintainers + debug/maintenance mode (new backend, no UI yet) — P0, S
The backend (migration V048, `server_registry.py:420-493`, `services/invocation.py`
Step-1.1 gate) is done and smoke-tested; this is UI-only.
- `fragment_admin_servers`'s query (`portal.py:2063-2068`) gains `maintainers,
  debug_mode` columns; the per-server row dropdown (`portal.py:2152-2162`, currently
  Detections/Quarantine/Delete) gains "Maintainers…" (opens a 2-slot editable list,
  `PUT /api/v1/servers/{id}/maintainers`) and a "Debug mode" toggle
  (`POST /api/v1/servers/{id}/debug-mode`) with a visible "🔧 maintenance" badge on
  the row when `debug_mode=true` (reuses the agent-portal's existing "maintenance"
  cstatus copy at `portal.py:1722` for consistent language).
- FM: non-owner/non-maintainer/non-admin attempts the toggle ⇒ existing 403 from
  `server_registry.py:404` surfaces as an inline error, not a silent no-op.
- AC: as alice (owner), setting 2 maintainers and enabling debug mode updates the row
  badge without a page reload; as bob (neither owner nor maintainer), the invoke path
  is denied per the existing backend gate (regression check only — gate itself is not
  new work here).

### R-12 Submission-review UI depth (F-13) — P0, M — *builds on R-9, R-10's richer data*
- `fragment_admin_submissions`'s query (`portal.py:4038-4042`) adds
  `upstream_idp_config`; render it as a labeled key/value block (mode, audience,
  client id/scopes as applicable) so a reviewer can see what will actually be wired
  at approval time (directly closes the F-14 blind-approval risk, not just F-13).
- Scan report renders for **any** terminal scan status, not only `scan_blocked`
  (`portal.py:4092` condition drops the `st ==` guard, keeps the finding-severity
  styling); a `passed` scan with zero findings shows an explicit "0 findings — n
  scanners ran" line rather than nothing.
- Repo link (`portal.py:4120-4128`) gets equal visual weight to the new SBOM link:
  once R-9 lands, a "View SBOM" link/button appears per submission once its
  provisioned tool(s) (R-10) have `sbom_records`; before provisioning, the slot shows
  "not yet provisioned" rather than being absent.
- FM: `upstream_idp_config` contains a stored secret reference (it shouldn't — secrets
  live in the credential broker, not this JSONB column) ⇒ render defensively:
  allowlist the keys actually written by the wizard (`portal.py:4573`-area collection)
  rather than dumping the JSONB verbatim, so an unexpected key never leaks into the
  admin HTML by accident.
- AC: a `kc_token_exchange` submission's reviewer view shows the exact audience string
  the submitter entered; a passed scan shows a non-empty report; a submission with
  provisioned tools shows a working SBOM link.

### R-13 Role visibility: link out to Keycloak, no in-platform role editor (F-12) — P1, S
- Profile page (R-3) gains a "Manage roles in Keycloak" link to the Keycloak admin
  console's user-detail page for the current principal (constructed from the existing
  `OIDC_*` settings — realm/base URL already in config, no new secret needed) alongside
  the existing read-only role list.
- **Explicitly out of scope for this pass, and why:** a full in-platform role-write API
  is a new privilege-escalation surface — whoever can grant `platform_admin` can grant
  themselves or anyone else full control of every security gate this PRD's earlier
  requirements harden (R-2's access UI, R-11's debug-mode bypass, R-0's scanner gate).
  That needs its own dedicated security review (threat model: who can call the
  endpoint, what confirms a grant, how it's audited, whether Keycloak should remain
  the single source of truth or a mirror-write pattern is safe) — not a few routes
  bolted onto this implementation pass. This requirement intentionally ships the
  link-out only.
- FM: Keycloak console unreachable from the admin's network ⇒ link still renders (it's
  a static URL construction, not a live health check); no failure mode to handle
  beyond a dead link, which is acceptable for an external-console link.
- AC: an admin viewing bob's profile sees bob's current roles (existing R-3 behavior)
  plus a working deep link to Keycloak's console for that principal; no new
  role-mutation endpoint exists anywhere in the diff.

## 4. Acceptance & verification

- Each R-* AC becomes a Playwright spec extending `ui/e2e/portal-acceptance.spec.ts`
  (AC-09..16 for R-0..R-7, AC-17..21 for R-9..R-13 below), including the two security
  regression tests already defined (R-5 clamp + resolver env-lock; R-7 INV-001 drawer
  assertion), R-0's fail-closed scanner test, and three new ones this revision adds:
  R-9's bounded-parser test (oversized manifest doesn't hang/block approval), R-10's
  INV-005 regression test (auto-provisioned tools are still born quarantined — auto-
  provisioning is not an auto-quarantine-release), and R-10's no-code terminal-state
  test (`scaffold_ready` never renders "active"/"running" copy anywhere in the portal).
- `make test-lab-functional` stays green; portal acceptance suite passes.
- No regression to security invariants: INV-001, INV-003 (OPA default deny), INV-005
  (quarantine), fail-closed credential broker and scanner.

## 5. Phasing

- **P0 — done this session (uncommitted, verified live):** R-0, R-1, R-2, R-3, R-6,
  R-7 — R-0 is new (security bug found in review); the rest map to reported issues #1
  (R-1), #2/#3 (R-2/R-3), #6 (R-6), #7/#8 (R-7).
- **P0 — still open, ordered for implementation (top-to-bottom, grouped by shared
  files to minimize merge conflict as one dev works down the list):**
  1. **R-10** (`submission.py`, `tools.py`, `portal.py` status-chip maps) — foundational:
     defines the tool_registry-creation point that R-9 attaches SBOM data to and that
     R-12 displays richer data about. Do this first; everything else in this list reads
     easier once "approved and running" actually means something.
  2. **R-9** (`services/sbom.py`, `submission_scanner.py`, `tools.py` at R-10's new
     insertion point, portal SBOM tab) — needs R-10's tool_registry row to attach
     `sbom_records` to (FK is `NOT NULL`); touches the same `tools.py` region R-10 just
     changed, so doing it immediately after avoids re-reading that diff cold.
  3. **R-12** (`portal.py` `fragment_admin_submissions`, same function as F-13's
     evidence) — consumes both R-10 (`upstream_idp_config` now meaningfully wired) and
     R-9 (SBOM link); natural next step once both exist to link to.
  4. **R-11** (`portal.py` `fragment_admin_servers`, adjacent admin-fragment territory
     to R-12's edit in the same file) — backend is already done; UI-only, low risk,
     grouped here purely to keep `portal.py` admin-fragment edits contiguous.
  - R-13 is P1 (below) rather than P0 because it's additive polish on the already-shipped
    R-3 profile page with zero dependency on R-9–R-12; nothing blocks on it.
- **P1:** R-4 is **superseded by R-9** for this pass (see R-9's note) and demoted
  further to "P2 real syft sidecar" rather than carried as an active P1 item; R-5
  (issue #5 — visibility/bounded config; using the LLM *for detections* is P2 because
  it is a new capability, not a fix), R-8, **R-13** (Keycloak role-visibility link-out).
- **P2 (stretch):** real syft-sidecar SBOM (R-4's original scope, now that R-9 has
  proven the tool_registry-creation insertion point and the sidecar only needs to
  swap the parser for a syft-shelled-out call), semgrep in scanner sidecar,
  LLM-assisted detection triage (summarize an alert's invocation window via Ollama),
  SPDX export, Keycloak admin-API principal sync, in-platform role-write API (**only**
  after a dedicated security review per R-13's note — not scheduled by this PRD).

**Estimate honesty:** the six done P0 items totaled roughly the ~3.5 engineer-weeks
originally estimated (R-2 and R-7 were both L with BE components, as flagged). The four
still-open P0 items (R-10 L, R-9 M, R-12 M, R-11 S) add ~2 more engineer-weeks. If any
exceeds 2× its estimate, that trips the D-1 falsifier — stop and re-evaluate the
frontend strategy rather than pushing through.

## 6. Risks

- **Three access layers with mismatched identity keys** (KC sub vs client_id vs
  principal_id) — R-2 mitigates by displaying client grants as a separate dimension
  and validating effective-access against live OPA; a consolidation ADR should follow.
- **R-9's parser runs inside the proxy container**, same as R-0's interim scanner
  placement — accepted for this pass because it's textual-only (no subprocess, no
  package manager invocation), but it's still attacker-controlled input; the bounded
  file-size/component-count limits (R-9 FM) are the mitigation, not a sidecar boundary.
  A real syft sidecar (P2) is still the correct end state for anything that resolves
  or executes.
- **R-10's auto-provisioning is a new automatic write path into `tool_registry`** —
  mitigated by keeping INV-005 (quarantine-on-insert) completely unchanged; the AC and
  a dedicated regression test both assert this explicitly because it's the single
  highest-consequence change in this revision if it regresses silently.
- **portal.py is 4,491+ lines and R-9/R-10/R-11/R-12/R-13 all touch it** — same
  extraction guidance as v2: fragments should move toward
  `proxy/app/routers/portal/` modules rather than growing the single file further;
  the implementation order above is chosen to reduce *diff* collisions, not as a
  substitute for that extraction work.
- **Lab DB is not fresh-bootable** — all schema changes ship as forward migrations
  only (R-10's `scaffold_ready` status value needs no migration — free-text column —
  but any future enum/CHECK on `submission_status` would); never `down -v`.
