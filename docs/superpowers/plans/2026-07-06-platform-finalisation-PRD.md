---
type: prd
project: mcp-security-platform
date: 2026-07-06
status: ready-for-implementation
implementation_plan: ./2026-07-06-platform-finalisation.md
tracker: Brain/Vault/00_AI/mcp-security-platform/Codex_review/Claude_status.md
---

# PRD — Platform Finalisation (remaining Codex-review items)

**Implementation plan (HOW / sequencing / work packages):**
[`2026-07-06-platform-finalisation.md`](./2026-07-06-platform-finalisation.md) — this PRD
is the WHAT/WHY; that plan is the HOW. Every requirement below names its work package
(WP-x) in the plan. Do not implement from this PRD alone — open the plan's WP, then write
the WP's own detailed sub-plan (superpowers:writing-plans) at pickup.

**Status tracker (single source of truth for done/not-done):** `Codex_review/Claude_status.md`.
Update the CR row + matching `docs/spec/*.md` after every item lands.

## For the Sonnet implementer — read first

- **Model routing:** you (Sonnet) do the coding + testing. Design/architecture calls that
  aren't already settled here or in the plan → escalate, don't invent.
- **Fail closed, always.** Lookup error, missing scanner binary, LLM-audit outage,
  unparseable manifest = block / review_required / error. Never a silent pass. This is the
  #1 source of real bugs in this codebase (CR-09, CR-11 were both fail-open).
- **`/mcp` errors are HTTP 200 + JSON-RPC error body.** A broken gate looks like a 200.
  Verify gates with `make test-lab-functional`, NOT curl status codes. `_err()` takes no
  `http_status` kwarg.
- **Secrets never appear raw OR base64** in logs/audit/scan/errors. Every credential path
  gets a redaction test.
- **Never wipe `postgres-data` / `down -v`** outside the explicitly-approved WP-D3 gate.
- **Migrations must fresh-boot:** grant only to roles that exist (`compliance_checker_app`,
  `proxy_app` — never `compliance_checker`/`mcp_proxy`); no `REFERENCES` on ENUM types.
- **OPA edits are a no-op until `make sign-policy-bundle`.**
- **Definition of done (every item):** unit tests green + `make test-lab-functional` green
  + relevant acceptance suite green + tracker row + spec doc updated + committed on a branch.

## Current state (what is already done — do NOT redo)

Done this program: CR-02 (enum module, additive only), CR-03/07/08/09/11/15/16/18 (partial —
evidence-gap fixes), CR-05 (basic_auth, full), CR-04 Entra app-only + delegated (full),
plus the credential-codec product bug (unified on `approach_a`). All 9 implemented auth
modes pass E2E; functional 46/1/0; acceptance 26/1/0.

**This PRD covers only what remains open.** Two buckets: fully-unstarted subsystems, and
load-bearing remainders of partial fixes.

---

## P0 — Unblocks documentation & closes the auth story

### PRD-1 · Canonical auth-mode model, finished (CR-02 remainder) → WP-A5

**Problem.** The `AuthMode` enum exists (`app/services/auth_modes.py`) but is not
authoritative: 5+ call sites (`submission.py`, `server_onboarding.py`,
`admin_credentials.py`, `portal.py`, `dispatcher.py`) still declare their own mode lists,
and nothing rejects an unsupported mode until first invocation.

**Requirements.**
- All mode lists outside `auth_modes.py` replaced by the canonical enum.
- Approval-time validator: an unsupported mode/combo is rejected at draft/update time, with
  a structured reason — not at first invoke.
- Legacy `oauth_user_token` rows migrated to canonical names.

**Acceptance.** `grep` finds zero hardcoded mode lists outside `auth_modes.py`; a rejection
test exists per unsupported combo; existing submissions unaffected (migration test).
**Unblocks PRD-11 (docs).**

### PRD-2 · Flip scan-freshness default to enforced (CR-11 remainder) → Phase 0 Task 0.5

**Problem.** `SCAN_FRESHNESS_ENFORCED` fail-open bug is fixed, but the default is still off.

**Requirements.** Flip default to `true` (all lab servers already have fresh
`last_rescanned_at`). Ship the `scan_valid_until`/`scan_commit`/`scan_image_digest` columns
+ admin waiver-with-expiry alongside, OR record them as explicit fast-follow.

**Acceptance.** `make test-lab-functional` green (46/1/0) with the default enforced.
*(Cheapest item — good warm-up.)*

---

## P1 — Track A: identity & policy (strict order A1 → A2 → A3)

### PRD-3 · Typed principal propagation (CR-10) → WP-A1

**Problem.** `invocation.py` forwards only bare `X-User-Sub`. An OIDC user, an API key, and
an mTLS agent that happen to share a subject string collide onto the same credential set.

**Requirements.**
- Forward `X-Principal-Id/-Type/-Issuer/-Display-Sub`; keep `X-User-Sub` as alias.
- SDK `identity()` exposes typed fields (needs `stateless_http=True`).
- **Dual-read** credential migration: lookup by typed principal, fall back to bare sub;
  writes always typed. NO big-bang rewrite. **Bare-sub fallback must never cross principal
  types** — a cross-type fallback is a deny + audit event, not a match.
- Typed principal in audit events + OPA input (then `make sign-policy-bundle`).

**Acceptance.** Collision test: 3 principals, identical subject IDs → 3 distinct credential
sets. Existing enrollments still resolve (dual-read test). **Prerequisite for PRD-5.**

### PRD-4 · OAuth/IdP policy engine (CR-13, + CR-03 remainder) → WP-A2

**Problem.** No table governs which issuer/tenant/scope an onboarded OAuth server may
request; requested config == approved config today.

**Requirements.**
- `oauth_provider_policy` table + `approved_upstream_idp_config` separate from requested.
- Approval-time validation: requested ⊆ policy; high-risk scopes
  (write/admin/mail/files/offline_access) need explicit reviewer approval.
- Dispatcher uses only approved config at invoke time.
- Fold in CR-03: per-server `approved_token_audience`/`approved_token_scopes` columns +
  requested-vs-approved surfacing; migrate `KC_TOKEN_EXCHANGE_ALLOWED_AUDIENCES` env
  allowlist into this model.
- **Trap:** `service_account` scope (`"openid"`) and `kc_token_exchange` audience
  (`"lab-tickets"`) need DIFFERENT validation shapes — do not reuse one allowlist (already
  tried and rejected; breaks every existing service_account tool).

**Acceptance.** Overbroad-Entra-scope, unknown-issuer, and broad-service-account-audience
tests all reject; existing lab service_account tools (lab-gitea, lab-grafana-mcp,
lab-wazuh) still invoke green. **Prerequisite for PRD-5.**

### PRD-5 · External IdP adapters — generic + Jira (CR-04 remainder) → WP-A3

**Problem.** Entra works E2E, but the generic non-KC/non-Entra `external_oauth_user_token`
adapter registry and Jira 3LO are not built. `kc_token_exchange` and
`external_oauth_user_token` are still conflated in the dispatcher.

**Requirements.** (NOT greenfield — audit `credential_broker/adapters/registry.py` first.)
- Extend the existing adapter registry with issuer/endpoints/refresh/revocation/scopes/
  client-type/consent-type metadata, governed by PRD-4's policy table.
- New dispatcher branch `external_oauth_user_token`, cleanly separated from
  `kc_token_exchange`. Add `external_oauth_client_credentials` branch.
- Jira (if in scope per D2): `credential_broker/adapters/jira.py`, OAuth 2.0 3LO.
- Enrollment-status endpoint/health per per-user OAuth service.

**Acceptance.** Generic external-OAuth has passing dispatch tests; enrollment state visible.
**D2 = Entra-first, Jira fast-follow:** the generic registry is the finalisation deliverable;
Jira 3LO lands last and is droppable without re-planning — not a blocker for closeout.

---

## P1 — Track B: scan & deploy pipeline (strict order B1 → B2 → B3), parallel to Track A

### PRD-6 · Isolated scanner worker + job queue (CR-14) → WP-B1

**Problem.** Untrusted clone + scanners run inside the proxy container today.

**Requirements.**
- Postgres-backed job queue (status/attempts/dead-letter — no new broker dependency).
- New `scanner-worker` service (git, trufflehog, osv-scanner, pip-audit, npm, govulncheck,
  syft, semgrep, mcp_checker). No proxy secrets/DB-admin/Vault/gateway-secret in its env;
  read-only checkout; CPU/mem/pids/time/egress limits.
- **Execution/adjudication split (non-negotiable):** the worker emits RAW scanner output
  only — it NEVER writes `block`/`scan_status`/state transitions. A trusted evaluator in
  the proxy (never touches attacker content) parses raw output, applies policy, writes the
  verdict. Worker DB role = INSERT-only on raw-results + UPDATE only its own claim/heartbeat
  columns. A corrupted worker can at worst produce parse-error → `scan_status='error'`
  (fail closed), never forge a PASS.
- Migrate the EXISTING pip-audit/clone flow into the worker first (no new scanners) to prove
  behavior unchanged.

**Acceptance.** Existing scan-gated acceptance tests (AT3 malicious-submission) pass with
scanning fully out of the proxy; proxy image has no scanner binaries; dead-letter tested.
**Substrate for PRD-7 and PRD-8.**

### PRD-7 · Multi-ecosystem dependency CVE gate (CR-12) → WP-B2

**Problem.** CVE gate is Python-only (pip-audit).

**Requirements.** (Issue file is complete — use its schema verbatim.)
- Scanner layers in the worker: OSV-Scanner, pip-audit, npm audit, govulncheck. Go-native
  "incomplete" marker FORCES review-required (a submitter can break `go.mod` to trigger the
  downgrade — incomplete-that-passes is an attacker-controlled fail-open).
- Normalized finding schema (scanner, ecosystem, package, version, vuln_id, aliases,
  severity, cvss_score, fix_versions, source, reachable, direct_dependency, block,
  waiver_id, message); alias collapse (CVE/GHSA/GO/RUSTSEC → one group).
- Fail-closed: parse error/missing binary → error; missing npm lockfile → review-required;
  unknown severity → review-required; severity from advisories/CVSS, never inferred.
- Waivers: expiring, exact package+version+vuln match, integrity = DB-role provenance +
  `waived_by` (typed principal) + `expires_at` + audit event (NOT a crypto signature).
  Waived findings stay visible in SBOM/review UI.

**Acceptance.** All 7 acceptance fixtures from the issue pass (Python-critical blocks,
Node-with-lockfile blocks, Node-without-lockfile → review, Go-reachable blocks,
missing-binary → error, mixed-ecosystem runs both, valid-waiver exact-match-only).

### PRD-8 · Apply/deploy/verify loop (CR-01, + CR-06/CR-07 remainders) → WP-B3

**The centerpiece.** Prerequisites: PRD-6, PRD-7, **and PRD-3 + PRD-4** (verify/release
consume typed principals + approved policy config). Do NOT start before A1+A2 land.

**Problem.** No path from approved submission → built → deployed → verified → invocable.
`provide-url` self-hosted is the only route; there is no platform-managed deploy.

**Requirements (phased, each phase independently shippable).**
1. Schema + state machine: `deployment_status`, `build_artifact_digest`, `runtime_url`,
   `verification_report`, `provenance`; every transition state-guarded + audited. New queue
   job types: `build_requested`/`deploy_requested`/`verify_requested`.
2. **Build worker — UNPRIVILEGED** (rootless buildah/kaniko, no docker/podman socket),
   holds no proxy secrets, emits artifacts only. SBOM + provenance recorded; built image
   runs through PRD-7's scan layer. **Build-source pinning (TOCTOU):** build consumes the
   exact scanned+approved commit/content digest — never a re-clone of branch HEAD; digest
   mismatch = build refused. Runtime launch is a separate small **privileged launcher** on
   the host/compose layer consuming only evaluator-approved digest-pinned artifacts — this
   permanently separates the SEC-05-trusted process from the socket-capable one (resolves
   the CR-18 "no env is both" contradiction architecturally).
3. Deploy: per-server isolated runtime (dedicated network, resource limits, read-only fs,
   egress allowlist — lab's existing per-server compose patterns are the template);
   healthcheck gate.
4. Verify: discovery via strict-audit path (tools register QUARANTINED — deploy success
   NEVER auto-releases; reuse CR-07 evidence gate). Fold in CR-07 remainder here:
   `POST .../release` endpoint + `released_by`/`released_at`/`release_notes` +
   `TOOL_RELEASED` audit event. Final invocation probe; `verification_report` written.
5. API: `POST /api/v1/submissions/{id}/apply`,
   `GET /api/v1/submissions/{id}/verification-report`. `provide-url` runs the SAME probes.
6. CR-06 remainder: machine-testable JSON/YAML contract subset + `contract_version` on
   server metadata; verify phase runs it against the deployed server.

**Acceptance.** One acceptance test: scaffold submission goes draft → apply → built →
scanned → deployed → verified → quarantined-tools → evidence-gated release → invocable.
Self-hosted path passes the same probes.

---

## P2 — Ops & docs (after both tracks converge)

### PRD-9 · Observability, audit, runbooks (CR-17) → WP-D1

**Requirements.** `/metrics` on proxy + scanner-worker (authz decisions, deny rates, scan
queue depth/latency, dead-letter, credential-broker failures, OPA/Vault reachability, audit
emit failures, quarantine backlog). Dashboards (extend lab Grafana). Alerts on hard
invariants first (OPA unreachable, audit-emit failure, Vault failure, scanner dead-letter,
stale scans, rising deny rate) — thresholds labeled "initial defaults". 9 runbooks under
`docs/runbooks/`. Synthetic probe: login → low-risk invoke → audit-emission check.

**Acceptance.** Probe green in lab; dashboards render; 9 runbooks each walked once against
the lab. *(D4 = no prod env: alert thresholds ship as labeled "initial defaults".)*

### PRD-10 · User/admin documentation (CR-19) → WP-D2

**Prerequisite: PRD-1 done** (docs the canonical model, which must exist and be enforced).

**Requirements.** The 13-file role-split set (user/admin/reference/troubleshooting).
Lifecycle language matches REAL post-PRD-8 states. **Auth-mode table GENERATED from
`auth_modes.py`** (one generator script + a docs test asserting it's current).
"Unsupported today" labels from the enum status matrix. Exact verification commands +
expected output per supported mode. Portal screens link to doc pages.

**Acceptance.** All 13 files exist; generated-table docs test green; a non-expert
walkthrough of `self-service-onboarding.md` succeeds against the lab verbatim.

### PRD-11 · End-of-program gate (CR-18 closeout + full wipe) → WP-D3

**Requirements.** All CR-01..19 rows read `fixed` or have user-accepted disposition. Specs +
`ARCHITECTURE.md` reflect final state. CR-18: the "no env is both SEC-05-trusted and
socket-capable" limitation is resolved architecturally by PRD-8's launcher split; document
the TEST consequence (suites needing both run as two cooperating suites). ONE approved lab
wipe + `lab-setup.sh --reset`; both suites green post-wipe including the new
apply/deploy/verify acceptance test.

---

## Product decisions (RESOLVED 2026-07-06)

| # | Decision | Outcome | Effect |
|---|---|---|---|
| D1 | basic_auth keep/drop | **Keep** | Implemented (CR-05 done) |
| D2 | Jira 3LO launch requirement? | **Entra-first, Jira fast-follow** | PRD-5 builds the generic external-OAuth adapter registry; Jira 3LO lands last and is droppable — NOT a finalisation blocker |
| D3 | Helm production-supported? | **Compose-only, Helm experimental** | CR-16 remainder stays OUT of scope; label Helm "experimental" in docs |
| D4 | Prod env to calibrate SLOs? | **None — ship marked defaults** | PRD-9 ships /metrics + dashboards + runbooks + probe now; alert thresholds labeled "initial defaults — tune in first prod deployment" |

## Sequencing (from the plan)

`Phase 0 (PRD-1 unblock prep, PRD-2 flip)` → Tracks A & B in parallel:
**A:** PRD-3 → PRD-4 → PRD-5 → (PRD-1 finish) · **B:** PRD-6 → PRD-7 → PRD-8 (convergence,
needs A1+A2) → then **P2:** PRD-9 → PRD-10 → PRD-11. Critical path ≈ B1→B2→B3→D1→D2→D3
(~16–18 sessions with A absorbed alongside; ±50% bear-case band).

## Explicitly out of scope (recorded)

CR-16 remainder (Helm subchart, values.schema.json, helm test) unless D3 says otherwise;
CR-08/CR-09 remainders (registration_source enum, discovery manifest limits) — hardening
backlog, main holes closed, discovery limits get a home in PRD-8 phase 4 if trivial there;
result signing beyond service-identity binding — revisit at appsec review.
