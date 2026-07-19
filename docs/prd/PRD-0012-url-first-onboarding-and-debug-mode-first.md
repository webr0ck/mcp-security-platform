# PRD-0012 — URL-first self-hosted onboarding, re-approval on change, debug-mode-first

Status: **v2 — critic-hardened (3-critic pass folded in), pending final owner go-ahead**
Date: 2026-07-19 · Scope: **self-hosted flow only** (platform-deployed apply/build/deploy pipeline unchanged).

## Problem (verified)
Self-hosted flow today: `draft → submit (declares requested_upstream_url) → scan
→ awaiting_review → approve → approved_pending_url ("url required") → submitter
provide-url → active`. Defects: (1) reviewer never sees the real backend
(`upstream_url` empty at review, `SubmissionReview.tsx:107`); (2) the "set URL"
control is submitter-only and absent from the admin Servers tab (dead-end); (3)
`PATCH upstream_url` (`server_registry.py:356`) silently overwrites a live
backend with no re-scan/re-review; (4) `debug_mode` is never auto-set.

## THE load-bearing correction (all 3 critics, same root cause)
Runtime enforcement gates on **`server_registry.status='approved'`**
(`entitlement.py:343`, `credential_broker/registry.py:117`), **`tool_registry.status`**
+ **`server_registry.debug_mode`** (`invocation.py` Step 1/1.1), and **NOT**
`submission_status`. Therefore **every state change in this design must move the
real enforcement columns at the moment the change is *requested*, not when it is
re-approved.** `submission_status` is a review-queue label with zero runtime
effect.

## Design (v2)

### C1 — URL is a submit requirement; reviewer sees the real target
- `requested_upstream_url` (already required at `submit_for_review`,
  `submission.py:511`) is SSRF-validated **at submit** via the full
  `validate_upstream_url_ssrf` (scheme/embedded-cred/CIDR checks —
  `server_onboarding.py:459`), not the cheap structural guard. Failure blocks
  submit with a clear error (non-name-consuming, per the Fix-4 pattern).
- Reviewer card (React `SubmissionReview.tsx` + portal reviewer card) shows the
  live URL, git repo + browse-code, injection mode, IdP config, SBOM, scan
  findings — everything except secrets.

### C2 — Approve runs discovery+verify and lands in debug mode (H-01 preserved)
On `approve` for a self-hosted submission (`deployment_status IS NULL` — the
discriminator, see §Discriminator), in the approve handler:
1. Re-run **full** `validate_upstream_url_ssrf(requested_upstream_url)` and
   persist the matched `upstream_allowlist_entry` (identical to
   `provide_running_url:1055`); copy → `upstream_url`.
2. Run discovery (tools land `quarantined`, INV-005) then
   `run_verification_probes` (`deploy_verifier`). **H-01 ordering preserved**:
   `status='approved'` is only written after probes succeed; before that the
   server sits in debug mode, not live.
3. Set `debug_mode=TRUE` with `debug_enabled_by = <approving reviewer sub>`,
   `debug_enabled_at = now()` (real identity — never a `'system'` sentinel;
   satisfies `server_registry_debug_consistency`, V048).
4. **Release the discovered tools from quarantine** (scan-passed + server-approved
   ⇒ release is evidence-legitimate per INV-006/CR-07). Tools become `active`
   BUT `debug_mode=TRUE` restricts invocation to owner/maintainers (Step 1.1),
   so the owner can run **real** test calls without weakening INV-005 (release is
   the deliberate evidence gate; debug_mode is the containment). This resolves
   the appsec HIGH-1 quarantine/debug conflict: the owner tests released tools,
   gated to owner-only, not quarantined ones.
- `approved_pending_url` remains only as a legacy path for existing rows.

### C3 — Backend/code change ⇒ demote real state NOW, then re-scan + re-review
New governed endpoint **`POST /api/v1/servers/{id}/request-change`** (owner or
admin; own CAS + segregation-of-duties mirroring the approve path). In ONE
transaction it:
1. **Quarantines every `tool_registry` row for `server_id`** (`status='quarantined'`).
   This is the real revocation lever — INV-005 Step 1 then blocks ALL invocation
   (incl. owner) against the changed/unverified backend, and closes the
   skip-idempotent-discovery hole (appsec CRITICAL 2): stale same-name tools are
   re-quarantined, not left `active`.
2. **Demotes `server_registry.status`** from `approved` → `quarantined` (defense
   in depth on the entitlement/credential gates), with an audit event.
3. Sets `submission_status='awaiting_review'` via an atomic
   `UPDATE ... WHERE status IN ('approved','active')` CAS (legal source states
   only; rejects mid-scan/rejected/deleted).
4. Re-enqueues a scan using a **guarded re-review scan path** (NOT the unguarded
   `_evaluate_submission_scan`; a re-review job that CAS-guards on the current
   demoted state, so a concurrent reject/delete can't be clobbered — architect §4).
Then: reviewer re-approves → C2 runs again (re-discover, re-verify, release,
debug-mode ON) → owner verifies → go live.
- `PATCH upstream_url` on a self-hosted approved server is **re-routed through
  `request-change`** (no more silent overwrite). The admin PATCH branch checks
  `deployment_status IS NULL`; platform-deployed servers keep today's behavior.

### C4 — Debug-mode-first for new AND updated; explicit verify → publish
- New approvals (C2) and post-change re-approvals (C3) both land in debug mode
  with the tools released-but-owner-gated.
- **Retry verification** is a distinct control from **Go live** (product HIGH-1):
  - `POST /servers/{id}/verify` — re-runs `run_verification_probes`; on failure
    the server stays in debug mode and the card shows the probe error + View logs.
  - `POST /servers/{id}/debug-mode {enabled:false}` ("Go live / exit
    maintenance") — only offered once verification has passed; opens invocation
    to all entitled callers.
- **Existing live servers are grandfathered** — C4 applies only going forward;
  no migration retroactively flips already-approved servers into debug mode
  (product MEDIUM, architect §6).

## Reject-after-re-review = rollback, not kill (product HIGH-3)
If a change-triggered re-review is **rejected**, the server rolls back to its
**last-known-good** config: restore the previous `upstream_url`/tool set,
`status='approved'`, tools `active`, `submission_status='active'`, out of debug
mode. A routine-update rejection must NOT terminally kill a previously-live
server (unlike a first-time `rejected`). Requires persisting last-good
(`upstream_url` + a marker) at `request-change` time so it can be restored.

## Discriminator (architect §3)
Add column **`server_registry.is_self_hosted BOOLEAN`** (migration V082),
backfilled `TRUE WHERE deployment_status IS NULL` and set at registration. C2/C3
branch on it explicitly rather than inferring — removes the fragile
`github_repo_url`/`deployment_status` heuristics and guarantees "platform-deployed
unchanged."

## UI (portal + React)
- **Submitter wizard**: URL entered/validated at submit; remove the
  provide-url-after-approval affordance from the happy path.
- **Owner/admin server card** (`portal.py`): a **first-class maintenance banner**
  on the card/detail when `debug_mode` is on — "In maintenance — verify (View
  logs / Retry verification), then Go live" — NOT buried in the `⋯` menu (the
  original complaint was a hidden control). Plus `⋯` actions: Edit
  endpoint/config → `request-change`; Update from git & rebuild → ops-agent
  rebuild → `request-change`; View logs (shipped); Retry verification; Go live.
- **Reviewer card**: real URL + code link + config + SBOM (C1).
- **`changes_requested` form** (`portal.py:2386`) gains an upstream-URL field so
  a reviewer's change-request can be satisfied by editing the URL (product LOW).

## Out of scope / explicitly excluded
- **D3 dual-control direct-registration path** (`server_registry.py:719`,
  `POST /api/v1/servers`): the legacy admin path is **excluded** from C1–C4; it
  keeps its own approve/URL logic. Documented, not silently skipped (product MED).
- **Platform-deployed** apply/build/deploy flow: unchanged.
- Debug-mode staleness TTL / "N days in maintenance" dashboard flag: deferred
  (product LOW) — noted as follow-up.

## Residual risks (accepted, named — appsec HIGH-3)
- **Same-URL-different-backend bait-and-switch**: an owner (or a post-approval
  compromise of the owner's box) can swap what listens behind the *unchanged*
  `upstream_url`; C3 never fires (URL string unchanged), and scan-freshness
  tracks code-scan age, not live endpoint drift. Inherent to self-hosting (the
  platform can't observe the owner's process); mitigated only by
  `SCAN_MAX_AGE_HOURS` re-scan cadence and per-call SSRF re-resolution. Accepted.
- **No cryptographic tie** between scanned commit and the owner's actually-running
  self-hosted process (architect §4) — inherent to self-hosted; the owner asserts
  the change. Accepted.

## Migrations / tests
- V082: `is_self_hosted` column + backfill.
- No enum changes (V046/V060/V068 already permit every value used).
- Required tests: every `debug_mode=TRUE` write sets both consistency columns
  (CHECK); `request-change` quarantines all tools + demotes status atomically;
  INV-005 still blocks quarantined-tool invocation for all roles; reject rolls
  back to last-good; platform-deployed flow untouched (is_self_hosted=false path).

## One decision still open for the owner
**IP-only endpoint change vs code change** (product HIGH-2). You chose "always
re-scan + re-review." All three critics + your self-hosted reality (Tailscale/DHCP
IP rotation) argue for a lighter path when only the *address* moves and the git
commit is unchanged: re-run discovery+verification (confirm the tool schema still
matches) but skip the full code re-scan and skip blocking reviewer approval,
auto-approving iff the discovered tool set is identical to the last-approved one.
Code/repo changes still get the full C3 treatment. Recommend adopting this split;
awaiting your call before implementation.
