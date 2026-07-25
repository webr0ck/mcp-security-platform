# Architecture & UX Remediation Plan — 2026-07-25

**Branch:** `feat/trust-envelope-consumer` (has uncommitted taint-floor/trust-envelope work — land or stash before Stage 1)
**Source:** full service/implementation/UX review + live lab verification, 2026-07-25
**Lab baseline at plan time:** smoke 4/4 · functional **39/7/1** (was 46/1/0) · portal acceptance 34/1 flaky/1 skip

## Status board

| Stage | Title | State | Verified by |
|---|---|---|---|
| 0 | Architect decision on the profile fork | ✅ done | 3-critic REJECTED the original diagnosis — verdict below |
| 1 | **F6/F7/F1 — fail-open, escalation, key mismatch** | ✅ **done** | live repro flips to denied; 46/1/0; 3 mutations caught |
| 2 | F2/F3/F4 — self-lockout guard, deny-message remediation | ✅ **done** | 400 on self-lockout; remediation live; 3 mutations caught |
| 3 | F8 — audit all discovery surfaces (fan-out) | ✅ **done** | 2 no-change verdicts, 3 real fixes; 39/39 acceptance |
| 4 | F5 — test state hygiene (F3 folded into Stage 2) | ✅ **done** | acceptance 36/0/0 twice; functional 46/1 twice |
| 5 | A5/A7 — unify deny mapping, health honesty | ⏳ pending | unit + functional |
| 6 | A1/A3/A2 — delete dead UI, extract portal assets | ⏳ pending | portal acceptance green |
| 7 | B1/B2 — toast/confirm, accessibility | ⏳ pending | portal acceptance + a11y pass |
| 8 | A4 — split `invoke_tool` at the dispatch seam | ⏳ pending | full unit + functional + security |
| 4.5 | **Unblock the security gate** (H3 + F-001) | ✅ **done** | `make security-check`: ALL CHECKS PASSED |
| 9 | Full acceptance + security gate | ⏳ pending | see Exit criteria |

Legend: ⏳ pending · 🔄 in progress · ✅ done · ⚠️ done with caveats · ⛔ blocked

> **⚠️ Stage 0 invalidated the original F1 diagnosis.** The findings section below has been
> corrected in place. Two critical authorization defects (F6, F7) were discovered during the
> critic run and are now the top of the plan. Do not work from the pre-Stage-0 version of this file.

---

## Findings being fixed

Ranked by severity. F-series = live defects found against the running lab. A/B-series = structural findings from code review.

### F6 — named-profile restrictions are hidden-but-callable (**fail-open authorization bypass**) 🔴🔴 CRITICAL
The named-profile writer and the named-profile invoke-reader use **different tables**:

| Role | Code | Table |
|---|---|---|
| WRITER (only one) | `profiles.py:957 _upsert_profile_mcp_binding` | `profile_mcp_bindings` |
| DISCOVERY reader | `mcp_server.py:522 _lookup_profile_mcp_binding` | `profile_mcp_bindings` ✅ |
| INVOKE reader | `invocation.py:139` | `mcp_profiles WHERE profile_uuid=` ❌ |
| INVOKE "configured?" probe | `invocation.py:~258 _named_profile_has_any_binding` | `COUNT(*) FROM mcp_profiles WHERE profile_uuid=` ❌ |

`_upsert_profile_row` never populates `mcp_profiles.profile_uuid`, so the invoke-side count is
**always 0** → "unconfigured profile" → default-**allow**. A tool an admin disables in a named profile
is hidden from `tools/list` and **still callable**.

**Live repro (lab, today)** — profile `readonly-demo` (`6f39481d-…`) disables two privileged reviewer tools:
```
tools/list  no profile   → 46 tools
tools/list  X-MCP-Profile → 44 tools   (approve_submission, reject_submission HIDDEN ✅)
tools/call approve_submission + X-MCP-Profile → PASSED THE PROFILE GATE
                                                (reached upstream arg validation, not denied)
tools/call reject_submission  + X-MCP-Profile → PASSED THE PROFILE GATE
```
Fail-open on a platform whose prime invariant is fail-closed. Opposite polarity to the originally
reported bug, and strictly more severe: the original is a UX failure, this one grants access.

### F7 — any authenticated caller can escape their own restrictions with one header 🔴🔴 CRITICAL
`auth.py:363` lets an external-OIDC (Bearer) caller select a profile via `?profile=<guid>` or
`X-MCP-Profile: <guid>`. `_resolve_active_profile_uuid` (`auth.py:435`) checks only that the profile
**exists and is active** — it never checks the caller is entitled to it. Because the invoke gate is an
`if profile_uuid: … else: …` (`invocation.py:134`), binding *any* active profile switches the caller
off their legacy per-identity rules entirely — and onto the F6 path, which allows everything.

**Live repro (lab, today)** — alice has 37 legacy `enabled=false` rows:
```
tools/call ping                    → DENIED  mcp_disabled_for_profile
tools/call ping + X-MCP-Profile    → SUCCEEDS, real upstream output, caller_sub=alice@corp
```
The only barrier is the GUID being "unguessable" (the code comment says so explicitly) — security by
obscurity, and the portal's profile fragment lists profiles to users. Remotely triggerable by any
authenticated user, no admin setup.

### F1 — `tools/list` legacy profile filter is keyed on the wrong identity 🔴 (**diagnosis corrected**)
~~No legacy filter exists at all.~~ **Wrong.** A legacy filter *does* exist at `mcp_server.py:665-673`.
The real defect is a **key-namespace mismatch**:

| Path | Key used | Example value |
|---|---|---|
| WRITER `profiles.py:192` | `client_id` | `alice@corp` |
| INVOKE `invocation.py:151` | `client_id` | `alice@corp` |
| DISCOVERY `mcp_server.py:667` | **`principal_id`** | `human:keycloak:alice@corp` |

`_build_principal_id` (`auth.py:125`) builds `human:{issuer}:{sub}`. Discovery therefore never matches a
row → every tool is shown. Fix is one argument, not a new filter.

Live repro: alice sees 40 tools, 37 deny on call. README lists discovery==invoke as *Enforced today*.

### F8 — discovery is parallel-implemented on 4 surfaces, 3 of which have no profile gate 🟠
Verified: `GET /api/v1/tools` (`tools.py:351`) has no profile filter · `catalog.py:38/59` gates on
entitlement only · `portal.py fragment_catalog:~1558` has no profile predicate · only `/mcp tools/list`
has one (and it is mis-keyed, per F1). Any per-surface fix reproduces the defect class on the next
surface. Additionally `_visible_tools(roles)` (`mcp_server.py:292`) serves platform meta-tools through a
**role-only** path that no profile filter touches — so 3 of the tools in the F1 repro would remain
mis-listed even after F1 is fixed.

### F2 — self-service `disable_mcp` can disable its own recovery tools 🔴
`profiles.py:668` → `_upsert_profile_row` has no protected set. 37 rows written by `alice@corp` in 1.4s
disabled `enable_mcp`, `enable_function` **and** `get_profile`. Alice holds `admin`; there is no role
bypass (correct, deliberate) so the lockout is total via MCP.

### F3 — recovery tools are name-traps 🟠
`get_profile` denied / `get_my_profile` works · `enable_mcp` denied / `enable_mcp_server` works.
Survival is accidental (no `mcp_profiles` row → default-allow), not designed.

### F4 — deny messages are dead ends 🟠
`{"code":-32003,"message":"Access denied by policy","data":{"reasons":["mcp_disabled_for_profile"]}}` —
no remediation, no cause, no request_id. The adjacent `CredentialEnrollmentRequiredError` branch is the
in-repo gold standard; this path never got the same treatment.

### F5 — both test suites depend on and mutate ambient lab state 🟡
Functional asserts alice can invoke `ping`/`search-kb` without seeding it — a `disable_mcp` from six days
prior poisoned every run since. Portal acceptance flaked on shared `serverId` module state (tests 22–26).
Also: the functional assertion message says *"gate-chain failure leaked through HTTP 200"* when the gate
worked correctly — actively misleading diagnostics.

### A5 — deny→client mapping copy-pasted 3× and already drifted 🟠
`tools.py:1640-1791` (HTTP) · `mcp_server.py:849-918` (JSON-RPC) · `mcp_server.py:1313-1355` (text).
`ToolDisabled/Quarantined/Deprecated` are mapped only in `tools.py`; the other two fall through to
`_err(-32603, f"Tool invocation failed: {exc}")` — loses deny semantics **and** leaks the exception
string three branches below a "no internals leaked" comment. Latent today (status pre-filtered at
`mcp_server.py:1172`), guaranteed to bite on the next deny reason added.

### A7 — `lifespan` degrades 8 subsystems to log warnings 🟠
`main.py:96-216`. Registry, OPA sync, rescan, scan evaluator, build evaluator, trust labeler, trust
observer, DB health all `except: logger.warning`. "OPA data sync failed — grants will not be synced" as a
WARNING on a fail-closed platform is the wrong severity, and `/health` doesn't report any of it.

### A1/A3 — dead frontends 🟠
`ui/src` (3k LOC React SPA) is in no compose file and no nginx location; commit `e0e1bd0` calls portal
"the portal UI actually in use". `proxy/app/static/design.html` (96 KB) is referenced by nothing and
served unauthenticated.

### A2/B3/B4 — `portal.py` is 7,108 lines with untooled inline assets 🟠
28 inline `<style>`/`<script>` blocks, 615 inline `style=`, 102 inline `onclick=`, all inside Python
f-strings. Zero ruff/mypy/formatter coverage. Blocks any CSP tightening.

### B1/B2 — portal UX floor 🟠
73 `alert()`/`confirm()` calls. **Zero** `aria-*` attributes across 119 `<button>`s; no `aria-live` on
htmx swap targets, so screen readers announce nothing on fragment load.

### A4 — `invoke_tool()` is ~1,130 lines / 14 params / 17 numbered steps 🟡
`invocation.py:377-1511`. Correct — gate order verified — but the `1.1/1.2/1.5/1.6/3a-pre/3c-pre`
numbering is the code admitting it's been inserted-into ~10 times.

### D1 — dangling doc references 🟡
`docs/prd/PRD-0010-taint-floor-mode-delegation.md`, PRD-0001, PRD-0012, RFC-0001 §8.1, RFC-0002 are cited
in `invocation.py`/`config.py`/test names. `docs/prd/` does not exist. `docs/ROADMAP.md` does not exist.

---

## Stage 0 — Architect decision (blocking Stage 1)

**The fork:** two profile systems coexist — legacy per-identity `mcp_profiles(profile_id, mcp_name)` and
named `profiles`/`profile_mcp_bindings(profile_uuid, mcp_name)`. F1 exists *because* they have different
enforcement coverage. Options:

- **(a) Patch** — add a legacy-profile filter to `tools/list` so discovery matches invoke. Smallest diff,
  keeps both systems and the ongoing drift risk.
- **(b) Converge** — make named profiles the only path, migrate legacy rows, delete the legacy branch.
  Bigger, removes the root cause, touches auth/OPA input shape.
- **(c) Unify at the source** — single `resolve_effective_profile()` used by both discovery and invoke,
  regardless of which table backs it. Medium; kills the drift without a data migration.

Decision requires a critic run (Claude + Codex + Gemini). **Verdict recorded here before Stage 1 starts.**

> **VERDICT: REJECTED — all critics chose (d), none chose (a)/(b)/(c).**
> The fork as posed was a solution space for a misdiagnosed bug. Gemini errored (HTTP 400);
> the security lens was substituted with an in-session `appsec-reviewer` subagent.

| Lens | Critic | Verdict | Choice | Top issue |
|---|---|---|---|---|
| Logic / Idea | Claude (repo access) | rejected | (d) | Diagnosis wrong: it's a key mismatch, and the filter option (a) proposes already exists |
| Implementation | Codex / OpenAI | rejected (feasibility 2/5) | (d) | Literal discovery==invoke is impossible; option (a) leaves 3 other surfaces |
| Security | appsec-reviewer (Gemini substitute) | see Stage 1 notes | — | ran on the corrected facts incl. F6/F7 |

**Adopted design — (d), sequenced.** The two critics' (d)s differ in altitude and compose in order:

1. **Stop the bleeding (Claude's (d)):** fix the key (`principal_id` → `client_id` at
   `mcp_server.py:667`); make the named-profile invoke path read `profile_mcp_bindings`, the table the
   only writer writes; require caller entitlement in `_resolve_active_profile_uuid`.
2. **Then converge (Codex's (d)):** one mandatory `list_authorized_tools()` consumed by all four
   discovery surfaces, bulk-loading both profile systems and issuing **one batched OPA evaluation**
   (a comprehension over `input.candidates`) rather than N round trips. All direct discovery queries
   deleted or made private.
3. **Redefine the invariant honestly.** Codex is right that literal discovery==invoke is
   *technically impossible*: invoke sees call arguments, anomaly score, taint state and
   `recent_calls` that do not exist at list time. Restate it as **conservative preflight** —
   discovery must never show what static policy would deny; dynamic denial at invoke remains
   possible and is expected. README + `docs/enforced-vs-roadmap.md` must say this.

**Open questions this raised, to settle before Stage 3** (both critics flagged; neither is answered
in the code today):
- **Precedence:** when a legacy row and a named binding disagree, which wins? Must be deny-dominant
  and written down as a truth table before either is migrated.
- **Partial-failure semantics:** if bulk resolution fails for some candidates, a partially filtered
  list violates fail-closed, an empty list conceals an outage, a 503 is safest — but must be
  identical across all four surfaces.
- **Cache coherence:** three Redis tiers (`_lookup_profile_row`, `_lookup_profile_mcp_binding`,
  `_named_profile_has_any_binding`) with independent keys and a `__has_bindings__` sentinel;
  invalidation on write must cover all three or a stale tier re-opens F6.

---

## Exit criteria (Stage 7)

Non-negotiable, all on **one** lab boot:

1. `make -f Makefile.lab lab-smoke` — 4/4
2. `make test-lab-functional` — **46+/0 fail**, zero unexplained skips
3. `cd ui && npx playwright test --config playwright.portal.config.ts` — 0 fail, **0 flaky**
4. `make -f Makefile.lab lab-acceptance` — full AT0–AT3 green
5. `make security-check` — secret scan + rego lint + OPA deny-default + F-001 isolation
6. `make lint` — ruff + ruff format + mypy clean on `app/`
7. `python scripts/check_network_isolation.py` — pass
8. Suites reproducible: run twice back-to-back, identical results (proves F5 fixed)
9. README Enforced-vs-Roadmap table true for every control touched

## Rules for every stage

- One logical change per commit, conventional commits, tests in the same commit.
- **No fail-open introduced.** Any new branch defaults to deny.
- `podman restart mcp-proxy` after editing `proxy/app/**` — uvicorn `--reload` does not
  detect bind-mount changes on macOS podman-machine.
- Never hard-DELETE `tool_registry`; soft-delete via `deleted_at`.
- Update this file's status board at the end of every stage, with the actual verification output.

---

## Stage 1 — CLOSED 2026-07-25

**Design:** profile resolution became a **deny-dominant merge** owning key, table AND precedence —
the correctly-scoped version of option (c) the critics demanded (a resolver that returns only a
boolean is, in the logic critic's words, "a comfortable fiction"; one that owns which identity key
and which table a decision is read from is a real fix).

### Changes
| File | Change |
|---|---|
| `services/invocation.py` | new `merge_profile_deny_dominant()` (pure) · new `_lookup_profile_source()` (one fail-closed 3-tier lookup, parameterized by table/key) · `_lookup_profile_with_cache()` now merges BOTH sources instead of if/else · named source reads `profile_mcp_bindings` · `_named_profile_has_any_binding` counts `profile_mcp_bindings` · cache keys namespaced `v2` |
| `routers/mcp_server.py` | discovery routes through new `_resolve_profile()` → the same resolver invoke uses · **deleted** `_lookup_profile_row` + `_lookup_profile_mcp_binding` (170 lines of drifted per-surface duplication) |
| `routers/profiles.py` | invalidators write `v2` keys · named invalidator now also drops the `__has_bindings__` sentinel (previously invalidated by *no writer* — a fail-open window on the very mechanism that enforces named profiles) |

### Verification (one lab boot)
| Gate | Result |
|---|---|
| F6 live repro | `list_policies`: listed+callable without profile · **hidden AND denied** with profile ✅ |
| F7 live repro | `ping` + `X-MCP-Profile` → **denied** (was: succeeded with real upstream output) ✅ |
| F1 live | discovery 46 → 12 tools for a restricted caller (key mismatch closed) ✅ |
| `lab-smoke` | 4/4 ✅ |
| `test-lab-functional` | **46 passed, 1 skipped** — restored to baseline ✅ |
| portal acceptance | 34 passed, 1 pre-existing flaky (AC-06), 1 skipped ✅ |
| unit suite | 1591 passed / 42 failed — **42 == HEAD baseline exactly, zero regressions**, +22 new tests ✅ |
| F-001 isolation | ALL PASS ✅ |

### Mutation testing (non-vacuity proof)
The new regression tests were validated by reintroducing each bug:
1. named lookup → `mcp_profiles` (F6) → **caught**
2. merge → old `named if named is not None else legacy` (F7) → **initially NOT caught**; the test
   returned `None` from the named side, which fell through to legacy and looked correct. Fixed to
   return a *permissive row*, then **caught**. Worth remembering: a regression test written from the
   fix rather than from the bug can pass against the bug.
3. disjoint-allowlist deny removed → **caught**

### Known-unfixed (pre-existing, verified identical at HEAD — NOT introduced here)
- `make security-check` — 2 checks fail (H3 semgrep: `lab/mcp-servers/entra-directory/server.py`
  `get_user(user_id)` takes caller identity as a tool param, CWE-639).
- `make lint` — ruff reports **1601** errors on `app/`.
- unit suite — 42 pre-existing failures.
- `test_list_profiles_forbidden_for_non_admin` — fails at HEAD; the DB query in
  `_list_named_profiles` runs **before** the admin check, so a non-admin triggers a query before
  rejection. Auth-ordering smell worth its own ticket.
- `scripts/check_network_isolation.py` fails unless `.env.lab` is sourced first — it reports a
  confusing "compose config resolution failed" instead of "missing env". Usability wart.

### Not committed
The working tree still carries the user's **pre-existing uncommitted** taint-floor / trust-envelope
work (`config.py`, `taint_floor.py`, `tools.py`, `tests/rfc0002/`, `test_taint_floor.py`,
`test_invocation_taint_notices.py`), which `CHANGES-article4-truth.md` explicitly reserves for the
user to review and commit. **`services/invocation.py` contains BOTH that work and the Stage 1 fix**,
so there is no clean split. Left uncommitted pending the user's call.

---

## Stage 2 — CLOSED 2026-07-25

### F2 — self-lockout guard
`would_self_lockout(principal, mcp_name, enabled, changed_by)` — a pure predicate — plus a
`400 PROFILE_SELF_LOCKOUT_BLOCKED` raised from **inside `_upsert_profile_row`**. The guard lives in
the writer, not the endpoints, because **11 call sites** across `profiles.py` and `mcp_server.py`
route through it; guarding each caller would leave the next one unprotected.

Protected set `_RECOVERY_MCPS = {get_profile, enable_mcp, enable_function}` — deliberately covers
both halves of recovery: **inspect** (you must be able to see what you disabled) and **undo** (server
and function level). A set that can undo but not inspect only lets you fix what you could already name.

**Scoped to self-directed writes (`changed_by == principal`).** An admin restricting *another*
principal's self-service stays allowed — that is legitimate policy and not a lockout, because the
admin can still reverse it. Role is irrelevant to the predicate: the lab case was an `admin`
locking *herself* out, and there is deliberately no role bypass on the profile gate.

### F3 — name-trap closed structurally
Recovery previously survived only by accident: `get_my_profile` / `enable_mcp_server` are platform
meta-tools served by the role-only `_visible_tools` path, so they bypass the profile gate, while the
near-identically-named `get_profile` / `enable_mcp` are registry tools that do not. With F2 the
recovery tools can no longer be disabled at all, so the accident is now a guarantee. No rename
needed; the confusing pairs remain but are no longer load-bearing.

### F4 — deny messages carry remediation
`deny_remediation(reasons)` in `services/policy.py`, one table consumed by all three deny-mapping
sites. Remediation goes **in the message, not only in `data`** — MCP clients render `message` and
frequently ignore `data`, which is why the credential-enrollment path already does this. Handles
decorated reasons (`taint_floor:required_integrity=3`) by falling back to the prefix.

Returns **None** for unrecognised reasons rather than generic filler: "contact your administrator"
on every deny trains both agents and humans to ignore the field, which costs more than an absent one.

Also fixed: the REST deny carried `"audit_id": "see X-Request-ID"` — a literal string, not an id.
It is now the real `request_id`, so a deny is greppable in Loki and pasteable into a ticket.

Live: `disable enable_mcp` → 400 · `disable get_profile` → 400 · `disable echo-basic` → 200 ·
invoke denied → message carries the how-to-undo text + `request_id`.

### Verification
smoke 4/4 · functional **46 passed, 1 skipped** · unit **1606 passed / 42 failed == HEAD baseline
exactly** (+15 tests) · portal acceptance 34 passed, 1 pre-existing flaky.

Mutations caught: (a) guard ignoring `changed_by` (would block legitimate admin action),
(b) `get_profile` dropped from the recovery set, (c) remediation returning generic filler.

---

## Stage 4 — CLOSED 2026-07-25 (F5, test-state hygiene)

Ran ahead of Stage 3 because it is independent of the discovery-surface analysis.

### Two vacuous tests found — the acceptance suite was reporting green over a hole

**AC-06 `POST /submit` had never passed.** It returns `422 INCOMPLETE_SUBMISSION —
requested_upstream_url` because drafts default to `is_self_hosted=true` and the test never set
a URL. That is CORRECT product behaviour; the test simply never satisfied it. On retry, the
module-level `let serverId = ''` re-initialised, so `test.skip(!serverId)` skipped the retry —
and Playwright reports fail-then-skip as **"flaky"**, not "failed". The suite showed
`34 passed, 1 flaky` for however long this has been true.

Fixed by supplying `requested_upstream_url` in the PATCH step, and by marking the block
`test.describe.serial` so a retry re-runs the chain from the start instead of skipping into
a false pass.

**AC-02 `all admin nav tabs are present` only passed because AC-06 was broken.** The Servers
nav button renders an awaiting-review count badge *inside itself*
(`portal.py` → `adm-nav-badge`), so its accessible name becomes `"Servers1"` whenever a
submission is pending. The test asserted `exact: true`, which held only while the pending
count was always 0 — i.e. only while AC-06's `/submit` kept failing. Fixing the first test
broke the second. Now matched with an anchored regex `^<group>\s*\d*$`.

That coupling is F5's thesis in miniature: the suites shared mutable lab state, so one test's
brokenness was another test's precondition.

### Functional suite now establishes its own preconditions
`_alice_profile_preconditions` (session, autouse) self-service-enables the tools the suite
invokes as alice. The 2026-07-19 `disable_mcp` sweep left 37 rows that made 7 unrelated tests
fail for six days with a policy deny that read like a broken gate chain. Uses alice's own
token — no admin rights, no direct DB write — and only ever adds access the suite already
assumes, so it cannot mask a genuine deny bug in tools it does not touch.

**Proven by re-poisoning:** set `ping`/`search-kb` to `enabled=false` directly in the DB,
flushed the profile cache, ran the suite → 46 passed, and the rows came back as
`ping=true (by alice@corp)`. The fixture repaired state; the suite did not merely get lucky.

### Diagnostics
`_assert_invoke_ok` said *"gate-chain failure leaked through HTTP 200"* for every failure mode,
including a correct policy deny — which reads as a security breach and sends you hunting a bug
that is not there (it cost one diagnostic pass during this engagement). Policy denials are now
reported distinctly as a PRECONDITION FAILURE, with the SQL to check the likely cause.

`POST /submit` asserted a bare `expect(resp.ok())`, yielding "expected true, received false"
with no server response — which is why this sat unexplained. It now prints status + body.

### Verification (reproducibility is the point)
| Suite | Before | After |
|---|---|---|
| portal acceptance | 34 passed, 1 flaky, 1 skipped | **36 passed, 0 flaky, 0 skipped** — twice back to back |
| functional | 46 passed, 1 skipped | **46 passed, 1 skipped** — twice back to back |

---

## Stage 3 — CLOSED 2026-07-25 (discovery surfaces, fan-out)

Three agents analysed one surface each in parallel and proposed rather than edited, because the
surfaces have **different audiences** and a blanket filter would have created new bugs. Two returned
**no-change** verdicts, which were the right answers. Every claim was re-verified before acting.

### NO CHANGE — `catalog.py`
Lists **servers**, not tools (`list_entitled_servers`, entitlement-gated). A per-tool profile gate is
not meaningful at server granularity: a user with 5 of 10 tools disabled should still see the server.
No live consumer outside unit tests. Adding a join here would buy nothing and invent a
hide-if-all-disabled policy decision nobody asked for.

### NO CHANGE (profile gate) — platform meta-tools
**Verified:** the inline meta-tool `opa_input` (`mcp_server.py:1533-1543`) never sets a `profile` key,
so `mcp_disabled_for_profile` structurally cannot fire for them. Applying a profile filter would break
the recovery path — `get_my_profile` / `enable_mcp_server` are how a user escapes a lockout, and Stage 2
made that guarantee load-bearing. Filtering them would have made the self-lockout guard moot.

### FIXED — meta-tool role map had drifted (found by the fan-out, not in the original plan)
`platform_meta_tool_roles` in `authz.rego` listed only 4 of 9 meta-tools. `is_platform_meta_tool`
requires membership, so the other five fell through to the generic `allow`, whose
`client_has_invoke_permission` recognises agent/user/admin/platform_admin/analyst/platform_internal/
server_owner/manager — **never `viewer` or `editor`**, which `_TOOLS` explicitly grants. A viewer or
editor SAW `get_my_profile` / `enable_mcp_server` in `tools/list` and was denied on `tools/call`:
listed-but-denied again, on the recovery path.

Fixed by mirroring `_TOOLS` exactly (`invoke_tool` stays intentionally absent — it runs the full OPA
pipeline against its *target*). Role sets were read from source, not inferred: a first pass at this
had `viewer` on `enable_mcp_server` (over-grant) and a too-narrow `list_available_mcps`.

Guarded by `test_meta_tool_role_map_parity.py` — the rego comment has always said this map "MUST
mirror `_roles`", and a comment is not an enforcement mechanism. Plus 8 policy tests asserting the
decisions themselves. Bundle re-signed (`make sign-policy-bundle`) — editing `authz.rego` is a no-op
otherwise. `opa test`: 59/59.

### FIXED — deleted `GET /portal/fragments/catalog`
Orphaned route that dumped every non-deleted `tool_registry` row with no entitlement, grant or profile
filtering, gated only by `_require_portal_access` (agent/auditor/admin). Any authenticated portal user
could enumerate the full tool inventory. Already dead — the Catalog tab renders inline from
`_build_portal_access`, and `ssShowTab('catalog')` is a client-side toggle, not an `hx-get`. Deleted
rather than filtered: a second independently-filtered listing surface is what caused the drift.

### FIXED — portal access pill was decorative
`_build_portal_access` read `mcp_profiles` directly (a fourth un-synced implementation) and, worse,
keyed the lookup on the **server** name while the table is **tool**-keyed — the key invoke uses. It
matched nothing, fell back to the `True` default, and rendered "Access enabled" **regardless of actual
profile state**. Found only because the new e2e test would not go red.

Now resolves per tool through the shared resolver with `profile_uuid` threaded, folded up per card
(any tool callable = card enabled). The read was also inside a broad `except Exception`, so a DB error
silently produced "everything enabled" — a fail-open in the UI. It now sits outside that catch and
`ProfileLookupError` surfaces as a 503.

### New coverage (there was none — this is why the drift survived)
`AC-09` asserts the pill tracks the profile decision (one tool disabled must NOT flip the card; all
disabled must), that the self-lockout guard returns 400, and that the deleted fragment 404s.

### Verification
acceptance **39 passed, 0 flaky, 0 skipped — twice** (was 34/1 flaky/1 skipped at session start) ·
functional 46/1 · unit 1618 passed / 42 failed == HEAD baseline · `opa test` 59/59 · smoke 4/4.

### NO CHANGE — `GET /api/v1/tools` (delivered late; verdict accepted)
A **registry/inventory** endpoint, not a discovery-then-invoke surface. Verified directly:

- RBAC is NOT admin-only — `tools.py:371` admits `{admin, agent, auditor, readonly}` and
  `middleware/rbac.py:75` is wider still. That is what made it *look* caller-facing.
- The deciding evidence is `lab/tests/functional_test.py::TestToolRegistry::test_all_new_tools_registered`
  (L579-585): it asserts the FULL registered set is present in a regular user's response. That is a
  registry-completeness contract, not a can-I-call-this contract.
- The portal's admin Tools tab never calls this endpoint — it queries `tool_registry` by raw SQL — and
  `ui/**` has zero references. Every real consumer (functional, acceptance, red-team, smoke scripts)
  uses it for **tool_id resolution**.
- Auditors specifically MUST see tools they cannot personally call; filtering would defeat
  `test_list_tools_auditor_allowed` in intent, not just in status.

The `callable_by_you` annotation idea was withdrawn: `grep` finds zero consumers of such a field, so it
is speculative work. Follow-up worth a ticket (NOT fixed here): the `agent`/`user` RBAC grant means any
agent can enumerate the full tool inventory. Intentional for a registry view, but it is the same
disclosure shape as the portal catalog fragment that was deleted — worth a deliberate decision rather
than an inherited default.

---

## Stage 4.5 — CLOSED 2026-07-25: `make security-check` now passes

Both failures were pre-existing at HEAD. Fixed properly rather than suppressed.

### H3 — identity-as-tool-param in the entra lab sample (CWE-639)
`get_user(user_id: str)` tripped `policies/semgrep.yml::mcp-identity-as-tool-param`.

The rule fires on an ambiguous NAME, and it is right to: `user_id` reads as both "who I am"
and "who I am asking about". Here it was the latter — a Graph lookup key — so this was not an
identity-forgery hole. But the honest fix is to stop using an identity-shaped name for a query
key, not to suppress the rule. Renamed to `target_user_id` with the reasoning written down.

The adjacent REAL gap the rule does not catch: this server holds an app-only Graph token with
tenant-wide read scopes, so every caller reads the whole directory at the same privilege, and
the server logged **nothing** about who asked. Added `_caller()`, which records
`X-Principal-Id` (collision-proof, CR-10) and the display sub on every directory read.

Deliberately NOT added: per-caller authorization inside the server. "May this caller use this
tool" is the proxy's decision (entitlement → profile → OPA); a second implementation in the
server is exactly the drift pattern that produced F1/F6. `X-User-Sub` is recorded for humans
and never branched on — invocation.py states it is never an authorization key.

### F-001 — network isolation gate had a stale expectation
`proxy<->self-service reachable via proxy-self-service-net only (got ['mcp-self-service-net'])`.
`docker-compose.yml` uses the `proxy-<svc>-net` convention; `podman-compose.lab.yml` names ALL
of its per-server pairwise nets `mcp-<svc>-net` (mcp-echo-net, mcp-notes-net, …). Both are
internally consistent and the control is identical — one dedicated pairwise net, nothing else.
Only the label differed, so the GATE was wrong, not either compose file.

`PAIRWISE` values may now be a set of accepted names. **The exactly-one-shared-network
assertion is unchanged** — widening the name set must not weaken the control, and a negative
control confirms a backend sharing two accepted nets still FAILS. Renaming a live lab network
would have changed no security property.

**Result: `make security-check` → ALL CHECKS PASSED** (was 2 failing at HEAD).
