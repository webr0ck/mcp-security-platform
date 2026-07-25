# Roadmap — remaining findings to close

**Created** 2026-07-25 · **Branch** `feat/trust-envelope-consumer` (14 commits, clean tree)
**Companion** [`2026-07-25-architecture-remediation.md`](2026-07-25-architecture-remediation.md) — what is already closed and why.

Everything already fixed is recorded in the companion doc. This file is ONLY what is still open,
so it can be worked from a clean session with no prior context.

## Verified state at the time of writing (fresh boot, `down -v` + rebuild)

| Gate | State |
|---|---|
| `lab-smoke` | ✅ 4/4 |
| `test-lab-functional` | ✅ 46 passed, 1 skipped |
| portal acceptance (`ui/e2e/portal-acceptance.spec.ts`) | ✅ 39/39, 0 flaky, reproducible |
| `make security-check` | ✅ ALL CHECKS PASSED |
| `check_network_isolation.py` | ✅ ALL PASS |
| `opa test` | ✅ 61/61 |
| proxy unit suite | ⚠️ **41 failed** (was 42; one fixed) — deterministic, see R5.3 |
| `make lab-acceptance` | ⚠️ **2 failed / 41 passed / 0 errors** (was 8F/32P/3E) |
| `make lint` | ❌ **1583 ruff + 728 mypy across 94 files**; `ruff format` fails 124/140 files |

**CI on `main` has been red on the lint gate for at least 5 pushes.** Pre-existing.

---

# R1 — Accessibility + portal UX  🔴 highest user-visible value

The live UI is the server-rendered portal (`proxy/app/routers/portal.py`). The React SPA was
deleted (never deployed). Current state, measured:

| Metric | Count |
|---|---|
| `aria-*` attributes | **0** across 119 `<button>` |
| `alert()` / `confirm()` | **73** |
| inline `<style>` / `<script>` blocks | **28** |
| inline `style="…"` attributes | 615 |
| inline `onclick=` handlers | 102 |

### R1.1 — ✅ DONE (847a76a) — portal.py 7048 → 5930; 3 blocks justifiably remain
~~Extract inline assets~~
Move the 28 inline blocks into `proxy/app/static/portal.css` + `portal.js`. `/static` is already
mounted (`main.py`). Nothing else changes behaviourally.
**Why first:** CSS/JS inside Python f-strings gets zero ruff/mypy/formatter coverage, cannot be
linted, and blocks any future CSP tightening. Also shrinks a 7,000-line file substantially.
**Done when:** portal acceptance still 39/39; no inline `<style>`/`<script>` remain.

### R1.2 — Replace 73 `alert()`/`confirm()`
One `toast(msg, kind)` + one `confirmDialog()` in `portal.js`; delete every `alert`/`confirm`.
They are blocking, unstyled, uncopyable, and invisible to Playwright unless explicitly handled.
**Done when:** `grep -c "alert(\|confirm(" portal.py` == 0; acceptance green.

### R1.3 — Accessibility pass (WCAG basics)
- `aria-live="polite"` on every htmx swap target (`#adm-content`, `#portal-body`) — screen
  readers currently announce **nothing** when a fragment loads
- `aria-current="page"` on the active nav item
- accessible names on icon-only buttons (they have `title=` only, which is not a name)
- visible focus management after a tab swap
**Done when:** an axe-core pass in the acceptance suite reports 0 criticals.

### R1.4 — Event delegation for the 102 inline `onclick=`
Requires R1.1. Removes the `script-src 'unsafe-inline'` requirement.

### R1.5 — Design tokens over 615 inline `style=`
Half-migrated already (323 `--adm-*` / `--cyan` references coexist with hardcoded hex and
arbitrary `font-size: 11/12/13px`). Lowest priority; cosmetic consistency.

---

# R2 — `lab-acceptance`  ⚠️ 2 failed / 41 passed / 0 errors (was 8F/32P/3E)

Six of the eight were fixed (26aaadf) — see the commit for each root cause. The headline
one: `conftest.py::db_query` was missing `-q`, so `INSERT … RETURNING` returned the value
WITH psql's command tag appended (`"<uuid>
INSERT 0 1"`), silently corrupting every
chained query and permanently poisoning the seed idempotency check.

Both remainders are lab CONFIG drift, not code:

| # | Test | Cause | Status |
|---|---|---|---|
| R2.4 | `test_entra_user_token_m365_delegated` | `.env.lab` points `ENTRA_TOKEN_URL` at REAL Azure AD, but `seed.py` still seeds a fake `mock-refresh-<identity>` token. Real AAD rejects it (`AADSTS9002313`); the broker reports it as "please enroll". | **DECIDED: provision a real delegated refresh token.** BLOCKED — needs a real token from the tenant owner. Until then this test stays red. |
| R2.5 | `test_external_oauth_dex_user_token_generic_path` | `PROXY_BASE_URL` is the host's Tailscale IP; `lab/dex/config.yaml` only registers 127.0.0.1/localhost `redirectURIs`, so Dex 400s "Unregistered redirect_uri". | **DECIDED: template the redirectURI from `PROXY_BASE_URL`** so it never drifts. In progress. |

---

# R3 — `make lint` / CI  🟠 belongs on a branch off `main`, NOT here

Do **not** mix into the security branch — it would bury the work in a 1600-line diff.

Order matters (`ruff format` reflows lines that `--fix` touches, so format goes LAST):
1. `ruff check app/ --fix` for the ~305 mechanical rules (I001, UP*, RET*) — own commit
2. `[tool.ruff.lint.per-file-ignores]` → `"app/routers/portal.py" = ["E501"]` — **559 of the
   1041 E501 hits are that one file** (HTML-in-f-strings). Do not raise the global limit.
3. Drop `B008` or per-file-ignore it for routers — 26/26 sampled are FastAPI's own
   `Depends(get_db)` idiom. Pure noise.
4. Fix genuine signal by hand, one commit per class: **B904** (67), **S110** (23 — log instead
   of silent `pass`; keep fail-open semantics), **S608** (21 — 3 sampled were false positives,
   but `anomaly.py:136`'s `where_clause` construction needs one real read before dismissing).
5. `ruff format app/` — own commit, 100% whitespace
6. **mypy: 728 errors / 94 files** — split per directory (`routers/`, `services/`,
   `credential_broker/`, `models/`) or per error class (`type-arg` first, mostly mechanical;
   `attr-defined` last, likely real bugs)

**CI unblock without a big-bang cleanup:** ruff 0.15.22 has no native baseline mode. Use a
changed-files-only gate — `git diff --name-only origin/main...HEAD -- 'proxy/app/**/*.py' | xargs -r ruff check` —
and keep the full `ruff check app/` as a non-blocking informational job so the debt stays visible.

---

# R4 — Security findings surfaced but NOT fixed  🔴 each needs a decision

### R4.1 — ✅ DONE (2e6a30c)
~~`str(exc)` leaked to API clients~~
`admin_credentials.py:108,154,215,259,314,383` put raw exception text into client-facing
`HTTPException` details — DB error text / internals reaching a caller. Same class as the
`/mcp` deny-path leak already closed via `services/deny_map.py`. Also `admin_git.py:86,117`.

### R4.2 — ✅ DONE (632fc37) — and it uncovered a latent privilege escalation
`agent` now has the three recovery meta-tools. NOTE: the claim that "the agent portal
renders a toggle that 403s" was **WRONG** — the portal calls the canonical
`/{principal}/…` route, which is role-blind for self. Only the `/me/` shorthand 403'd.

The real find while implementing: `_handle_enable_mcp_server` / `_handle_disable_mcp_server`
call `_upsert_profile_row` DIRECTLY, bypassing `_assert_may_write` and therefore the P1-2
service-account guard. A machine token holding a granted role could self-enable MCP servers
— automated credential compromise → scope expansion. Latent (no lab service account held a
granted role) but would have gone live with this change. Closed by
`_sa_blocked_for_profile_mutation`.

### R4.3 — **DECIDED: lab health-check only** (option c). In progress.
Auto-recovery (b) rejected as gameable; exempting platform-critical servers (a) rejected as
backwards — it would strip the circuit-breaker from the most-trusted server. Original text:
`invocation.py` auto-flips `debug_mode=true` after 3 consecutive connection failures and
**never auto-clears** (deliberate). It applied to the platform's own `self-service` provider,
which then denied every non-owner caller platform-wide until the wipe. Options: exempt
platform-critical infra servers, add auto-recovery on N consecutive successes, or add a lab
health-check asserting `self-service.debug_mode=false`.

### R4.4 — profile binding is client-supplied for bearer callers
`auth.py:363` accepts `?profile=<guid>` / `X-MCP-Profile` for external-OIDC callers;
`_resolve_active_profile_uuid` checks only exists+active, never that the caller is entitled to
that profile. Session/cookie callers get it from a signed JWT claim and cannot forge it.
Because resolution is deny-dominant, a profile can only ever NARROW — so this is "opt out of
extra narrowing", not privilege escalation. Still worth an explicit decision: should a named
profile be an **assignment** (enforced) rather than an **opt-in filter**?

### R4.5 — `GET /api/v1/tools` inventory disclosure
Audited and correctly left unchanged (registry-completeness contract, auditors must see tools
they cannot call). But RBAC admits `agent`/`user`, so any agent can enumerate the full tool
inventory. Intentional for a registry view; same disclosure shape as the portal catalog
fragment that was deleted. Deserves a deliberate decision rather than an inherited default.

### R4.6 — ✅ DONE (32674a7) — it was a staging PARITY gap; production was already guarded
~~`"change-me-in-production"` defaults~~
`config.py:400 VAULT_TOKEN` and `config.py:526 OAUTH_STATE_SECRET`. Confirm a production
startup guard hard-fails on these (there is precedent for fail-closed startup checks).

---

# R5 — Structural  🟡

### R5.1 — Split `invoke_tool` (`invocation.py`, ~1,130 lines, 14 params, 17 numbered steps)
Steps run 1, 1.1, 1.2, 1.5, 1.6, 2, 2.3, 2.5, 2.7, 3, 3a-pre, 3b, 3c-pre, 3c, 4, 6, 6a — the
numbering is the code admitting it has been inserted-into ~10 times. Clean seam: pre-dispatch
gates (1 → 2.7) split from dispatch+audit (3c → 6a). **Highest-risk item in this roadmap** —
it is the security choke point. Full unit + functional + security gate required.

### R5.2 — ✅ DONE (b123a78) — NOT an auth-ordering smell; the read is deliberately open. The test was vacuous.
~~Auth-ordering smell~~
`_list_named_profiles` runs its DB query **before** the admin check, so a non-admin triggers a
query before rejection. Surfaced by `test_list_profiles_forbidden_for_non_admin`, which fails at
HEAD.

### R5.3 — ~~Four intermittently-failing unit tests~~ RESOLVED: not a defect
**The suite is deterministic.** Investigated with 24 full runs on a settled tree —
6 sequential, 2 deliberately concurrent, and 16 with `PYTHONHASHSEED` forced to different
values (the standard suspect for same-code-different-result non-determinism). All 24
produced byte-identical sorted FAILED lists.

The apparent flakiness was **an artifact of running pytest against a tree being
concurrently edited.** It was reproduced live and diffed: the extra failures were exactly
the tests covering the files that were mid-write at that moment (`_TOOLS` /
`platform_meta_tool_roles` during the R4.2 edit, and the self-service handlers before
their fixture was updated for the new guard). Not random tests — whichever tests exercise
whatever file is being written.

A hypothesis was raised and **disproved rather than assumed**: nine test files do
`del sys.modules["app.services.invocation"]` + reimport inside `patch.dict(sys.modules, …)`,
which looks like it should leave a swapped module polluting later tests. Verified by
`id()`-comparing the module object before and after — `patch.dict.__exit__` restores the
whole `sys.modules` snapshot and silently undoes the `del`. Poor hygiene, not a live bug.

**Standing rule this produced — now part of the verification discipline:**
> A FAILED-list diff is only meaningful when `git status --short` is clean for the files
> the tests cover. Check it BEFORE trusting a pytest run as a regression signal. With
> several agents editing concurrently, a full-suite run samples a moving target.

Confirmed after settling: 3 consecutive runs, byte-identical, 41 failures — the old
42-baseline minus `test_list_profiles_forbidden_for_non_admin`, which was deliberately
fixed. Zero regressions.

### R5.4 — Dangling doc references
`docs/prd/` does not exist, yet `PRD-0010`, `PRD-0001`, `PRD-0012` are cited in code comments.
`RFC-0001 §8.1` / `RFC-0002` are Article-4 concepts, not repo docs — the citations should say so
rather than cite a section number of a non-existent spec.

---

## Suggested order

1. **R1.1** (extract assets) — unblocks R1.2/R1.3/R1.4
2. **R1.2 + R1.3** (toast + a11y) — biggest user-visible gain
3. **R4.1 + R4.2** (leak + agent recovery) — small, security-relevant
4. **R2.1 → R2.6** (acceptance, cheapest first)
5. **R3** (lint) — separate branch off `main`
6. **R4.3–R4.6, R5.2–R5.4** — decisions + small fixes
7. **R5.1** (`invoke_tool`) — last, alone, with the full gate

## Rules that apply to every item
- `podman restart mcp-proxy` after editing `proxy/app/**` (uvicorn `--reload` does not detect
  bind-mount changes on macOS podman-machine)
- editing `authz.rego` is a **no-op** until `make sign-policy-bundle`
- never hard-DELETE `tool_registry` (audit immutability guard) — soft-delete via `deleted_at`
- unit-suite baseline is **42 failures**; anything above that is a regression — diff the FAILED
  list, do not compare counts
- mutation-test every new regression test: reintroduce the bug and confirm the test fails. One
  test in this engagement passed against the very bug it was written for.
