# MCP Security Platform — Dev & Test Process (Agent Playbook)

**Date:** 2026-05-16 · **Audience:** any agent or human making a change to this repo.

This is mandatory and self-contained. It exists because the platform shipped with hand-rolled crypto, fail-open controls, doc/reality drift, and CI that skips its own invariant tests. The process below is designed so those failure modes cannot recur silently.

Core rule: **the test gate must fail closed, exactly like the system it protects.** A skipped test, a missing tool, or an unverifiable doc claim is a *failure*, not a warning.

---

## 1. Change Workflow (every change, no exceptions)

```
1. PLAN      — write/extend a failing test FIRST (TDD). State which INV/finding it touches.
2. CLASSIFY  — is this a SECURITY-CRITICAL change? (see §2). If yes → appsec gate is mandatory.
3. IMPLEMENT — minimal change; no scope creep; no new fail-open path.
4. PROVE     — run the full local gate (§3). All green, nothing skipped.
5. DOC SYNC  — update every doc the change touches; every new claim cites file:line (§5).
6. REVIEW    — security-critical → appsec-reviewer subagent sign-off before merge (§2).
7. MERGE     — only if CI gate (§4) is green AND docs verified AND appsec signed off.
```

Never mark work complete with: a failing/skipped test, an unverified doc claim, an unaddressed appsec finding, or a new fail-open branch without an alert.

---

## 2. Security-critical changes — extra gate

A change is **security-critical** if it touches any of: `proxy/app/credential_broker/**`, `proxy/app/routers/oauth.py`, `proxy/app/middleware/**`, `proxy/app/services/{policy,invocation,auditor}.py`, `policies/rego/**`, `gateway/**`, `infra/db/migrations/**`, `docker-compose*.yml` networks, `observability/mcp-audit-logger/**`, anything matching `SECURITY_NONNEGATABLES.md`, or any crypto/KDF/nonce/key code.

For these:
- Dispatch the **`appsec-reviewer`** subagent with the diff and the relevant INV/finding IDs. It must return an explicit verdict (UNBLOCKED / BLOCKED with findings).
- BLOCKED findings of HIGH/CRITICAL must be fixed before merge — no "follow-up ticket" deferral for the broker or auth path.
- Crypto changes: no bespoke primitives. Use `cryptography` HKDF/AESGCM. Hand-rolled KDF/state/nonce derivation is auto-reject.
- The 12 INV invariants in `SECURITY_NONNEGATABLES.md` may never be weakened. Adding a subsystem (e.g. the broker) requires extending INV scope, not leaving it stale.

---

## 3. Local gate — run before every commit

```
make test-unit            # all @pytest.mark.unit — must pass, zero skips unexplained
make test-integration     # requires docker compose up; postgres+redis+opa
make security-check       # see §3.1 — must be HARD (no skip-on-missing-tool)
pytest -q --no-header -p no:randomly --strict-markers   # no unmarked test silently skipped
opa check --strict policies/rego/                        # rego must compile strict
```

### 3.1 `make security-check` must enforce (fix if it doesn't — current gaps in REVIEW §2)

| Check | Asserts | INV |
|---|---|---|
| redaction pytest | all 10 categories, +/- cases | INV-002 |
| `grep 'default allow := false' authz.rego` | exact line present | INV-003 |
| trufflehog (HARD fail if absent) | no secrets staged/in tree | INV-008 |
| compose topology assertion | proxy inbound only on gateway-net | F-001 |
| OPA bundle-signing config present (staging/prod) | signing keyid + scope | INV-012/F-002 |
| migration role-grant lint | every table written by app has explicit GRANT + REVOKE UPDATE/DELETE where required; `credential_store`,`role_assignments` covered | INV-011 |
| doc-consistency lint | see §5 | — |

If a tool (trufflehog/opa) is missing, the gate **fails** (currently it warns — that is a defect to fix in Phase 2.5).

---

## 4. CI gate (blocking, on every PR)

Mirror §3 in CI. Required jobs: unit, integration (must actually run — fix the missing `tests/fixtures/integration_seed.sql` / `ci/test-jobs/security.yml` referenced by test-plan), security-lint, doc-consistency, and `appsec-reviewer` for security-critical paths. INV-004 tests must **run** (set the env they require) — a test that always `pytest.skip`s is not a gate.

---

## 5. Documentation consistency gate (prevents the v1.0.0 hallucination class)

Every PR that changes behavior must update affected docs in the same PR. The doc-consistency lint enforces:
- No doc may describe a feature without a code referent. New/changed capability claims include an inline `(file:line)` or are placed under an explicit **"Planned — not built"** heading.
- Removing/disabling a feature removes its claims in the same PR.
- A subsystem added to `proxy/app/` or `infra/db/migrations/` must appear in `ARCHITECTURE.md` §2/§3 and, if security-relevant, in `SECURITY_NONNEGATABLES.md`.
- No marketing/statistical claim without a citable source.
- `SECURITY_NONNEGATABLES.md` "Enforcement:" clauses must name a test/job that exists and actually asserts the claim (verified by the lint cross-checking the path).

Treat an unverifiable claim as a build defect equal to a failing test.

---

## 6. Test suites by category — what to run after every change

### 6.1 Functional / QA
- **Unit** (`proxy/tests/unit/`): services, middleware, broker, adapters — all mocked, <1s each.
- **Integration** (`proxy/tests/integration/`): real postgres/redis/opa — invocation happy/deny/error, audit completeness (incl. credential lifecycle after Phase 0.6), OPA deny-by-default, OPA-down→503 (must not skip).
- **Migration tests**: apply V001→V00n on a clean DB; assert role grants resolve (regression for CB-005); assert immutability triggers.
- **Contract**: API responses match `docs/API.md` schemas; 401 for unauth, 403 for quarantined/zero-role, 503 for OPA down, 500 for audit-emit failure.

### 6.2 Security (run on every security-critical change; weekly full sweep otherwise)
- INV-001..INV-012 invariant tests (the real ones — see REVIEW §2 for which exist vs must be created).
- Redaction fuzz: random payloads embedding all 10 secret patterns → assert never in any log sink.
- Auth bypass matrix: forged `X-Client-Cert-CN` on `/auth/*`, `/api/`, direct `proxy:8000` (sidecar simulation) → must be rejected (F-001/CB-001 regression).
- OAuth: state replay, nonce reuse, missing PKCE, IdP-error-body-in-logs (CB-003/10/11 regressions).
- Crypto: KEK determinism/uniqueness, nonce uniqueness across N encryptions, ciphertext auth-tag tamper → decrypt fails, master-secret never in logs/heap-dump fixture (CB-001/2/7/8).
- Secret scan: trufflehog on tree + history; `.env.lab`/`.env*` never staged.
- Negative RBAC: each role × each protected endpoint = expected allow/deny matrix.
- `appsec-reviewer` subagent sign-off (the human-judgment gate machine tests can't cover).

### 6.3 UI / UX (when a UI exists — currently none; gate before building)
No UI ships before backend P0–P2 are green. When built, after every UI change run:
- Playwright E2E for each flow: catalog browse, MCP submission, scan status, results viewer (must show *why* a scan failed — violation IDs + remediation hints), reviewer approve/reject/exception, integration status, credential enrollment.
- RBAC-aware navigation: each role sees only permitted actions (auditor read-only, etc.); assert hidden controls are also server-side enforced (no UI-only gating).
- Accessibility: axe-core pass on every page; keyboard-only completion of the submission + reviewer flows.
- Error UX: every backend error code (401/403/503/500/quarantine) renders an actionable message, never a raw stack trace or a leaked secret.
- Visual regression on the results/violations view.

---

## 7. Definition of Done (per change)

- [ ] Failing test written first, now passing; no unexplained skips.
- [ ] Full local gate (§3) green; CI gate (§4) green.
- [ ] Security-critical → `appsec-reviewer` returned UNBLOCKED; no open HIGH/CRITICAL.
- [ ] All affected docs updated; every claim cites file:line or is under "Planned — not built".
- [ ] No new fail-open path without an alert + doc note.
- [ ] Relevant INV scope updated if a subsystem/table was added.

A change failing any box is **not done**, regardless of effort spent.
