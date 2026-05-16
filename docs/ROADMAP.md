# MCP Security Platform — Roadmap & Challenges

**Date:** 2026-05-16 · Driven by `REVIEW-2026-05-16.md` and `ARCHITECTURE-v2.md`.

Principle: **no new features until the platform is honest and not exploitable.** A security platform that is itself insecure or oversold is worse than none — it manufactures false confidence (the exact failure mode INV-001 was written to prevent).

---

## STATUS DASHBOARD (as of 2026-05-16)

| Phase | State | Summary |
|---|---|---|
| **P0 — Security unblock** | ✅ **DONE** | All 2 CRITICAL + 4 HIGH + supporting MEDIUM findings fixed, unit-tested (79 pass), F-001 **runtime-proven on the live podman lab**. |
| **P1 — Truth reconciliation** | ⏳ **NEXT** | Docs vs reality: kill/relabel hallucinated features, fix broken CI/test refs, document the credential broker. ~1–2 days, no code risk. |
| **P2 — Hardening** | 🔜 after P1 | CB-008, INV-007 real verify, pre-commit secret hook, de-skip INV-004 in CI, wire F-002 signed bundle into a real staging deploy. |
| **P3 — Feature completion** | ⛔ blocked by P0–P2 | OIDC, learned anomaly baseline, real Helm, outbound Jira, per-tool rate-limit, UI. |

**Immediate next action: start P1.1 (replace the stale `ARCHITECTURE.md` v1) and P1.4 (fix the broken CI/test cross-references that currently make the integration job fail).**

---

## Phase 0 — UNBLOCK (security-critical) — ✅ COMPLETE

Exit criteria met: every P0 finding fixed, each with a passing regression test; F-001 additionally proven at runtime.

| # | Fix | Findings | Status / evidence |
|---|---|---|---|
| 0.1 | Broker/RBAC identity from `request.state.client_id` (never raw `X-Client-Cert-CN`); real nginx `location /auth/`; CN blanked outside `/api/v1/tools/`; OAuth callback public, identity recovered from server-side nonce. | CB-001, F-001 | ✅ `proxy/app/routers/oauth.py`, `middleware/auth.py`, `gateway/nginx/conf.d/mcp-proxy.conf` · tests: `test_oauth_router.py` (identity-from-store, spoof-ignored) |
| 0.2 | `VAULT_ADDR` default `https://`; model-validator rejects `http://` outside dev; `VAULT_CA_BUNDLE`; `kms.py` explicit TLS verify. | CB-002, CB-009 | ✅ `core/config.py`, `credential_broker/kms.py` · tests: `test_vault_tls_enforcement.py`, `test_config_broker.py` |
| 0.3 | Proxy off the flat `internal-net` + `observability-net`; pairwise `proxy-{opa,ollama,redis,db}-net` + `vault-net`; inbound only `gateway-net`. **Apply via full `compose up -d` (recreate) — not live `network disconnect`, not `--no-deps` without `--alias` on manually-connected backends.** | F-001 | ✅ `docker-compose.yml` · gate `scripts/check_network_isolation.py` in `make security-check` · **runtime-proven**: `mcp-netbox`→proxy:8000 REACHABLE→REFUSED, proxy healthy |
| 0.4 | Real OPA signed-bundle mechanism: `scripts/sign_policy_bundle.sh` + `make sign-policy-bundle` + `docker-compose.opa-signed.yml` overlay (HS256, `scope=write`). Dev keeps directory mount (INV-012 permits). | F-002 | ✅ mechanism delivered & overlay validates. **NOT yet enforced in a running staging deploy → see P2.8** |
| 0.5 | Server-side random nonce in Redis (single-use, TTL 300s, atomic consume); PKCE S256 added to m365/bitbucket/dex. | CB-003, CB-011 | ✅ `oauth.py`, adapters · tests: `test_oauth_router.py` (nonce/PKCE, replay→400) |
| 0.6 | Synchronous `CREDENTIAL_ENROLLED` audit event, RuntimeError-propagation (INV-001 pattern). | CB-004, CB-012 | ✅ `oauth.py::_emit_credential_audit` |
| 0.7 | Migration `V009`: `GRANT SELECT, INSERT ON role_assignments TO proxy_app; REVOKE UPDATE, DELETE`. | CB-005, INV-011 | ✅ `infra/db/migrations/V009__role_assignments_grants.sql` |
| 0.8 | KEK via HKDF-SHA256 (RFC 5869), not single-round HMAC. | CB-007 | ✅ `approaches/approach_a.py` · test: `test_approach_a.py` (HKDF, ≠ legacy) |
| 0.9 | OAuth token adapters raise `TokenExchangeError` (status only, never IdP body). | CB-010 | ✅ `adapters/{m365,bitbucket,dex}.py`, `adapters/base.py` |
| 0.10 | In-process MCP-client contract tests (no Docker): auth/role/JSON-RPC/quarantine/OPA/audit. | coverage | ✅ `proxy/tests/unit/test_mcp_client.py` (9 tests) |

**Not yet done in P0 scope (carried forward):** the *regression tests for some fixes are unit-level, not the integration tests the original plan named* — integration coverage (real DB/OPA) is folded into P1.4 (the integration CI job is currently broken by missing fixtures and must be repaired first).

---

## Phase 1 — TRUTH RECONCILIATION (documentation integrity)

Exit criteria: every claim in every doc maps to verified file:line, or is deleted, or moved to "Planned (not built)".

- 1.1 Replace `ARCHITECTURE.md` with `ARCHITECTURE-v2.md` content (or redirect it); never let a doc call itself "single source of truth" while omitting a shipped subsystem again.
- 1.2 Remove or implement: SPDX SBOM, outbound Jira, Helm/K8s, OIDC, per-tool rate limiting, learned anomaly baseline. Default action = **remove the claim**; reintroduce only when built (Phase 3).
- 1.3 Remove unsourced "92% / 20%" stat and the competitor differentiator table, or cite a verifiable public source.
- 1.4 Fix every broken cross-reference: `ci/test-jobs/security.yml` (missing), `tests/fixtures/integration_seed.sql` (missing), `test_audit_completeness_opa_down.py` (missing), INV-001's wrong test path. Either create the files or fix the references — the integration CI job currently fails at the seed step.
- 1.5 Rewrite each INV "Enforcement:" clause to state what is *actually* automated vs human-review vs aspirational (table in REVIEW §2). Correct T3: GOVERNANCE mode is not MFA-WORM.
- 1.6 Document the credential broker fully in architecture, API.md, RBAC.md (roles that may enroll), and SECURITY_NONNEGATABLES (a new INV for credential-at-rest + credential lifecycle audit).

---

## Phase 2 — HARDENING (not started; sequence after P1)

- 2.1 ✅ DONE in P0.8 — KEK via HKDF (RFC 5869) (CB-007).
- 2.2 ⏳ Master secret: TTL re-fetch from Vault, explicit zeroing, honor rotation (CB-008).
- 2.3 ✅ DONE in P0.9 — adapters raise typed `TokenExchangeError`, status only (CB-010). *Still pending:* add IdP-error redaction patterns to `mcp-audit-logger` (INV-002 depth).
- 2.4 ⏳ Real INV-007 startup Object-Lock verification in compliance-checker; decide GOVERNANCE vs COMPLIANCE mode and align the doc.
- 2.5 ⏳ Add pre-commit secret-scan hook (INV-008 gap); make trufflehog/opa hard failures in `make security-check` (currently skip-with-warn).
- 2.6 ⏳ De-skip INV-004 tests so they run in real CI (set the env the tests require in the workflow).
- 2.7 ⏳ Add broker variables to `.env.example`; `make lab-init` generates lab key material instead of `devpassword` constants (CB-006, CB-015).
- 2.8 ⏳ **Wire F-002 into a real staging deploy**: bring the stack up with `-f docker-compose.opa-signed.yml`, prove OPA refuses an unsigned/tampered bundle at runtime (the mechanism exists from P0.4 but has only been validated statically, not enforced in a running env).

---

## Phase 3 — FEATURE COMPLETION (only after P0–P2)

OIDC (replace 501 stubs, wire `oidc_role_mappings`) · learned/statistical anomaly baseline · SPDX (if a real consumer needs it) · outbound Jira issue creation on critical risk · real Helm chart + `helm template` CI lint · per-tool rate limiting · UI (catalog/submission/scan-status/reviewer actions — none exists yet; spec it before building).

---

## Challenges & Risks

1. **The doc/reality gap is structural, not a one-off.** The "canonical" doc drifted because nothing enforces doc↔code consistency. Mitigation: Phase 1.5 + the DEV-TEST-PROCESS doc-consistency gate; treat an unverifiable claim as a build defect.
2. **Credential broker is the highest-value attack target on the platform** — it holds keys to M365/Bitbucket/Grafana/Netbox/Dex. Its security bar must be the *highest*, yet it shipped with the *least* review (added after the appsec-review froze). Mitigation: mandatory `appsec-reviewer` sign-off on every broker change (DEV-TEST-PROCESS).
3. **Fail-open behaviors hide in "advisory" components.** Tool Manifest Auditor scores 0 if Ollama is down; anomaly uses fixed rules. These are defensible *if documented*; dangerous if presented as active controls. Mitigation: label advisory vs enforcing in architecture; alert when an advisory control is degraded.
4. **CI gives false assurance.** Several INV "Enforcement" tests `pytest.skip` unless env vars CI never sets, and `make security-check` skips tools when absent. Green CI ≠ invariants enforced. Mitigation: Phase 2.5/2.6; the gate must fail closed, like the system it protects.
5. **Crypto built by hand.** Per-user KEK, nonce handling, KDF were hand-rolled. Each is a CB-00x finding. Mitigation: standardize on `cryptography` HKDF/AESGCM primitives; no bespoke KDF/state derivation; crypto changes require appsec sign-off.
6. **No UI exists** despite reviewer/submission flows implied by the API. Don't let UI work start before P0–P2; a UI over an exploitable backend widens the attack surface.
7. **GOVERNANCE-mode WORM is not tamper-proof.** Compliance positioning depends on it. Decide COMPLIANCE mode (irreversible, operationally heavier) vs honest downgrade of the claim before any compliance marketing.

---

## Done Means

A phase is done only when: code merged, regression test in the **blocking** CI gate, docs updated to match (verified file:line), `make security-check` and `appsec-reviewer` both green, and no claim in any doc lacks a code referent. See `DEV-TEST-PROCESS.md`.
