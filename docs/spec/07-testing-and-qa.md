# 07 — Test & QA Program Specification

**Purpose.** This document tells a re-implementer — in any language — *what* tests must exist and *what*
must pass before the system may be called "done." It is normative: the security posture is only as
trustworthy as the tests that gate it, so the governing rule is **every enforced control has a test, and
the CI gate fails closed** (a missing scanner is a FAILURE, never a skip). Counts and commands below
describe the reference implementation (Python/pytest + Playwright + shell harnesses) as calibration; a
port must reproduce the *coverage and gates*, not the tooling.

**Status:** matches code at HEAD (`4dfa7b5`). Test-suite calibration figures are from commit `2f6430c`.
Conformance keywords (MUST/SHOULD/MAY) follow RFC 2119. `(roadmap)` marks a control not yet wired; a
`(roadmap)` control MUST NOT be asserted by a passing gate.

> Authority: where this spec and the README **Enforced-vs-Roadmap** table disagree about whether a
> control is live, the README table wins. Where this spec and `docs/ARCHITECTURE.md` §10 disagree about
> an invariant's meaning, §10 wins. Keep tests matched to code, not to this prose.

---

## 1. Test pyramid overview

Six categories. The re-implementation MUST provide every category; the parenthetical figures calibrate
expected scale at `2f6430c`.

| # | Category | Location (reference) | Scale (calibration) | Needs a running stack? |
|---|----------|----------------------|---------------------|------------------------|
| 1 | **Unit** | `proxy/tests/unit/` (+ `unit/credential_broker/`) | ~98 files / ~1131 tests green per commit | No — pure, deterministic |
| 2 | **Integration** | `proxy/tests/integration/` | ~21 scenarios (`-m integration`) | Yes — full stack up |
| 3 | **Security invariant / regression** | `proxy/tests/security/` + `make security-check` | invariant + tamper + sandbox-escape | Partly (static gates need no stack) |
| 4 | **Trust-envelope (RFC-0002) oracle-parity + red-team** | `proxy/tests/rfc0002/` | oracle-parity + adversarial regression | No — self-contained |
| 5 | **Containerized red-team harness** | `sandbox/tests/red_team/` + lab MCP probes | 11 containment probes + MCP backend-isolation probe | Yes — podman + sandbox/lab net |
| 6 | **Lab functional gate-chain** | `lab/tests/functional_test.py` | headline E2E acceptance chain | Yes — `make lab-up` |
| — | **UI e2e (Playwright)** | `ui/e2e/*.spec.ts` | portal (~4) + acceptance (~32) specs | Yes — portal + backend |
| — | **Performance** | `proxy/tests/performance/` | throughput/latency, non-gating | Yes — reports only |

The pyramid is bottom-heavy by design: the unit tier carries the bulk of coverage and runs with no
external services; everything above it proves that the wired-together system preserves the same
invariants the units prove in isolation.

---

## 2. Per-category normative requirements

### 2.1 Unit tests

Unit tests MUST cover every security-relevant decision core in isolation, with no network and no running
services. The following classes of unit coverage are REQUIRED (generalized from the reference suite; the
cited files are the reference implementation of each requirement):

- **Credential crypto chain.** The KEK derivation and envelope encryption MUST be unit-tested:
  per-user HKDF-SHA256 KEK from a ≥256-bit master, AES-256-GCM envelope, and **AAD binding to the
  authenticated identity** so a blob encrypted for user A cannot be decrypted under user B
  (`credential_broker/test_kms.py`, `test_approach_a.py`, `test_master_secret_ttl.py`). Verifies INV-013.
- **Redaction.** Every credential/PII pattern class (AWS keys, GitHub tokens, bearer tokens, private
  keys, emails…) MUST have a positive redaction assertion producing `[REDACTED:<cat>]`
  (`test_redaction.py`, `test_log_filter.py`). Verifies INV-002.
- **Injection-pattern three-way consistency.** The injection phrase list MUST be identical across all
  three enforcement surfaces — the Python list, the Rego `data.json` (`data.mcp.injection_phrases`), and
  the tool-risk policy — with a sync test that fails on divergence (`test_injection_patterns.py`). A port
  with a single source of truth still MUST test that every consumer reads the same list.
- **Policy client null-handling / fail-closed.** A `null`, missing, or malformed OPA result MUST
  normalize to **deny**, and an unreachable OPA MUST yield 503 `OPA_UNAVAILABLE`
  (`test_policy_null_result.py`, `test_dispatcher_fail_closed.py`). Verifies INV-004.
- **Session-JTI revocation fail-closed.** Any Redis/DB error during revocation lookup MUST deny, never
  allow a possibly-revoked token (`test_jti_revocation.py`, `test_ratelimit_redis_error.py`,
  `test_entra_token_cache_redis.py`). Verifies INV-014.
- **MCP-profile lookup fail-closed.** DB error + cache miss MUST yield 503, never an empty/unrestricted
  profile (`test_mcp_server_profile_failclosed.py`, `test_profile_lookup_failclosed.py`). Verifies INV-015.
- **Taint keying / floor.** The taint-floor decision core (binary integrity from trust tier, fail-closed
  on unknown tier) and per-identity taint keying MUST be unit-tested
  (`test_taint_floor.py`, `test_taint_store.py`, `test_gap1_taint_audit.py`).
- **Verified-identity anti-spoofing.** An OIDC email MUST be usable as identity key only when the IdP
  asserts it verified; machine (client_credentials) tokens MUST be barred from human-only self-service
  mutation (`test_p1_verified_identity.py`, `test_p2_self_service_sa_guard.py`, `test_typed_principals.py`).
- **Auth middleware / trusted-proxy.** The `X-Client-Cert-CN` header MUST be honoured only with a
  matching gateway secret compared in constant time (`test_auth_middleware.py`,
  `test_gateway_secret_trust.py`, `test_gateway_secret_scope.py`).
- **RBAC matrix.** The role→permission matrix (admin/agent/auditor) MUST be unit-asserted, including
  auditor read-only isolation (`test_rbac_matrix.py`, `test_rbac_v3_roles.py`, `test_portal_auditor_access.py`).
- **SBOM signing.** No `active` tool without a valid HMAC-signed SBOM (`test_sbom.py`,
  `test_sbom_manifest_parser.py`). Verifies INV-006.
- **Entitlement / quarantine.** Quarantined tools MUST be denied pre-OPA for every role incl. admin;
  discovery==invoke entitlement MUST be enforced on the invoke path
  (`test_entitlement_enforcement.py`, `test_per_function_entitlement.py`, `test_dispatcher_*.py`).
  Verifies INV-005.
- **SSRF / upstream validation** (`test_ssrf.py`, `test_upstream_validator.py`,
  `test_server_onboarding_validation.py`).
- **Trust-envelope primitives.** JCS/RFC-8785 canonicalization, ES256 sign/verify, labeler/observer/
  verifier (`test_jcs.py`, `test_trust_verifier.py`, `test_trust_labeler.py`, `test_trust_observer.py`).

> Rule: **a decision that can fail closed MUST have a unit test that proves it fails closed on the error
> path**, not only that it allows on the happy path.

### 2.2 Integration tests

Integration scenarios run against a live stack (`-m integration`). Each REQUIRED scenario below is listed
as *scenario → invariant it proves*:

- `test_auth_flows.py` → end-to-end auth acceptance across the supported credential types.
- `test_oauth_pkce_flow.py` → browser-equivalent OAuth **PKCE S256** login yields a valid session JWT.
- `test_onboarding_e2e_mode_a.py`, `test_onboarding_e2e_mode_b_c_d.py`, `test_onboarding_real_e2e.py` →
  server onboarding **modes A–D** each reach a governed, invocable end state.
- `test_opa_deny_by_default.py` → an unmatched request is denied (INV-003 at runtime).
- `test_rbac.py` → the RBAC matrix holds through the real stack (admin vs agent vs auditor).
- `test_taint_floor_invoke.py` → taint floor blocks a low-integrity invoke path end-to-end.
- `test_registry_migration.py`, `test_db_migrate.py` → registry/schema migrations apply cleanly and
  preserve constraints (incl. per-role DB grants, INV-011).
- `test_mcp_server_chain.py` → a multi-hop MCP server chain invokes through the proxy under one identity.
- `test_audit_completeness.py`, `test_invocation_audit.py` → **every** invocation and auth rejection
  emits a synchronous audit event before the response; emission failure ⇒ 500 (INV-001).
- `test_opa_bundle_with_grants.py`, `test_grants_sync_mutation_integration.py` → OPA data-API push on
  every grant mutation; `data.mcp_grants` evaluated at invoke time.
- `test_admin_limits.py`, `test_invoke.py`, `test_registration_endpoint.py`,
  `test_server_scoped_enrollment.py` → admin limits, invoke contract, registration, scoped enrollment.

### 2.3 Security invariant gates — `make security-check` (CI gate)

This is the blocking CI gate. **Governing principle: fail closed on missing tooling** — an absent
scanner (`trufflehog`, `opa`, `semgrep`) is a FAILURE, not a skip. Every gate below MUST run on **every
CI run**. Each is stated as *gate → what it proves*:

- **INV-002 redaction** → runs the redaction unit tests; proves logs cannot leak raw secrets/PII.
- **INV-003 deny-by-default** → greps `policies/rego/` for `default allow = false`; proves no wildcard
  allow / fallthrough was introduced.
- **INV-008 secret scan** → `trufflehog git file://. --only-verified --fail`; proves no verified secret
  in git history. Missing trufflehog ⇒ FAIL.
- **Rego lint** → `opa check policies/rego/`; proves the policy compiles. Missing opa ⇒ FAIL.
- **F-001 network isolation** (`scripts/check_network_isolation.py`) → static topology check run across
  **all five compose tiers** (`docker-compose.yml`, `podman-compose.lab.yml`, `compose.poc.yml`,
  `compose.engine.yml`, `compose.standard.yml`); proves proxy and MCP servers stay isolated (proxy never
  on `internal-net`; MCP servers never on a platform backend net; pairwise nets shared with proxy only;
  no credential env leakage; `.env`/`GATEWAY_SHARED_SECRET` scoped to allowed services only). Resolves
  statically — no daemon required.
- **F-002 / INV-012 signed bundle default** (`scripts/check_signed_default.sh`) → every non-dev tier that
  runs OPA MUST pass `--verification-key`, AND the signed bundle MUST actually verify against the repo
  key (empty `POLICY_SIGNING_KEY` ⇒ FAIL — an empty key silently disables verification). Proves signed
  policy is the default, not opt-in.
- **N1 Loki label consistency** (`scripts/check_loki_labels.sh`) → alert rules reference only labels
  Promtail assigns; proves the audit-alert path is not silently broken.
- **H3 identity-as-tool-param** (`semgrep --config policies/semgrep.yml`) → no MCP tool accepts caller
  identity as a parameter (CWE-639). Missing semgrep ⇒ FAIL.

A re-implementation MUST provide an equivalent single command that runs all of these and exits non-zero
if any fails or any required scanner is absent.

### 2.4 Red-team / adversarial

Two proof types are BOTH REQUIRED and are not interchangeable:

- **Static topology proof** — F-001 above proves the *configured* topology is isolated.
- **Dynamic runtime unreachability** — the containerized harness (`sandbox/tests/red_team/run_all.sh`)
  MUST prove a running sandboxed MCP container cannot: reach the network beyond its allowlist
  (`test_network_isolation.sh`, `test_mcp_egress_control.sh`), exfiltrate credentials
  (`test_credential_exfil.sh`), escape the filesystem or via symlink (`test_filesystem_isolation.sh`,
  `test_symlink_escape.sh`), escalate privilege (`test_privilege_escalation.sh`), break seccomp
  (`test_seccomp.sh`), exceed resource limits (`test_resource_limits.sh`), inject via stdio
  (`test_stdio_injection.sh`), or poison tools / supply chain (`test_tool_poisoning.sh`,
  `test_supply_chain.sh`, `test_prompt_injection_wazuh.sh`). The same probes MUST also run against a real
  lab MCP server (`test_mcp_platform_backend_isolation.sh`, RT-MCP-001) — isolating the generic sandbox
  is not enough; the actual server container MUST be proven unable to reach platform backends.
- **RFC-0002 malicious-MCP catalogue** — the trust-envelope red-team regression
  (`proxy/tests/rfc0002/test_redteam_regression.py`) plus oracle-parity
  (`test_scenarios_oracle.py`, `test_gateway_parity.py`, `test_appendix_b_vectors.py`) MUST prove the
  verifier's verdicts match the spec oracle on the adversarial vector set and that known-bad envelopes
  stay rejected.

**Rule:** a "runtime isolation" claim requires *both* a static topology proof and a dynamic
unreachability proof. Neither alone is sufficient.

### 2.5 Lab functional gate-chain (headline E2E acceptance)

`lab/tests/functional_test.py` is the single headline acceptance test. It runs *outside* the proxy
container (uses `podman exec` for the network-reachability probe and hits published ports) against a full
lab stack. It MUST prove the whole gate chain end-to-end, not just an HTTP 200:

- Infrastructure liveness (proxy `/health`, direct MCP `initialize` handshakes, Keycloak health).
- **Scenario A** — per-user tokens via ROPC (simulating PKCE): distinct identities get distinct `sub`;
  tokens are not interchangeable; unauthenticated/invalid tokens rejected; users invoke permitted tools.
- **Scenario B** — shared service-account (client_credentials) token invokes permitted tools; wrong
  audience rejected.
- **`TestInvokePathGateChain`** — the critical class: it catches the failure mode where a broken invoke
  path (network split, SSRF/DNS-rebind, missing entitlement) still returns HTTP 200. It asserts the
  proxy can DNS-resolve all registered upstreams **and** that a real invoke returns 200 *with no
  JSON-RPC / gate-chain error in the body*. A re-implementation's acceptance gate MUST assert on body
  semantics, never on status code alone.

### 2.6 UI e2e (Playwright)

Portal changes MUST NOT ship without green Playwright e2e (`ui/e2e/portal.spec.ts`,
`portal-acceptance.spec.ts`). REQUIRED coverage: full browser PKCE login; every admin nav tab; the
submission wizard (all steps, guided + quick-pick); submission lifecycle CRUD; and **RBAC-aware UI
assertions** — admin, agent, and auditor each see only their permitted views and controls (auditor
read-only, no approve/reject). Security-boundary checks (e.g. GitHub URL validation) MUST be asserted in
the UI layer too.

### 2.7 Performance

Honest scope: `proxy/tests/performance/test_throughput.py` exists and is run via `make test-perf`
(`-m performance`). It measures latency/throughput and **reports regressions only — it does not fail
CI** and is excluded from `make test-all`. A re-implementation SHOULD keep a non-gating perf smoke test;
it MAY expand it, but MUST NOT let perf targets block merges unless explicitly promoted to a gate.

---

## 3. Acceptance criteria matrix

Each invariant → the test(s)/gate(s) that verify it → verification type. Where an invariant has **no**
automated verification, that is stated explicitly (required honesty).

| Invariant | Verified by | Type |
|-----------|-------------|------|
| INV-001 audit-before-response, fail-500 | `integration/test_audit_completeness.py`, `test_invocation_audit.py`; `unit/test_audit_auth_failure.py`, `test_audit_who_fields.py` | integration + unit |
| INV-002 redaction | `unit/test_redaction.py`, `test_log_filter.py`; `security-check` INV-002 block | unit + static-gate |
| INV-003 deny-by-default | `integration/test_opa_deny_by_default.py`; `security-check` grep gate | integration + static-gate |
| INV-004 OPA-unreachable ⇒ fail-closed | `unit/test_policy_null_result.py`, `test_dispatcher_fail_closed.py` | unit |
| INV-005 quarantine denied pre-OPA (incl. admin) | `unit/test_entitlement_enforcement.py`, `test_dispatcher_*.py` | unit |
| INV-006 no active tool without signed SBOM | `unit/test_sbom.py`, `test_sbom_manifest_parser.py` | unit (+ DB constraint) |
| INV-007 audit archive Object-Lock (≥GOVERNANCE, 90d) | **No automated test** — enforced by `compliance-checker/checker.py` + `setup-minio.sh`; verify manually | **manual** |
| INV-008 no secrets in git | `security-check` trufflehog gate | static-gate |
| INV-009 invoke requires mTLS/API-key/JWT | `unit/test_auth_middleware.py`; `lab functional` unauthenticated-rejected | unit + integration |
| INV-010 mTLS cert ≤24h TTL | **No automated test** — asserted by step-ca provisioner config; verify by config review | **manual / config** |
| INV-011 per-role DB write grants | `integration/test_db_migrate.py`, `test_registry_migration.py` (migrations `V003`/`V009`) | integration |
| INV-012 signed OPA bundle is default | `security-check` F-002 (`check_signed_default.sh`); `unit/security/test_signed_bundle.py` | static-gate + unit |
| INV-013 per-user HKDF KEK + AES-256-GCM + identity AAD | `unit/credential_broker/test_kms.py`, `test_approach_a.py`, `test_master_secret_ttl.py` | unit |
| INV-014 JTI revocation fail-closed | `unit/test_jti_revocation.py` | unit |
| INV-015 profile lookup fail-closed | `unit/test_mcp_server_profile_failclosed.py`, `test_profile_lookup_failclosed.py` | unit |
| **F-001** network isolation (all tiers) | `scripts/check_network_isolation.py` via `security-check`; `sandbox/tests/red_team/*` runtime probes | static-gate + red-team |
| **F-002** signed-bundle default | `scripts/check_signed_default.sh` via `security-check` | static-gate |
| Identity anti-spoofing (P1-1/P1-2) | `unit/test_p1_verified_identity.py`, `test_p2_self_service_sa_guard.py` | unit |

Invariants with **no automated verification** today: **INV-007** (Object-Lock retention) and **INV-010**
(≤24h mTLS TTL). A re-implementation SHOULD add automated checks for both; until then they MUST be
covered by a documented manual verification step and MUST NOT be claimed as automatically gated.

---

## 4. QA process requirements (implementation phase)

- **Tests alongside each layer, not after.** Each layer lands with its unit tests in the same change;
  a control without a blocking test is treated as a bug, not a TODO.
- **Security gate green before merge.** `make security-check` MUST pass before any merge. It fails
  closed — a missing scanner blocks the merge.
- **Red-team pass before any "done" claim.** No layer with a runtime-isolation or containment claim may
  be called done until both the static F-001 gate and the dynamic `sandbox/tests/red_team` harness pass
  against the real container.
- **UI e2e before portal ships.** Playwright acceptance MUST be green before any portal change ships.
- **Adversarial dual-review with mandatory post-fix verification.** The project's review pattern is
  adversarial (independent critics) AND requires a **second verification pass after fixes** — because
  fixes regress. The reference experience: a review-findings pass fixed a batch of issues, and the
  *pass-2* verification found that some fixes had reintroduced regressions. Therefore post-fix
  verification passes are **mandatory**, not optional: never close a finding on the strength of the fix
  alone; re-run the relevant tests/gates and re-review after applying it.
- **Docs matched to code.** A doc claim without backing code is a bug; the README Enforced-vs-Roadmap
  table is the authority for per-control status and MUST be updated in the same change that moves a
  control from roadmap to enforced.

A change is **complete** only when: code merged, a regression test is in the blocking suite, the docs
match code, `make security-check` is green, and — for isolation/portal work — the red-team / e2e gates
are green.

---

## 5. Test commands (reference implementation)

```bash
# ── Unit (no stack) ──────────────────────────────────────────────
cd proxy
python3 -m pytest tests/unit -q                 # full unit suite (~1131 tests)
python3 -m pytest tests/unit tests/security -q  # unit + security invariants
python3 -m pytest tests/unit/test_redaction.py -q   # a single file

# ── Trust envelope (RFC-0002), self-contained ────────────────────
python3 -m pytest tests/rfc0002 -q

# ── Via the stack (containers) ───────────────────────────────────
make test              # everything, inside the proxy container
make test-unit         # unit only
make test-integration  # -m integration (needs services)
make test-oauth        # full OAuth/ROPC/PKCE flow (needs Keycloak)
make test-all          # unit + integration + security (not perf)
make test-security     # -m security (tamper / AI attack / sandbox escape)
make test-perf         # performance (reports regressions, non-gating)

# ── The blocking security gate (fails closed) ────────────────────
make security-check

# ── Red-team containment harness (needs podman + sandbox/lab net) ─
make test-red-team
bash sandbox/tests/red_team/run_all.sh

# ── Headline lab gate-chain acceptance (needs `make lab-up`) ──────
make test-lab-functional

# ── UI e2e (needs portal + backend) ──────────────────────────────
cd ui && npx playwright test e2e/
```
