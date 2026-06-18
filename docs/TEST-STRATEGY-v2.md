# MCP Security Platform — Test Strategy v2

Version: 2.0.0
Date: 2026-05-30
Status: CURRENT

This document supersedes and extends `docs/test-plan.md` for all new test layers
added in v2. It defines the full test layer map, the invariant coverage matrix,
how to run each layer, and the CI gate assignment for each.

---

## 1. Test Layer Map

```
proxy/tests/
  unit/           - No external services. sys.modules patching. Fast (<5s total).
  integration/    - ASGI in-process with mocked DB/Redis. @pytest.mark.integration.
  security/       - [TAMPER] tests, AI attack surface, sandbox escape at Python layer.
  performance/    - Latency/throughput baselines with mocked services.

sandbox/tests/
  red_team/       - Shell-based container isolation tests (requires docker compose up).

ui/tests/e2e/     - Playwright journeys (future — see §6 Coverage Gap).
```

### Layer Characteristics

| Layer | Marker | Services Required | Approximate Runtime | CI Gate |
|-------|--------|-------------------|--------------------|----|
| Unit | `@pytest.mark.unit` | None | < 5s | Yes — blocks merge |
| Integration | `@pytest.mark.integration` | None (ASGI in-process) | < 30s | Yes — blocks merge |
| Security | `@pytest.mark.security` | None (all mocked) | < 30s | Yes — blocks merge |
| Performance | `@pytest.mark.performance` | None | < 60s | No — advisory only |
| Red team | shell | docker compose up | ~5 min | No — nightly only |

**`make test-all`** = unit + integration + security (the CI merge gate).
**`make test-perf`** = performance (opt-in, advisory, logged for regression tracking).
**`make test-red-team`** = red team shell scripts (nightly, requires live containers).

---

## 2. Security Invariant Coverage Matrix

Every INV from `docs/SECURITY_NONNEGATABLES.md` mapped to test file(s) and test name(s).

| INV | Statement | Test File | Test Name(s) | CI Gate? |
|-----|-----------|-----------|-------------|----------|
| INV-001 | Every invocation has exactly one audit record | `integration/test_mcp_server_chain.py` | `test_inv001_audit_id_present_in_happy_path_response`, `test_inv001_audit_failure_aborts_invocation` | Yes |
| INV-001 | (existing) | `integration/test_audit_completeness.py` | All | Yes |
| INV-001 | (unit) | `unit/test_mcp_client.py` | `test_audit_emission_failure_aborts_with_500_inv001` | Yes |
| INV-002 | Logs never contain raw payloads (10 categories) | `security/test_ai_attacks.py` | `test_tamper_aws_key_in_arguments_is_redacted_in_audit`, `test_tamper_github_token_in_arguments_is_redacted`, `test_tamper_jwt_in_arguments_is_redacted` | Yes |
| INV-002 | (library level) | `unit/test_redaction.py` | All (10 pattern tests) | Yes |
| INV-003 | OPA deny-by-default | `integration/test_opa_deny_by_default.py` | All | Yes |
| INV-004 | OPA unreachable → 503 fail closed | `unit/test_mcp_client.py` | `test_opa_unavailable_is_503_inv004` | Yes |
| INV-004 | (integration) | `integration/test_mcp_server_chain.py` | `test_opa_unavailable_returns_503_fail_closed` | Yes |
| INV-005 | Quarantined tools blocked before OPA | `unit/test_mcp_client.py` | `test_quarantined_blocked_before_opa_inv005` | Yes |
| INV-005 | (integration) | `integration/test_mcp_server_chain.py` | `test_quarantined_tool_blocked_no_upstream_call` | Yes |
| INV-006 | SBOM signature required | `security/test_ai_attacks.py` | `test_tamper_sbom_invalid_signature_detected`, `test_tamper_sbom_missing_signature_cannot_activate_tool` | Yes |
| INV-006 | (library level) | `unit/test_sbom.py` | All | Yes |
| INV-007 | Audit log WORM (MinIO Object Lock) | No automated test — aspirational per archive/REVIEW-2026-05-16.md | Gap: ROADMAP P2.4 | No |
| INV-008 | No secrets in code | `make security-check` (trufflehog) | N/A — tooling gate | Yes |
| INV-009 | mTLS enforced for agent endpoints | `unit/test_auth_middleware.py` | `test_missing_cn_no_auth_returns_401`, `test_401_includes_www_authenticate_header` | Yes |
| INV-009 | (integration) | `integration/test_rbac.py` | `test_unauthenticated_returns_401[POST /tools/{id}/invoke]` | Yes |
| INV-010 | step-ca certs max 24h TTL | Config verification — no automated test (deploy-time check) | Gap: not automated | No |
| INV-011 | No direct DB writes outside designated services | `integration/test_invoke.py` (existing) | Structural: DB role grants in V003 | No automated pytest |
| INV-012 | OPA policy bundle signing in prod | `make security-check` (rego lint) | N/A — config gate | Yes |
| INV-013 | Credential broker at-rest encryption + audit | `unit/test_oauth_router.py`, `unit/test_vault_tls_enforcement.py` | Existing | Yes |

---

## 3. RBAC Matrix Coverage

Full matrix per `docs/RBAC.md`. Unit tests in `unit/test_rbac_matrix.py`, HTTP-level in `integration/test_rbac.py`.

### 3.1 Tool Registry

| Operation | admin | agent | auditor | readonly | Test |
|-----------|-------|-------|---------|----------|------|
| `POST /tools/register` | ✅ 201 | ❌ 403 | ❌ 403 | ❌ 403 | `TestPostRegisterTool.*` |
| `GET /tools` | ✅ 200 | ✅ 200 | ✅ 200 | ✅ 200 (filtered) | `TestGetTools.*` |
| `GET /tools/{id}` | ✅ 200 | ✅ 200 | ✅ 200 | ✅ 200 (filtered) | `TestGetTools.*` |
| `PATCH /tools/{id}` | ✅ 200 | ❌ 403 | ❌ 403 | ❌ 403 | `TestPatchTool.*` |
| `DELETE /tools/{id}` | ✅ 204 | ❌ 403 | ❌ 403 | ❌ 403 | `TestDeleteTool.*` |

### 3.2 Audit + SBOM

| Operation | admin | agent | auditor | readonly | Test |
|-----------|-------|-------|---------|----------|------|
| `GET /tools/{id}/audit` | ✅ 200 | ❌ 403 | ✅ 200 | ❌ 403 | `TestGetToolAudit.*` |
| `POST /tools/{id}/audit/rerun` | ✅ 202 | ❌ 403 | ❌ 403 | ❌ 403 | (extends `TestDeleteTool` pattern) |
| `GET /tools/{id}/sbom` | ✅ 200 | ❌ 403 | ✅ 200 | ✅ 200 (no sig) | `TestGetToolSbom.*` |

### 3.3 Invocation

| Operation | admin | agent | auditor | readonly | Test |
|-----------|-------|-------|---------|----------|------|
| `POST /tools/{id}/invoke` | ✅ 200 (testing) | OPA-gated | ❌ 403 | ❌ 403 | `TestInvokeTool.*` |

### 3.4–3.7 Policy, Compliance, Anomaly, Audit

| Operation | admin | agent | auditor | readonly | Test |
|-----------|-------|-------|---------|----------|------|
| `GET /policy/rules` | ✅ 200 | ❌ 403 | ✅ 200 | ❌ 403 | `TestGetPolicyRules.*` |
| `POST /policy/evaluate` | ✅ 200 | ❌ 403 | ❌ 403 | ❌ 403 | `TestPostPolicyEvaluate.*` |
| `GET /anomaly` | ✅ 200 | ❌ 403 | ✅ 200 | ❌ 403 | `TestGetAnomaly.*` |
| `PATCH /anomaly` | ✅ 200 | ❌ 403 | ❌ 403 | ❌ 403 | `TestPatchAnomaly.*` |
| `GET /audit` | ✅ 200 | ✅ 200 (own) | ✅ 200 | ❌ 403 | `TestGetAuditEvents.*` |
| `GET /health` | ✅ 200 | ✅ 200 | ✅ 200 | ✅ 200 | Public path — no test needed |

**No-auth (unauthenticated):** All protected endpoints tested in `test_rbac.py::test_unauthenticated_returns_401[*]` — parametrized across 9 endpoints.

---

## 4. [TAMPER] Test Index

All tests labeled `[TAMPER]` in their names. Present in `security/test_ai_attacks.py` and `security/test_sandbox_escape.py`.

| Test Name | Attack Vector | INV |
|-----------|--------------|-----|
| `test_tamper_prompt_injection_in_path_argument` | Prompt injection via path arg | — |
| `test_tamper_prompt_injection_attempts_do_not_bypass_opa` | Injection bypass OPA | INV-003 |
| `test_tamper_manifest_poisoning_malicious_description_does_not_cause_500` | Tool manifest poisoning | INV-005 |
| `test_tamper_aws_key_in_arguments_is_redacted_in_audit` | Credential exfiltration via args | INV-002 |
| `test_tamper_github_token_in_arguments_is_redacted` | Token exfiltration | INV-002 |
| `test_tamper_jwt_in_arguments_is_redacted` | JWT exfiltration | INV-002 |
| `test_tamper_tool_name_with_prompt_injection_chars_handled_gracefully` | Name-based injection | — |
| `test_tamper_null_byte_in_argument_handled_gracefully` | Null byte injection | — |
| `test_unicode_rtl_override_in_tool_name_handled` | Unicode RLO attack | — |
| `test_tamper_ssrf_imds_url_in_upstream_tool` | SSRF to IMDS | INV-003 |
| `test_tamper_sbom_invalid_signature_detected` | SBOM tamper | INV-006 |
| `test_tamper_sbom_missing_signature_cannot_activate_tool` | Missing SBOM sig | INV-006 |
| `test_tamper_audit_log_hmac_invalid_signature_detected` | Audit log tamper | INV-001 |
| `test_tamper_path_traversal_in_arguments_does_not_crash` | Path traversal | — |
| `test_tamper_windows_path_traversal_handled` | Windows path traversal | — |
| `test_tamper_env_var_reference_not_expanded_by_proxy` | Env var exfiltration | — |
| `test_tamper_ssti_template_strings_not_evaluated` | SSTI injection | — |
| `test_tamper_shell_metacharacters_not_executed` | Subprocess injection | — |
| `test_tamper_zip_bomb_sbom_rejected_gracefully` | SBOM zip-bomb | INV-006 |
| `test_tamper_replayed_expired_jwt_rejected` | JWT replay | INV-009 |

---

## 5. MCP Server Integration Chain Coverage

From `mcps.yaml` — each server type tested in `integration/test_mcp_server_chain.py`:

| Server | Type | Test |
|--------|------|------|
| grafana, netbox, lab-grafana, lab-gitea | `api_key` | `test_api_key_chain_*` |
| m365, bitbucket, lab-dex | `oauth2/authorization_code` | `test_oauth2_chain_*` |
| All | error propagation | `test_api_key_chain_upstream_returns_error_is_propagated` |
| All | timeout handling | `test_api_key_chain_upstream_timeout_handled` |
| All | missing credential | `test_api_key_chain_missing_credential_fails_gracefully` |

**Gap:** `oauth2/device_flow` (lab-dex) is covered at the integration level by a mocked happy path. A full device poll loop test requires a live Dex container (not yet added).

---

## 6. Performance Baseline Targets

All baselines are **advisory** — CI logs regressions but does not fail on them.

| Metric | Soft Target | Hard Limit | Test |
|--------|-------------|------------|------|
| Single invocation p50 (mocked) | < 50ms | < 500ms | `test_single_invocation_latency_baseline` |
| Single invocation p99 (mocked) | < 200ms | < 500ms | `test_single_invocation_latency_baseline` |
| Auth middleware overhead | < 10ms | < 20ms | `test_auth_middleware_overhead_negligible` |
| GET /health p99 | < 10ms | < 100ms | `test_health_endpoint_sub_10ms` |
| 20 concurrent requests | All 200 | — | `test_concurrent_invocations_no_race_conditions` |
| Memory growth (1000 reqs) | < 10MB | < 50MB | `test_no_memory_leak_over_sequential_requests` |

---

## 7. How to Run Each Layer

```bash
# Unit tests (no services):
cd proxy && python -m pytest tests/unit/ -v -m unit

# Integration tests (ASGI in-process, no docker needed):
cd proxy && python -m pytest tests/integration/ -v -m integration

# Security tests ([TAMPER] + AI attacks):
cd proxy && python -m pytest tests/security/ -v -m security

# Performance benchmarks:
cd proxy && python -m pytest tests/performance/ -v -m performance -s

# All CI gate tests:
make test-all

# Red team (requires docker compose up):
make test-red-team

# Security invariant checks (trufflehog + rego lint):
make security-check
```

---

## 8. Coverage Gaps and Known Limitations

| Gap | Severity | Ticket / Status |
|-----|----------|-----------------|
| INV-007 MinIO Object Lock startup check | High | ROADMAP P2.4 — no automated test |
| INV-010 step-ca cert TTL enforcement | Medium | Config-only; needs `step ca certificate` integration test |
| INV-012 OPA bundle signing in staging | Medium | ROADMAP P2.8 — mechanism exists, not CI-gated |
| Device flow full poll loop test | Low | Requires live Dex container |
| Playwright E2E UI journeys | High | Not yet implemented — no UI layer exists |
| `readonly` field filtering verified end-to-end | Medium | Middleware allows; router filters — needs DB-seeded integration test |
| `agent` audit own-record filter | Medium | RBAC allows all audit; router must filter by client_id — not yet tested |
| SPDX SBOM format returns 501 | Low | Documented in router; no dedicated test |

---

*End of TEST-STRATEGY-v2.md*
