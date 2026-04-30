# MCP Security Platform — Test Plan

Version: 1.0.0
Date: 2026-04-21
Owner: QA Engineering
Status: LIVING DOCUMENT — update when new features land or invariants change.

---

## 1. Test Strategy

### 1.1 Test Layers

| Layer | Location | Speed | Services Required | CI Gate |
|-------|----------|-------|-------------------|---------|
| Unit | `proxy/tests/unit/` | <1 s/test | None (all mocked) | Yes — blocks merge |
| Integration | `proxy/tests/integration/` | 1–5 s/test | postgres, redis, opa | Yes — runs in service containers |
| E2E | (future: `ui/tests/e2e/`) | 5–30 s/test | Full stack | No — advisory only in v1 |
| Security lint | `ci/test-jobs/security.yml` | <30 s | None | Yes — blocks merge |

### 1.2 Markers

```
@pytest.mark.unit         — no network, no docker, safe to run anywhere
@pytest.mark.integration  — requires docker compose up (see ci/test-jobs/integration-tests.yml)
```

Tests without an explicit marker run in both contexts. No test is permitted to use `@pytest.mark.skip` or `pytest.skip()` without a code comment referencing a ticket number.

### 1.3 What Runs Where

**PR gate (CI, every push):**
- All `@pytest.mark.unit` tests
- Security lint: `trufflehog`, `opa check --strict`, `default allow = false` assertion
- INV-002 redaction tests (`proxy/tests/unit/test_redaction.py`)

**Integration gate (CI, on merge to main):**
- All `@pytest.mark.integration` tests
- Spins up postgres, redis, opa service containers (see `ci/test-jobs/integration-tests.yml`)

**Local developer workflow:**
```
make test-unit       # unit tests only, no docker needed
make test-integration # requires docker compose up
make security-check  # redaction + rego lint + secret scan
```

### 1.4 Coverage Targets

| Domain | Line coverage target |
|--------|---------------------|
| `proxy/app/services/auditor.py` | 90% |
| `proxy/app/services/sbom.py` | 90% |
| `proxy/app/services/invocation.py` | 85% |
| `proxy/app/middleware/auth.py` | 80% |
| `proxy/app/middleware/rbac.py` | 90% |
| `mcp_audit_logger/redaction.py` | 100% (every category) |

---

## 2. Security Invariant Coverage Map

Every invariant from `docs/SECURITY_NONNEGATABLES.md` must have at least one test. This table maps each invariant to the test file(s) that prove it.

| Invariant | Statement (abbreviated) | Test File(s) | Test Names |
|-----------|------------------------|--------------|------------|
| INV-001 | Every invocation has exactly one audit record | `tests/integration/test_audit_completeness.py` | `test_allow_path_produces_one_audit_event`, `test_deny_path_produces_one_audit_event`, `test_opa_down_produces_error_audit_event`, `test_unauthenticated_produces_no_audit_event` |
| INV-002 | Logs never contain raw payloads (10 categories) | `tests/unit/test_redaction.py` | All 10 `test_*_redacted` tests + `test_all_10_categories_covered` |
| INV-003 | OPA deny-by-default | `tests/integration/test_opa_deny_by_default.py` | `test_opa_deny_by_default_empty_input`, `test_opa_deny_unknown_client` |
| INV-003 | OPA rego lint: `default allow = false` present | `ci/test-jobs/security.yml` | `assert-opa-deny-by-default` lint step |
| INV-004 | OPA unreachable = 503, fail closed | `tests/integration/test_invoke.py` | `test_opa_unavailable_returns_503` |
| INV-005 | Quarantined tools blocked before OPA | `tests/integration/test_invoke.py` | `test_quarantined_tool_returns_403_before_opa` |
| INV-006 | SBOM signature required on registration | `tests/unit/test_sbom.py` | `test_hmac_signature_roundtrip`, `test_signature_rejects_tampered_sbom`, `test_missing_signing_key_raises` |
| INV-007 | Audit log archive is WORM (MinIO Object Lock) | Infrastructure (`infra/scripts/setup-minio.sh`) | Verified at deploy time; compliance checker startup assertion |
| INV-008 | No secrets in code/config files | `ci/test-jobs/security.yml` | `trufflehog-scan` step |
| INV-009 | mTLS enforced for agent endpoints | `tests/integration/test_invoke.py` | `test_unauthenticated_returns_401` |
| INV-010 | step-ca certs max 24h TTL | Nginx/step-ca config verification | Out of unit test scope; verified at deploy time |
| INV-011 | No direct DB writes outside designated services | PostgreSQL role grants (`V003__db_roles.sql`) | Out of unit test scope; verified at deploy time |
| INV-012 | OPA policy bundle signing in prod/staging | `ci/test-jobs/security.yml` | `policy-bundle-signing-check` step |

---

## 3. RBAC Matrix

Every cell below has a corresponding test in `proxy/tests/integration/test_rbac.py` (to be created as coverage expands). The expected HTTP status codes drive the test assertions.

### 3.1 Legend

- **Y / 2xx** — Allowed; expect 200 or 201
- **403** — Role resolved but operation forbidden
- **401** — No identity resolved
- **OPA** — Subject to OPA fine-grained evaluation (may also 403 from OPA)
- **Own** — Allowed only for the calling principal's own resources

### 3.2 Tool Registry

| Operation | `admin` | `agent` | `auditor` | `readonly` |
|-----------|---------|---------|-----------|------------|
| `POST /api/v1/tools` (register) | 201 | 403 | 403 | 403 |
| `GET /api/v1/tools` | 200 | 403 | 200 | 200 (filtered fields) |
| `GET /api/v1/tools/{id}` | 200 | 403 | 200 | 200 (filtered fields) |
| `PATCH /api/v1/tools/{id}` | 200 | 403 | 403 | 403 |
| `DELETE /api/v1/tools/{id}` | 204 | 403 | 403 | 403 |

### 3.3 Tool Audit and SBOM

| Operation | `admin` | `agent` | `auditor` | `readonly` |
|-----------|---------|---------|-----------|------------|
| `GET /api/v1/tools/{id}/audit` | 200 | 403 | 200 | 403 |
| `POST /api/v1/tools/{id}/audit/rerun` | 202 | 403 | 403 | 403 |
| `GET /api/v1/tools/{id}/sbom` | 200 | 403 | 200 | 200 (no signature) |

### 3.4 Tool Invocation

| Operation | `admin` | `agent` | `auditor` | `readonly` | unauthenticated |
|-----------|---------|---------|-----------|------------|-----------------|
| `POST /api/v1/tools/{id}/invoke` (active, granted) | 200 (OPA) | 200 (OPA) | 403 | 403 | 401 |
| `POST /api/v1/tools/{id}/invoke` (quarantined) | 403 TOOL_QUARANTINED | 403 TOOL_QUARANTINED | 403 FORBIDDEN | 403 FORBIDDEN | 401 |
| `POST /api/v1/tools/{id}/invoke` (OPA down) | 503 OPA_UNAVAILABLE | 503 OPA_UNAVAILABLE | 403 | 403 | 401 |
| `POST /api/v1/tools/{id}/invoke` (OPA deny) | 403 OPA_DENY | 403 OPA_DENY | 403 | 403 | 401 |

### 3.5 Policy Management

| Operation | `admin` | `agent` | `auditor` | `readonly` |
|-----------|---------|---------|-----------|------------|
| `GET /api/v1/policy/rules` | 200 | 403 | 200 | 403 |
| `POST /api/v1/policy/evaluate` | 200 | 403 | 403 | 403 |

### 3.6 Compliance

| Operation | `admin` | `agent` | `auditor` | `readonly` |
|-----------|---------|---------|-----------|------------|
| `GET /api/v1/compliance/reports` | 200 | 403 | 200 | 403 |
| `GET /api/v1/compliance/reports/{id}` | 200 | 403 | 200 | 403 |
| `POST /api/v1/compliance/reports/run` | 202 | 403 | 403 | 403 |

### 3.7 Anomaly Detection

| Operation | `admin` | `agent` | `auditor` | `readonly` |
|-----------|---------|---------|-----------|------------|
| `GET /api/v1/anomaly/baselines` | 200 | 403 | 200 | 403 |
| `GET /api/v1/anomaly/alerts` | 200 | 403 | 200 | 403 |
| `PATCH /api/v1/anomaly/alerts/{id}` | 200 | 403 | 403 | 403 |

### 3.8 Audit Log Access

| Operation | `admin` | `agent` | `auditor` | `readonly` |
|-----------|---------|---------|-----------|------------|
| `GET /api/v1/audit/events` | 200 (all) | 200 (Own — filtered to calling client_id) | 200 (all) | 403 |

### 3.9 Health and Auth (Public)

| Operation | `admin` | `agent` | `auditor` | `readonly` | unauthenticated |
|-----------|---------|---------|-----------|------------|-----------------|
| `GET /health` | 200 | 200 | 200 | 200 | 200 |
| `GET /health/ready` | 200 | 200 | 200 | 200 | 200 |
| `GET /api/v1/auth/oidc/login` | 302 | 302 | 302 | 302 | 302 |

---

## 4. Tamper Test Inventory

All tamper tests MUST be labeled `[TAMPER]` in their test name and docstring. They verify rejection at the earliest validation layer.

| ID | Test Name | File | Invariant | What Is Tampered |
|----|-----------|------|-----------|-----------------|
| T-001 | `[TAMPER] test_signature_rejects_tampered_sbom` | `tests/unit/test_sbom.py` | INV-006 | SBOM document field mutated after signing |
| T-002 | `[TAMPER] test_missing_signing_key_raises` | `tests/unit/test_sbom.py` | INV-006 | SBOM_SIGNING_KEY absent — must raise, not silently fail |
| T-003 | `[TAMPER] test_hmac_signature_roundtrip` | `tests/unit/test_sbom.py` | INV-006 | Valid signature verifies; must confirm correct key is used |
| T-004 | `[TAMPER] test_opa_unavailable_returns_503` | `tests/integration/test_invoke.py` | INV-004 | OPA connection refused — proxy must deny, not allow |
| T-005 | `[TAMPER] test_quarantined_tool_returns_403_before_opa` | `tests/integration/test_invoke.py` | INV-005 | Quarantined tool invocation — OPA must never be called |
| T-006 | `[TAMPER] test_unauthenticated_returns_401` | `tests/integration/test_invoke.py` | INV-009 | No auth header — rejected before proxy logic |

Future tamper tests to add (gap items):
- `[TAMPER]` Replayed JWT with expired `exp` claim — must reject 401 (requires OIDC enabled)
- `[TAMPER]` SBOM with detached signature presented at `/tools/{id}/sbom` — must verify before returning
- `[TAMPER]` Audit log event SHA-256 hash mismatch detected by compliance checker
- `[TAMPER]` Policy bundle without valid signature in `ENVIRONMENT=staging` — OPA must reject

---

## 5. Test Data Requirements

### 5.1 Database Seed Fixtures (Integration Tests)

Integration tests operate against a test database populated by `infra/db/migrations/`. The following seed data must be present:

| Fixture | Description | Used By |
|---------|-------------|---------|
| `tool:active-low-risk` | Active tool, risk_level=low, seeded OPA grant for `test-agent-client` | Audit completeness allow-path test |
| `tool:quarantined-critical` | Tool with status=quarantined, risk_level=critical | INV-005 tests, OPA quarantine tests |
| `tool:deprecated` | Tool with status=deprecated | Deprecated tool rejection tests |
| `client:test-agent-client` | Agent-role client with OPA grant for `active-low-risk` tool | Audit completeness, invocation tests |
| `client:test-agent-no-grant` | Agent-role client with NO OPA grants | Deny-path audit completeness test |
| `client:test-admin-client` | Admin-role client | RBAC and invocation testing tests |
| `client:test-auditor-client` | Auditor-role client | RBAC read tests |
| `client:test-readonly-client` | Readonly-role client | RBAC field-filtering tests |

### 5.2 OPA Data Fixtures

OPA `data.mcp.grants` must include test grants in the test environment:

```json
{
  "mcp": {
    "grants": {
      "test-agent-client": {
        "allowed_tools": ["active-low-risk-tool"],
        "max_risk_level": "medium"
      }
    }
  }
}
```

### 5.3 Environment Variables for Tests

Unit tests require a minimal `.env.test` with dummy (non-secret) values:

```
ENVIRONMENT=development
DB_PASSWORD=testpass
REDIS_PASSWORD=testpass
PROXY_SECRET_KEY=test-secret-key-32-chars-minimum!!
API_KEY_HMAC_KEY=test-api-key-hmac-key-32chars!!
SBOM_SIGNING_KEY=test-sbom-signing-key-32chars!!!
AUDIT_LOG_HMAC_KEY=test-audit-hmac-key-32chars!!!!
WEBHOOK_SIGNING_KEY=test-webhook-signing-key-32chars!
MINIO_ROOT_USER=testminio
MINIO_ROOT_PASSWORD=testminiopass
```

---

## 6. Negative Test Requirements

Every endpoint must have these negative tests at minimum:

1. **401 Unauthenticated** — request with no auth header
2. **403 Wrong role** — each forbidden role must be tested (see matrix)
3. **400 Malformed body** — missing required fields, wrong types
4. **404 Not found** — non-existent resource ID
5. **Error envelope shape** — assert `error.code`, `error.message`, `error.request_id`, `error.timestamp` all present

---

## 7. Gap Items and Known Limitations

The following are known gaps in v1 test coverage. Each has a ticket reference.

| Gap | Impact | Status |
|-----|--------|--------|
| OIDC JWT replay / tampered JWT tests | Medium — OIDC not yet enabled | Blocked on OIDC implementation |
| `readonly` field-filtering response tests | Medium — schema omission not yet verified | Requires response schema validation fixture |
| Webhook outbound signature verification E2E | Low — advisory path | Deferred to v2 |
| Policy bundle signing enforcement test (INV-012) | High — staging/prod critical | Blocked on staging env |
| `GET /audit/events` agent cross-client access prevention | High — data isolation | Requires multi-client integration fixture |
| Rate limit boundary tests (429) | Medium | Requires Redis rate limiter implementation |
| MinIO Object Lock verification (INV-007) | High — compliance critical | Infrastructure-level; not in unit scope |

---

## 8. Playwright E2E Coverage Matrix (Future)

No browser UI exists in v1. When a management UI is added, the following journeys must be covered:

| Journey | Roles | Critical Path |
|---------|-------|---------------|
| Login via OIDC, verify role badge displayed | all | Yes |
| Tool registry browse (list + detail view) | admin, auditor, readonly | Yes |
| Tool registration form submission | admin | Yes |
| Tool quarantine status change | admin | Yes |
| Audit event search and filter | admin, auditor | Yes |
| Compliance report view | admin, auditor | Yes |
| Anomaly alert resolution | admin | Yes |
| Access denied screens for forbidden operations | agent, readonly | Yes |

---

*End of Test Plan*
