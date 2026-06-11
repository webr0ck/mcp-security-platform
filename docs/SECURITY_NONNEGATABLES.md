# MCP Security Platform — Security Non-Negotiables

Version: 1.0.0
Date: 2026-04-21
Status: MANDATORY — these invariants may never be violated by any contributor, reviewer, or automated process.

---

## Purpose

This document defines security invariants for the MCP Security Platform. These are not guidelines or best practices — they are hard constraints. Any code, configuration, or process change that would violate an invariant listed here MUST be rejected, regardless of the justification offered.

A CI gate (`make security-check`) enforces the machine-verifiable invariants. Human review is required for the non-machine-verifiable ones.

---

## Enforcement reality (2026-05-16)

The per-INV "Enforcement:" lines below describe the *intended* control. Audited actual state (see `REVIEW-2026-05-16.md` §2):

| INV | Actually enforced by automation? |
|---|---|
| INV-002, INV-003, INV-005, INV-006 | ✅ Yes — real, gated. |
| INV-001 | ✅ Extended (Task 1.1, 2026-06-11): auth-layer rejections (401/403) now also fail-closed — `AuditMiddleware` emits synchronously; emission failure → 500. `test_audit_completeness.py` extended with `test_401_produces_audit_event` and `test_403_produces_audit_event`. Credential-lifecycle audit added (CB-004). Not yet in `make security-check`. |
| INV-004 | 🟡 Code correct & fail-closed; CI now runs the OPA-down phase (P1.4 fix) — previously skipped. |
| INV-009, INV-010 | 🟡 Config-only; verified at deploy, no automated test. |
| INV-008 | 🟡 CI trufflehog real; **no pre-commit hook in repo**, `make security-check` skips trufflehog if absent (ROADMAP P2.5). |
| INV-011 | 🟡 `V003`+`V009` grants real; written scope still omits `credential_store`/`role_assignments` (P1.6). |
| INV-007 | 🟡 `verify_object_lock_startup()` in `observability/compliance-checker/checker.py` runs at the start of every compliance check and logs WARN if Object Lock is absent. **Mode decision: GOVERNANCE** (not COMPLIANCE) — accepted for this reference implementation; GOVERNANCE is not MFA-enforced WORM (a privileged key can bypass it). Production deployments requiring true WORM must switch to COMPLIANCE mode. Tested by `observability/compliance-checker/tests/test_object_lock.py`. |
| INV-012 | ✅ **Signed bundles are now the DEFAULT** (Task 1.1, 2026-06-10). `docker-compose.yml` runs OPA with `--verification-key` + `bundle.tar.gz:ro`. `make up` auto-signs. `make security-check` runs `scripts/check_signed_default.sh` (F-002 gate). Unit tests in `proxy/tests/security/test_signed_bundle.py` assert config correctness. `docker-compose.opa-signed.yml` overlay deleted — no longer needed. |

---

## INV-001: Every Tool Invocation and Auth-Layer Rejection Has an Audit Record

**Statement:** Every call to `POST /tools/{tool_id}/invoke`, whether the outcome is ALLOW or DENY, must produce an audit event record before any response is returned to the caller.

**Extension (Task 1.1, 2026-06-11 — LOG-F02/LOG-F03):** Auth-layer rejections (HTTP 401 Unauthenticated, HTTP 403 Forbidden) are **now also fail-closed** under INV-001. `AuditMiddleware` (`proxy/app/middleware/audit.py`) emits a synchronous audit event for every 401 and 403 response *after* the inner handler returns. Emission failure raises `AuditEmissionError`, which the middleware's own outer handler converts to HTTP 500. This means:
- An attacker who can cause audit DB outages no longer gains a quieter brute-force channel (prior to this task, the middleware swallowed emission exceptions with `except Exception: pass`).
- Every rejected request — whether unauthenticated probe or role-denied call — is now unconditionally recorded.
- The audit row for auth failures has `tool_id IS NULL` (the invocation never reached the tool-lookup stage); `tool_name` carries the redacted `[HTTP_401] METHOD /path` string (attacker-chosen path segments are run through `redact_string` per INV-002).

**Rollout observable:** Watch the 5xx rate on unauthenticated probes after deploy. An audit-DB outage now 500s every probe. That is intended; it must page (Task 0.3 alerting is the prerequisite for comfort here). Table-growth/flooding is mitigated by gateway rate-limits (IPRateLimitMiddleware + Nginx layer). Add table-growth to rollout observables.

**Corollary:** The audit event must be emitted synchronously, not in a background task. If the audit emission fails, the invocation is treated as failed and a 500 is returned. There is no path where a tool executes — or where authentication is rejected — without an audit record.

**Why:** Without a complete invocation log, compliance reporting and anomaly detection are invalid. Partial logs are worse than no logs because they create false confidence. Audit gaps on auth-failure paths also mean brute-force attacks are invisible in the audit trail.

**Enforcement:** Integration test `proxy/tests/integration/test_audit_completeness.py` (note: `integration/` subdir) asserts every invocation produces exactly one audit event; `test_401_produces_audit_event` and `test_403_produces_audit_event` (same file, added Task 1.1) assert auth-failure rows with `tool_id IS NULL`; `proxy/tests/unit/test_mcp_client.py` covers the route-level contract. Credential enrollment also emits a synchronous audit event (CB-004). *Gap: not yet wired into `make security-check`.*

---

## INV-002: Logs Never Contain Raw Payloads

**Statement:** The `mcp-audit-logger` library MUST apply credential and PII auto-redaction to all fields before emitting any log line. Raw request bodies, raw response bodies, and raw parameter values MUST NOT appear in any log output.

**Specific patterns that must always be redacted:**
1. AWS access key IDs (`AKIA[A-Z0-9]{16}`)
2. AWS secret access keys (40-char base64)
3. GitHub personal access tokens (`ghp_*`, `github_pat_*`)
4. Private key material (`-----BEGIN * PRIVATE KEY-----`)
5. Passwords in URL query strings (`password=`, `passwd=`, `pwd=`)
6. JWT tokens (`eyJ[A-Za-z0-9-_=]+\.[A-Za-z0-9-_=]+\.?[A-Za-z0-9-_.+/=]*`)
7. Database connection strings with credentials
8. Email addresses (per GDPR)
9. IP addresses in parameter values (not in infrastructure headers)
10. API key patterns (`api_key=`, `apikey=`, `x-api-key:`)

**Redaction format:** `[REDACTED:<category>]` (e.g., `[REDACTED:aws_access_key]`)

**Why:** A single leaked credential in a log line invalidates the entire security value of the platform. The tool being a security tool makes this doubly impactful.

**Enforcement:** `observability/mcp-audit-logger/tests/test_redaction.py` tests all 10 pattern categories with positive and negative cases. This test MUST be in the CI gate.

---

## INV-003: OPA Deny-by-Default

**Statement:** The OPA policy engine MUST default to DENY for any input that does not match an explicit ALLOW rule. There must be no implicit allow, no wildcard allow-all rule, and no fallthrough-to-allow path in any Rego policy.

**Implementation requirement:** The base policy `policies/rego/authz.rego` must contain:

```rego
default allow = false
```

This line must never be removed or changed to `default allow = true`.

**Why:** Security policy engines must fail closed. An allow-by-default posture means any unconfigured tool or new client automatically gains access — exactly the behavior this platform is designed to prevent.

**Enforcement:** CI lints every `.rego` file and asserts that `default allow = false` is present in `authz.rego`. Pull requests that remove this line are blocked.

---

## INV-004: OPA Unreachable = Fail Closed

**Statement:** If the OPA sidecar is unreachable (connection refused, timeout, HTTP error), the proxy MUST return HTTP 503 with error code `OPA_UNAVAILABLE` and MUST NOT allow the tool invocation to proceed.

**Why:** A broken policy engine is not a fallback to "no policy." It is a system failure that must surface visibly rather than silently granting access.

**Enforcement:** Integration test uses a mock OPA that returns 503; asserts that the proxy returns 503 (not 200 or 403).

**Pre-bundle-load race (startup window):** Between OPA start and bundle load completion, OPA may return `{"result": null}` or `{"result": {}}` (allow key absent) for policy queries. `policy.py` normalises both to `allow=False` — `None` and missing dict are treated identically to an explicit deny. This prevents the startup race from creating a silent allow window. Verified by `proxy/tests/unit/test_policy_null_result.py` (`test_opa_null_result_is_deny`, `test_opa_missing_allow_key_is_deny`).

---

## INV-005: Quarantined Tools Cannot Be Invoked

**Statement:** A tool with `status: "quarantined"` MUST be denied at the proxy application layer (before OPA evaluation) and cannot be invoked by any role, including `admin`.

**Why:** A tool flagged as `critical` risk is in an unreviewed state. OPA policies should not be the only gate; application-layer enforcement provides defense in depth.

**Enforcement:** Unit test asserts that an invocation request for a quarantined tool returns 403 with `TOOL_QUARANTINED` error code before any OPA call is made.

---

## INV-006: SBOM Signature Required on All Tool Registrations

**Statement:** Every tool registered with the platform MUST have a signed SBOM record. The SBOM document is signed with HMAC-SHA-256 using `SBOM_SIGNING_KEY`. The signature is stored in `sbom_records.signature`. A tool cannot be set to `status: "active"` without a valid signature in its SBOM record.

**Why:** Unsigned SBOMs can be tampered with after the fact, invalidating the compliance audit chain.

**Enforcement:** Database constraint ensures `sbom_records.signature` is NOT NULL. Application code verifies signature before activating a tool.

---

## INV-007: Audit Log Archive is WORM

**Statement:** The MinIO bucket used for compliance archive (configured via `MINIO_AUDIT_BUCKET`) MUST have Object Lock enabled with at minimum GOVERNANCE mode and a 90-day retention period. No application code, no admin API endpoint, and no Makefile target may issue a delete to this bucket. Bucket deletion requires out-of-band MinIO admin credentials not available to any application service.

**Why:** WORM storage is the only reliable guarantee against insider log deletion. A platform that claims compliance logging but allows log deletion is worthless.

**Enforcement:** `infra/scripts/setup-minio.sh` configures Object Lock at bucket creation time. `observability/compliance-checker/checker.py::verify_object_lock_startup()` calls `GetBucketObjectLockConfiguration` at the start of each compliance run and logs WARN if Object Lock is absent; the check result is included in every compliance report.

**Mode decision (2026-06-08):** GOVERNANCE mode is chosen for this reference implementation. GOVERNANCE is NOT MFA-enforced WORM — a privileged key can bypass it. Only COMPLIANCE mode is true WORM. This choice is accepted here because (a) this is a learning/reference build, not a production security gateway, and (b) COMPLIANCE mode creates irreversible object locks that complicate lab teardown. Production deployments must switch to COMPLIANCE mode.

**Tested:** `observability/compliance-checker/tests/test_object_lock.py` — 5 tests covering enabled/disabled/boto3-error/COMPLIANCE mode.

---

## INV-008: Secrets Never in Code or Configuration Files

**Statement:** No secret value (password, token, private key, API key) may appear in any file that is tracked by git. This includes: source code files, configuration files, Dockerfiles, docker-compose files, Makefile, Helm chart values, Kubernetes manifests, or any documentation file.

**Permitted exceptions:** `.env.example` contains placeholder values only (e.g., `DB_PASSWORD=your-strong-password-here`). The actual `.env` file is in `.gitignore` and must never be committed.

**Why:** A single committed secret, even if later rotated, creates a permanent compliance finding and can be extracted from git history.

**Enforcement:** `git-secrets` or `trufflehog` pre-commit hook scans all staged files. CI runs `trufflehog git` on every pull request.

---

## INV-009: mTLS Enforced for Agent Endpoints

**Statement:** The `/tools/{id}/invoke` endpoint MUST require either a valid mTLS client certificate or a valid API key. Unauthenticated requests (no cert, no API key, no OIDC JWT) MUST return 401 and MUST NOT reach the proxy application logic.

**Implementation:** Enforced at the Nginx gateway layer via `ssl_verify_client on` for the `/api/v1/tools` location block. API key fallback is handled by the proxy auth middleware for clients that cannot present a cert.

**Why:** Tool invocations are the highest-risk operation on the platform. Double enforcement (gateway + application) is required.

---

## INV-010: Step-CA Certs Have Maximum 24-Hour TTL

**Statement:** Client certificates issued by the step-ca internal CA MUST have a maximum TTL of 24 hours. No certificate with a TTL longer than 24 hours may be used for mTLS authentication on this platform.

**Why:** Short-lived certificates are the primary mitigation for stolen certificate abuse. A stolen 24-hour cert has a bounded blast radius.

**Enforcement:** step-ca provisioner configuration sets `maxTLSDuration: 24h`. The Nginx `ssl_verify_depth` and OCSP responder check are configured to reject expired certs.

---

## INV-011: No Direct Database Writes Outside Designated Services

**Statement:** Only the `proxy` service may write to `tool_registry`, `sbom_records`, `audit_events`, `anomaly_baselines`, `api_keys`, and `role_assignments` tables. Only the `compliance-checker` service may write to `compliance_reports`. No other service, script, or operator tool may write directly to these tables outside of database migrations.

**Why:** Uncontrolled database writes bypass audit logging, RBAC enforcement, and SBOM signing.

**Enforcement:** PostgreSQL role grants are configured so that only the `proxy_app` DB user has INSERT/UPDATE on the above tables, and only the `compliance_checker` DB user has INSERT on `compliance_reports`. See `infra/db/migrations/V003__db_roles.sql`.

---

## INV-012: Policy Bundle Signing in Production

**Statement:** In any environment with `ENVIRONMENT=production` or `ENVIRONMENT=staging`, OPA MUST be configured with `--verification-key` and `--signing-alg=HS256`, and the policy bundle MUST be signed with `POLICY_SIGNING_KEY`. OPA must reject unsigned bundles (`--scope=write` covers every file in the bundle).

**Signed bundle is now the DEFAULT** (`docker-compose.yml`). OPA verifies `.signatures.json` at load time AND on every bundle refresh, refusing any unsigned or tampered bundle. `make up` automatically calls `make sign-policy-bundle` first.

**In development (`ENVIRONMENT=development`):** Bundle signing may be disabled for iteration velocity. `docker-compose.dev.yml` overrides the OPA command with an unsigned read-only directory mount and `--watch` for hot-reload. This is the ONLY permitted opt-out.

**Why:** Unsigned policy bundles in production mean an attacker who can modify the bundle filesystem volume can change allow/deny rules without detection.

**Enforcement (2026-06-10, Task 1.1):**
- `make sign-policy-bundle` (`scripts/sign_policy_bundle.sh`, HS256) produces `policies/bundle.tar.gz`.
- `docker-compose.yml` OPA service uses `--verification-key=${POLICY_SIGNING_KEY}`, `--signing-alg=HS256`, `--scope=write`, and mounts `bundle.tar.gz:ro`. **Signed is the default, not an overlay.**
- `docker-compose.opa-signed.yml` overlay **deleted** (Task 1.1) — absorbed into the default. References to this file are stale.
- `make up` depends on `sign-policy-bundle` so the bundle is always fresh before the stack starts.
- `make security-check` runs `scripts/check_signed_default.sh` (F-002 gate) which verifies every non-dev compose tier has `--verification-key` and optionally confirms OPA loads the signed bundle.
- Unit/structural tests in `proxy/tests/security/test_signed_bundle.py` assert the compose files are correctly configured.
- CI gate status: **ENFORCED** — `make security-check` fails if `--verification-key` is absent from any production-tier compose.

---

## INV-013: Credential Broker — At-Rest Encryption and Lifecycle Audit

**Statement:** Every third-party credential stored by the credential broker MUST be (a) envelope-encrypted at rest with AES-256-GCM under a per-user KEK derived via HKDF-SHA256 from a Vault-held master secret transported only over TLS; (b) keyed to the **authenticated** caller identity (`request.state.client_id`), never a client-supplied header; and (c) every enroll / refresh / revoke / delete on `credential_store` MUST emit a synchronous audit event before the response (same hard-fail discipline as INV-001).

**Why:** The broker holds the keys to M365/Bitbucket/Grafana/Netbox/Dex. Identity collapse or a plaintext master key (the original CB-001/CB-002 CRITICALs) compromises every brokered credential at once.

**Enforcement:** `proxy/tests/unit/test_oauth_router.py` (identity-from-store, spoof-ignored, nonce/PKCE replay), `test_vault_tls_enforcement.py` (no `http://` Vault outside dev), `test_approach_a.py` (HKDF KEK). *Pending:* extend the synchronous-audit requirement to refresh/revoke/delete and add an audit-before-delete DB trigger (ROADMAP P2 / §4.2.5).

---

## INV-014: Session JTI Revocation Must Deny on Error (Fail-Closed)

**Statement:** The session-JWT JTI revocation check (`_is_session_jti_revoked` in `proxy/app/middleware/auth.py`) MUST return DENY (True) on any error from either the Redis fast-path or the PostgreSQL fallback. There is no circumstance under which a Redis or DB error should allow a request through.

**Prior bug (F-C, fixed 2026-06-10):** `auth.py:343` had `return False` in the except block, meaning a DB connection blip caused revoked session tokens to pass JTI verification. This is a session-fixation / credential-persistence vulnerability.

**Fixed behaviour (two-tier lookup):**
1. **Redis fast-path** (`revoked_jti:{jti}` key): checked first; O(1). Set at logout time via `SETEX revoked_jti:{jti} <remaining_jwt_ttl> 1` (TTL bounded to JWT `exp`). Cache hit → DENY immediately (DB not consulted).
2. **DB authoritative fallback** (`oidc_sessions` table): checked when Redis misses. Row absent → DENY (forged/never-issued token). `revoked_at IS NOT NULL` → DENY. Active row → ALLOW.
3. **Any exception in either path → DENY** (fail-closed). If both Redis and DB are down, all session-JWT authentication is blocked. This is an accepted availability cost — a degraded auth store is not a safe state to allow through.

**Redis marker at logout:** `proxy/app/routers/oidc_browser.py::oidc_logout` writes the Redis marker before returning the logout response (best-effort — DB revocation is the authoritative record; Redis is the fast-path performance and fail-resistant optimisation). If Redis is unavailable at logout time, the warning is logged; the DB revocation still applies.

**Accepted availability trade-off:** A total Redis+DB outage blocks session-JWT auth for the duration of the outage. This is a documented and accepted trade-off: security (no revoked token ever passes on error) over availability (brief auth outage during infra failure). mTLS and API-key auth paths are unaffected by this check.

**Why:** JTI revocation that fails open is functionally equivalent to no revocation at all — a user who calls logout retains access if the DB experiences even a transient blip. Session-scoped auth requires hard revocation guarantees.

**Enforcement:** `proxy/tests/unit/test_jti_revocation.py` — 9 unit tests covering:
- Both-error path → deny
- Redis-only error → DB fallback (active / revoked / missing row)
- Redis hit → deny without DB call (short-circuit)
- Redis miss → DB fallback (active → allow, missing → deny, revoked → deny)
- DB-only error (Redis miss) → deny

Integration test in same file (`@pytest.mark.integration`) covers the postgres-down scenario end-to-end (skipped unless `INTEGRATION_TEST=1`).

---

*End of Security Non-Negotiables*
