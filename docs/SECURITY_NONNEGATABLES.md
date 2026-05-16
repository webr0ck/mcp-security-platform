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
| INV-001 | ✅ Test exists & is thorough, but at `proxy/tests/integration/test_audit_completeness.py` (not the path quoted below) and is **not** in `make security-check`. Credential-lifecycle audit added (CB-004). |
| INV-004 | 🟡 Code correct & fail-closed; CI now runs the OPA-down phase (P1.4 fix) — previously skipped. |
| INV-009, INV-010 | 🟡 Config-only; verified at deploy, no automated test. |
| INV-008 | 🟡 CI trufflehog real; **no pre-commit hook in repo**, `make security-check` skips trufflehog if absent (ROADMAP P2.5). |
| INV-011 | 🟡 `V003`+`V009` grants real; written scope still omits `credential_store`/`role_assignments` (P1.6). |
| INV-007 | ⚠️ Object Lock is configured, but the "compliance checker verifies on startup" claim below is **aspirational — no such startup check exists**. GOVERNANCE mode is **not** MFA-enforced WORM (a privileged key can still delete). Decide GOVERNANCE→COMPLIANCE or downgrade the guarantee (ROADMAP P2.4). |
| INV-012 | 🟡 Signing mechanism now delivered (`scripts/sign_policy_bundle.sh` + `docker-compose.opa-signed.yml`); **not yet enforced in a running staging deploy** (ROADMAP P2.8). |

---

## INV-001: Every Tool Invocation Has an Audit Record

**Statement:** Every call to `POST /tools/{tool_id}/invoke`, whether the outcome is ALLOW or DENY, must produce an audit event record before any response is returned to the caller.

**Corollary:** The audit event must be emitted synchronously, not in a background task. If the audit emission fails, the invocation is treated as failed and a 500 is returned. There is no path where a tool executes and no audit record is produced.

**Why:** Without a complete invocation log, compliance reporting and anomaly detection are invalid. Partial logs are worse than no logs because they create false confidence.

**Enforcement:** Integration test `proxy/tests/integration/test_audit_completeness.py` (note: `integration/` subdir) asserts every invocation produces exactly one audit event; `proxy/tests/unit/test_mcp_client.py` covers the route-level contract. Credential enrollment also emits a synchronous audit event (CB-004). *Gap: not yet wired into `make security-check`.*

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

**Enforcement:** `infra/scripts/setup-minio.sh` configures Object Lock at bucket creation time. ⚠️ **Correction (2026-05-16):** there is currently **no** compliance-checker startup verification of Object Lock — that is aspirational (ROADMAP P2.4). Also, GOVERNANCE mode does **not** require MFA to delete (a privileged key can bypass it); only COMPLIANCE mode is true WORM. Either move to COMPLIANCE mode or downgrade this guarantee in the docs.

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

**Statement:** In any environment with `ENVIRONMENT=production` or `ENVIRONMENT=staging`, OPA MUST be configured with `bundle.signing.keyid` and `bundle.signing.algorithm` set, and the policy bundle MUST be signed with `POLICY_SIGNING_KEY`. OPA must reject unsigned bundles via `bundle.signing.scope = "all_files"`.

**In development (`ENVIRONMENT=development`):** Bundle signing may be disabled for iteration velocity.

**Why:** Unsigned policy bundles in production mean an attacker who can modify the bundle filesystem volume can change allow/deny rules without detection.

**Enforcement (2026-05-16):** Mechanism delivered — `make sign-policy-bundle` (`scripts/sign_policy_bundle.sh`, HS256, `scope=write`) + the `docker-compose.opa-signed.yml` overlay (OPA started with `--verification-key`, refuses unsigned/tampered bundles at load and on refresh). Dev keeps the read-only directory mount (permitted above). **Pending:** prove it in a running staging deploy and add a CI gate (ROADMAP P2.8).

---

## INV-013: Credential Broker — At-Rest Encryption and Lifecycle Audit

**Statement:** Every third-party credential stored by the credential broker MUST be (a) envelope-encrypted at rest with AES-256-GCM under a per-user KEK derived via HKDF-SHA256 from a Vault-held master secret transported only over TLS; (b) keyed to the **authenticated** caller identity (`request.state.client_id`), never a client-supplied header; and (c) every enroll / refresh / revoke / delete on `credential_store` MUST emit a synchronous audit event before the response (same hard-fail discipline as INV-001).

**Why:** The broker holds the keys to M365/Bitbucket/Grafana/Netbox/Dex. Identity collapse or a plaintext master key (the original CB-001/CB-002 CRITICALs) compromises every brokered credential at once.

**Enforcement:** `proxy/tests/unit/test_oauth_router.py` (identity-from-store, spoof-ignored, nonce/PKCE replay), `test_vault_tls_enforcement.py` (no `http://` Vault outside dev), `test_approach_a.py` (HKDF KEK). *Pending:* extend the synchronous-audit requirement to refresh/revoke/delete and add an audit-before-delete DB trigger (ROADMAP P2 / §4.2.5).

---

*End of Security Non-Negotiables*
