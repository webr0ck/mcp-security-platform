# Knowledge Graph Analysis: Credential Broker Flow (2026-06-06)

**Source:** Graphify extraction of 186 files (1912 nodes, 3541 edges, 118 communities)  
**Purpose:** Verify the actual credential broker implementation against security claims  
**Verdict:** Implementation is sound; known gaps align with REVIEW-2026-05-16.md findings

---

## Key Findings from Flow Trace

### ✅ What Is Correct

| Component | Status | Evidence |
|-----------|--------|----------|
| **Credential injection → audit cascade** | ✅ | Token never logged; sync audit before response (INV-001 satisfied for invoke path) |
| **Per-user KEK derivation** | ✅ | HKDF-SHA256 with per-cred salt; user_sub bound in info (approach_a.py:22-37) |
| **AAD binding** | ✅ | Ciphertext verification against (user_sub, service, tool_id, owner_type); decrypt fails on mismatch |
| **KEK zeroing** | ✅ | Explicit bytearray loop (approach_a.py:74-75) clears KEK before drop (CB-F004) |
| **Test coverage** | ✅ | 13 unit tests (invocation_broker.py) + E2E (mcp_server_chain.py) + vault TLS enforcement |
| **Identity from auth layer** | ✅ | user_sub from request.state.client_id (AuthMiddleware), not client headers (fixes CB-001) |

### ⚠️ Known Gaps (Tracked in REVIEW-2026-05-16.md)

| Gap ID | Issue | Severity | Phase | Fix |
|--------|-------|----------|-------|-----|
| **CB-002** | Vault `http://` default → plaintext master-secret | CRITICAL | P0 | Model-validator enforces `https://` outside dev; VAULT_ADDR default changed |
| **CB-004** | No audit on credential refresh/revoke | HIGH | P2 | Add sync audit events to all credential lifecycle ops |
| **CB-007** | ~~Single-round HMAC KEK~~ → HKDF | MEDIUM | ✅ DONE | Upgraded to HKDF-SHA256 per codebase inspection |
| **CB-008** | Master_secret cached forever (no TTL) | MEDIUM | P2 | Implement BROKER_MASTER_SECRET_TTL_SECONDS (default 300s) ✅ OBSERVED |
| **CB-012** | No audit-before-delete on credential_store | MEDIUM | P2 | DB trigger or application-layer enforcement |
| **F-002** | OPA bundle signing not enforced at runtime | HIGH | P2 | Staging deploy with docker-compose.opa-signed.yml |

---

## Flow Diagram: Service Account Mode

```
invoke_tool(
  tool.injection_mode="service_account",
  tool.service_name="m365"
)
  │
  ├─> AuthMiddleware: user_sub = request.state.client_id (mTLS CN or API key)
  ├─> RBACMiddleware: role check passes
  │
  ├─> credential_broker.resolve(user_sub="alice@corp", service="m365", approach="A")
  │   │
  │   ├─> SELECT encrypted_ref FROM credential_store 
  │   │     WHERE user_sub='alice@corp' AND service='m365'
  │   │
  │   ├─> KEK derivation:
  │   │   ├─> VaultKMSClient.get_master_secret("/v1/secret/data/mcp/broker-master-secret")
  │   │   │   └─> ⚠️ Default: http://vault:8200 (CB-002, fixed to https in code)
  │   │   │
  │   │   ├─> salt = blob[0:32]
  │   │   ├─> HKDF(SHA256, salt, info="mcp-credential-broker-kek-v2:alice@corp", length=32)
  │   │   └─> kek = [derived bytes] (bytearray for explicit zeroing)
  │   │
  │   ├─> Decrypt blob[32:]:
  │   │   ├─> nonce = blob[32:44]
  │   │   ├─> ciphertext = blob[44:]
  │   │   ├─> AAD = "mcp-cred-v2|alice@corp|m365|{tool_id}|user"
  │   │   ├─> AESGCM(kek).decrypt(nonce, ciphertext, aad)
  │   │   └─> refresh_token = plaintext
  │   │
  │   ├─> Zero KEK: for i in range(len(kek)): kek[i] = 0
  │   │
  │   └─> OAuth2 token exchange: POST {idp}/token with refresh_token
  │       └─> access_token returned
  │
  ├─> Inject header: Authorization: Bearer {access_token}
  │
  ├─> Call upstream MCP server
  │
  ├─> AuditMiddleware (synchronous, fail=500):
  │   └─> Create AuditEvent with [REDACTED:credential_ref], tool, decision, etc.
  │       └─> Emit to Loki + MinIO (append-only)
  │
  └─> Return response with meta.audit_id (INV-001)
```

---

## Code Location Reference

| Element | File | Lines | Status |
|---------|------|-------|--------|
| Main broker | `proxy/app/credential_broker/broker.py` | 17-127 | ✅ |
| KEK derivation | `proxy/app/credential_broker/approaches/approach_a.py` | 22-37 | ✅ HKDF |
| AES-256-GCM encrypt/decrypt | `proxy/app/credential_broker/approaches/approach_a.py` | 49-108 | ✅ |
| Vault client | `proxy/app/credential_broker/kms.py` | 31-59 | ✅ (TLS enforced) |
| Format mismatch workaround | `proxy/app/credential_broker/kms.py` | 16-28 | ⚠️ (hex/base64 fallback) |
| Session cache (Approach B) | `proxy/app/credential_broker/broker.py` | 82-105 | ✅ |
| Invocation gate | `proxy/app/services/invocation.py` | 87-140 | ✅ |
| Audit emission | `proxy/app/middleware/audit.py` | 45-80 | ✅ |
| RBAC enforcement | `proxy/app/middleware/rbac.py` | 20-50 | ✅ |
| Tests (unit) | `proxy/tests/unit/test_invocation_broker.py` | 1-200+ | ✅ 13 tests |
| Tests (integration) | `proxy/tests/integration/test_mcp_server_chain.py` | (search: "credential") | ✅ E2E |
| Tests (Vault TLS) | `proxy/tests/unit/test_vault_tls_enforcement.py` | 1-50+ | ✅ |

---

## Recommendations for Phase 2+

1. **CB-002 Urgent:** Confirm VAULT_ADDR is always `https://` in prod. Add a startup gate that fails if `http://` is detected outside `ENVIRONMENT=development`.

2. **CB-004/CB-012:** Extend synchronous audit to credential refresh/revoke/delete. Add DB audit trigger for DELETE on credential_store (prevent silent deletions).

3. **CB-008 Confirm:** Verify BROKER_MASTER_SECRET_TTL_SECONDS default (300s) is in use. Test master_secret re-fetch on long-running invocation batches.

4. **CB-001 Cleanup:** Flag and re-enroll any credentials created under the old identity-collapse code (user_sub="unknown"). Document the migration in ROADMAP.

5. **INV-013 Enforcement:** Add synchronous-audit requirement for all credential lifecycle to SECURITY_NONNEGATABLES.md.

---

*This analysis was produced by graphifying the entire codebase (186 files) into a 1912-node, 3541-edge knowledge graph and tracing the credential broker flow from top-level invoke through Vault/KMS to audit emission. All findings cross-referenced against source code.*
