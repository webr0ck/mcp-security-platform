# MCP Security Platform — REST API Specification

Version: v1
Base URL: `https://<host>/api/v1`
Content-Type: `application/json` (all requests and responses)
Authentication: See Section 2.

---

## 1. Conventions

### 1.1 Versioning

All endpoints are prefixed with `/api/v1`. Breaking changes increment the version segment. Additive changes (new optional fields, new endpoints) are non-breaking and do not increment the version.

### 1.2 Authentication

Every request must include one of:

| Method | Header | Notes |
|--------|--------|-------|
| mTLS | Client certificate (TLS layer) | Gateway extracts CN; proxy receives `X-Client-Cert-CN` |
| API key | `Authorization: Bearer <api_key>` | Used when mTLS is not feasible |
| OIDC JWT | `Authorization: Bearer <jwt>` | For human-user flows via browser/OIDC |

The proxy resolves the caller identity in priority order: mTLS cert CN > OIDC JWT > API key. Requests with no resolvable identity return `401 Unauthorized`.

### 1.3 Standard Error Envelope

All error responses use this envelope:

```json
{
  "error": {
    "code": "TOOL_NOT_FOUND",
    "message": "No tool with id 'abc123' exists in the registry.",
    "request_id": "req_01HZ...",
    "timestamp": "2026-04-21T10:00:00Z"
  }
}
```

| Field | Type | Description |
|-------|------|-------------|
| `code` | string | Machine-readable error code (snake_case, uppercase) |
| `message` | string | Human-readable description |
| `request_id` | string | Trace ID for log correlation |
| `timestamp` | string (ISO 8601) | Error timestamp UTC |

### 1.4 Error Codes Reference

| HTTP Status | Error Code | Meaning |
|-------------|-----------|---------|
| 400 | `VALIDATION_ERROR` | Request body failed Pydantic validation |
| 401 | `UNAUTHENTICATED` | No valid identity could be resolved |
| 403 | `FORBIDDEN` | Identity resolved but lacks required permission |
| 403 | `OPA_DENY` | OPA policy explicitly denied the operation |
| 404 | `NOT_FOUND` | Resource does not exist |
| 409 | `CONFLICT` | Resource already exists (duplicate registration) |
| 422 | `SCHEMA_INVALID` | Tool schema semantically invalid (not Pydantic — business logic rejection) |
| 429 | `RATE_LIMITED` | Rate limit exceeded; `Retry-After` header present |
| 500 | `INTERNAL_ERROR` | Unhandled server error; check logs |
| 503 | `OPA_UNAVAILABLE` | OPA sidecar unreachable; fail-closed (deny all) |

### 1.5 Pagination

List endpoints accept:

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `page` | int | 1 | 1-indexed page number |
| `page_size` | int | 50 | Max 200 |

Paginated responses include:

```json
{
  "data": [...],
  "pagination": {
    "page": 1,
    "page_size": 50,
    "total_items": 342,
    "total_pages": 7
  }
}
```

### 1.6 Rate Limiting

Rate limit headers on every response:

```
X-RateLimit-Limit: 100
X-RateLimit-Remaining: 87
X-RateLimit-Reset: 1714000060
```

Default limits (configurable per role via `RATE_LIMIT_*` env vars):

| Role | Requests / minute |
|------|-----------------:|
| `admin` | 300 |
| `agent` | 120 |
| `auditor` | 60 |
| `readonly` | 30 |

---

## 2. Endpoints

---

### 2.1 Health and Status

#### `GET /health`

Public endpoint (no authentication required). Returns system liveness.

**Response 200**

```json
{
  "status": "ok",
  "version": "1.0.0",
  "timestamp": "2026-04-21T10:00:00Z",
  "services": {
    "database": "ok",
    "redis": "ok",
    "opa": "ok",
    "ollama": "ok"
  }
}
```

If any dependency is unhealthy, `status` is `"degraded"` and the affected service shows `"error"`.

**Response 503** — All dependencies down; returns same shape with `status: "error"`.

---

#### `GET /health/ready`

Kubernetes readiness probe. Returns `200` only if the proxy is fully initialized and all required dependencies (`database`, `redis`, `opa`) are reachable. `ollama` failure does not block readiness (advisory service).

**Response 200**

```json
{
  "ready": true
}
```

**Response 503**

```json
{
  "ready": false,
  "reason": "database unreachable"
}
```

---

### 2.2 Tool Registry

#### `POST /tools/register`

Register a new MCP tool with the platform. Triggers Tool Manifest Auditor and SBOM generation.

**Required Role:** `admin`

**Request Body**

```json
{
  "name": "file_reader",
  "version": "1.2.0",
  "description": "Reads files from the local filesystem.",
  "schema": {
    "type": "object",
    "properties": {
      "path": {
        "type": "string",
        "description": "Absolute file path to read."
      }
    },
    "required": ["path"]
  },
  "source_repo": "https://github.com/example/mcp-tools",
  "source_commit": "a1b2c3d4e5f6...",
  "upstream_url": "http://mcp-server:5000/tools/file_reader",
  "tags": ["filesystem", "read"],
  "metadata": {}
}
```

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `name` | string | Yes | Tool identifier, lowercase, hyphen-separated, max 64 chars |
| `version` | string | Yes | Semver (e.g., `1.2.0`) |
| `description` | string | Yes | Human description; scanned for injection patterns |
| `schema` | object | Yes | JSON Schema defining tool call parameters |
| `source_repo` | string | No | Source repository URL |
| `source_commit` | string | No | Git commit SHA (full 40 chars preferred) |
| `upstream_url` | string | Yes | URL the proxy forwards matching tool calls to |
| `tags` | string[] | No | Taxonomy tags for grouping |
| `metadata` | object | No | Arbitrary key-value metadata; stored as JSONB |

**Response 201**

```json
{
  "tool_id": "550e8400-e29b-41d4-a716-446655440000",
  "name": "file_reader",
  "version": "1.2.0",
  "status": "active",
  "risk_score": 72,
  "risk_level": "high",
  "risk_reasons": [
    "Parameter 'path' allows filesystem traversal with no apparent scope restriction.",
    "Tool description does not mention sandboxing."
  ],
  "sbom_ref": "sbom_01HZ...",
  "sbom_signature": "hmac-sha256:a3f8...",
  "registered_at": "2026-04-21T10:00:00Z",
  "registered_by": "admin@example.com"
}
```

If `risk_level` is `"critical"`, the tool is registered with `status: "quarantined"` and cannot be invoked until an admin sets `status: "active"`. A Jira issue is created if `JIRA_ENABLED=true`.

**Response 409** — Tool with same `name` + `version` already exists.

---

#### `GET /tools`

List registered tools.

**Required Role:** `admin`, `auditor`, `readonly`

**Query Parameters**

| Parameter | Type | Description |
|-----------|------|-------------|
| `status` | string | Filter by status: `active`, `quarantined`, `deprecated` |
| `risk_level` | string | Filter by risk level: `low`, `medium`, `high`, `critical` |
| `tag` | string | Filter by tag (repeatable: `?tag=filesystem&tag=read`) |
| `page` | int | Pagination |
| `page_size` | int | Pagination |

**Response 200**

```json
{
  "data": [
    {
      "tool_id": "550e8400-...",
      "name": "file_reader",
      "version": "1.2.0",
      "status": "active",
      "risk_score": 72,
      "risk_level": "high",
      "tags": ["filesystem", "read"],
      "registered_at": "2026-04-21T10:00:00Z"
    }
  ],
  "pagination": {
    "page": 1,
    "page_size": 50,
    "total_items": 12,
    "total_pages": 1
  }
}
```

---

#### `GET /tools/{tool_id}`

Retrieve full tool record including schema and SBOM reference.

**Required Role:** `admin`, `auditor`, `readonly`, `agent` (agents may read tools they are authorized to invoke)

**Path Parameters**

| Parameter | Type | Description |
|-----------|------|-------------|
| `tool_id` | UUID | Tool identifier |

**Response 200**

```json
{
  "tool_id": "550e8400-...",
  "name": "file_reader",
  "version": "1.2.0",
  "description": "Reads files from the local filesystem.",
  "schema": { "...": "..." },
  "status": "active",
  "risk_score": 72,
  "risk_level": "high",
  "risk_reasons": ["..."],
  "source_repo": "https://github.com/example/mcp-tools",
  "source_commit": "a1b2c3d4...",
  "upstream_url": "http://mcp-server:5000/tools/file_reader",
  "tags": ["filesystem", "read"],
  "metadata": {},
  "sbom_ref": "sbom_01HZ...",
  "sbom_signature": "hmac-sha256:a3f8...",
  "registered_at": "2026-04-21T10:00:00Z",
  "registered_by": "admin@example.com",
  "updated_at": "2026-04-21T10:00:00Z"
}
```

**Response 404** — Tool not found.

---

#### `PATCH /tools/{tool_id}`

Update tool status or metadata. Cannot change `name`, `version`, or `schema` (create a new version instead).

**Required Role:** `admin`

**Request Body**

```json
{
  "status": "active",
  "metadata": {
    "approved_by": "security-team",
    "approval_date": "2026-04-21"
  }
}
```

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `status` | string | No | `active`, `quarantined`, `deprecated` |
| `metadata` | object | No | Merged (not replaced) with existing metadata |

**Response 200** — Returns updated tool record (same shape as `GET /tools/{tool_id}`).

---

#### `DELETE /tools/{tool_id}`

Soft-delete a tool (sets `status: "deprecated"`, `deleted_at` timestamp). Does not remove from registry; historical audit references remain valid.

**Required Role:** `admin`

**Response 204** — No content.

---

### 2.3 Tool Audit

#### `GET /tools/{tool_id}/audit`

Retrieve the full Tool Manifest Auditor result for a registered tool.

**Required Role:** `admin`, `auditor`

**Response 200**

```json
{
  "tool_id": "550e8400-...",
  "audit_id": "aud_01HZ...",
  "audited_at": "2026-04-21T10:00:00Z",
  "auditor_version": "1.0.0",
  "risk_score": 72,
  "risk_level": "high",
  "findings": [
    {
      "finding_id": "f_001",
      "category": "parameter_scope",
      "severity": "high",
      "description": "Parameter 'path' allows filesystem traversal.",
      "parameter_name": "path",
      "evidence": "No path restriction pattern in schema.",
      "recommendation": "Add pattern constraint or enum to limit scope."
    },
    {
      "finding_id": "f_002",
      "category": "description_injection",
      "severity": "low",
      "description": "Description uses imperative language that may confuse LLM context.",
      "evidence": "Description: 'Always read the file at the given path.'",
      "recommendation": "Use neutral descriptive language."
    }
  ],
  "llm_analysis": {
    "model": "llama3.2",
    "prompt_injection_detected": false,
    "excessive_scope_detected": true,
    "suspicious_parameter_names": [],
    "summary": "Tool has broad filesystem access with no apparent scope restriction."
  },
  "static_analysis": {
    "injection_patterns_matched": [],
    "excessive_permissions_patterns_matched": ["filesystem_unrestricted"],
    "suspicious_name_patterns_matched": []
  }
}
```

---

#### `POST /tools/{tool_id}/audit/rerun`

Re-run the Tool Manifest Auditor on an existing tool (e.g., after Ollama model update).

**Required Role:** `admin`

**Response 202**

```json
{
  "audit_job_id": "job_01HZ...",
  "status": "queued",
  "estimated_seconds": 15
}
```

---

#### `GET /tools/{tool_id}/sbom`

Retrieve the CycloneDX SBOM for a registered tool.

**Required Role:** `admin`, `auditor`, `readonly`

**Query Parameters**

| Parameter | Type | Description |
|-----------|------|-------------|
| `format` | string | `cyclonedx` (default) or `spdx` |

**Response 200** — Returns the SBOM document as JSON. Content-Type: `application/vnd.cyclonedx+json` or `application/spdx+json`.

```json
{
  "bomFormat": "CycloneDX",
  "specVersion": "1.5",
  "version": 1,
  "serialNumber": "urn:uuid:550e8400-...",
  "metadata": {
    "timestamp": "2026-04-21T10:00:00Z",
    "tools": [{ "name": "mcp-security-platform", "version": "1.0.0" }]
  },
  "components": [
    {
      "type": "library",
      "bom-ref": "sbom_01HZ...",
      "name": "file_reader",
      "version": "1.2.0",
      "purl": "pkg:mcp/file_reader@1.2.0",
      "hashes": [{ "alg": "SHA-256", "content": "a3f8..." }],
      "externalReferences": [
        {
          "type": "vcs",
          "url": "https://github.com/example/mcp-tools",
          "comment": "Source repository"
        }
      ],
      "properties": [
        { "name": "mcp:risk_score", "value": "72" },
        { "name": "mcp:risk_level", "value": "high" },
        { "name": "mcp:audit_timestamp", "value": "2026-04-21T10:00:00Z" }
      ]
    }
  ],
  "signature": {
    "algorithm": "HMAC-SHA256",
    "value": "a3f8c9d2..."
  }
}
```

---

### 2.4 Tool Invocation

#### `POST /tools/{tool_id}/invoke`

Invoke a registered MCP tool. This is the primary MCP JSON-RPC proxy endpoint.

**Required Role:** `agent` (or `admin` for testing)

**Request Body** — MCP JSON-RPC 2.0 format

```json
{
  "jsonrpc": "2.0",
  "id": "req-123",
  "method": "tools/call",
  "params": {
    "name": "file_reader",
    "arguments": {
      "path": "/tmp/output.txt"
    }
  }
}
```

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `jsonrpc` | string | Yes | Must be `"2.0"` |
| `id` | string or int | Yes | Client-assigned request ID for correlation |
| `method` | string | Yes | Must be `"tools/call"` |
| `params.name` | string | Yes | Tool name (must match registered tool) |
| `params.arguments` | object | Yes | Tool-specific arguments, validated against tool schema |

**Response 200** — Upstream MCP server response, proxied verbatim (with redaction applied):

```json
{
  "jsonrpc": "2.0",
  "id": "req-123",
  "result": {
    "content": [
      {
        "type": "text",
        "text": "File contents here."
      }
    ]
  },
  "meta": {
    "audit_id": "evt_01HZ...",
    "latency_ms": 43
  }
}
```

**Response 403** — OPA denied the invocation:

```json
{
  "jsonrpc": "2.0",
  "id": "req-123",
  "error": {
    "code": -32603,
    "message": "Tool invocation denied by policy.",
    "data": {
      "opa_reasons": ["client not authorized for filesystem tools"],
      "audit_id": "evt_01HZ..."
    }
  }
}
```

**Response 429** — Rate limited; `Retry-After` header present.

---

### 2.5 Policy Management

#### `GET /policy/rules`

List currently loaded OPA policy rules (metadata only, not Rego source).

**Required Role:** `admin`, `auditor`

**Response 200**

```json
{
  "data": [
    {
      "rule_id": "rule_filesystem_agent_allow",
      "package": "mcp.authz",
      "description": "Allow agents in the 'filesystem-readers' group to invoke filesystem tools.",
      "enabled": true,
      "last_loaded_at": "2026-04-21T10:00:00Z"
    }
  ],
  "pagination": { "...": "..." }
}
```

---

#### `POST /policy/evaluate`

Manually evaluate a policy decision (for testing and debugging).

**Required Role:** `admin`

**Request Body**

```json
{
  "input": {
    "client_id": "agent-001",
    "client_roles": ["agent"],
    "tool_name": "file_reader",
    "tool_risk_level": "high",
    "params": {
      "path": "/tmp/output.txt"
    }
  }
}
```

**Response 200**

```json
{
  "allow": false,
  "reasons": [
    "Rule 'deny_high_risk_without_explicit_grant' matched: client 'agent-001' lacks explicit grant for risk_level=high tools."
  ],
  "evaluated_at": "2026-04-21T10:00:00Z",
  "opa_decision_id": "dec_01HZ..."
}
```

---

### 2.6 Compliance and Reporting

#### `GET /compliance/reports`

List compliance report runs.

**Required Role:** `admin`, `auditor`

**Query Parameters**

| Parameter | Type | Description |
|-----------|------|-------------|
| `status` | string | `pass`, `fail`, `in_progress` |
| `from` | ISO 8601 date | Start of date range |
| `to` | ISO 8601 date | End of date range |
| `page` | int | Pagination |

**Response 200**

```json
{
  "data": [
    {
      "report_id": "rpt_01HZ...",
      "run_at": "2026-04-21T02:00:00Z",
      "status": "pass",
      "sample_size": 1000,
      "categories_checked": 10,
      "categories_failed": 0,
      "archive_url": "s3://mcp-audit-archive/compliance/2026-04-21/report.json"
    }
  ],
  "pagination": { "...": "..." }
}
```

---

#### `GET /compliance/reports/{report_id}`

Retrieve full compliance report.

**Required Role:** `admin`, `auditor`

**Response 200**

```json
{
  "report_id": "rpt_01HZ...",
  "run_at": "2026-04-21T02:00:00Z",
  "status": "pass",
  "sample_size": 1000,
  "period_start": "2026-04-20T02:00:00Z",
  "period_end": "2026-04-21T02:00:00Z",
  "categories": [
    {
      "category": "pii_email",
      "description": "Checks for unredacted email addresses in log fields.",
      "events_checked": 1000,
      "violations_found": 0,
      "status": "pass"
    },
    {
      "category": "credential_aws_secret",
      "description": "Checks for AWS secret key patterns in log fields.",
      "events_checked": 1000,
      "violations_found": 0,
      "status": "pass"
    }
  ],
  "hash_integrity": {
    "events_checked": 1000,
    "hash_mismatches": 0,
    "status": "pass"
  },
  "archive_url": "s3://mcp-audit-archive/compliance/2026-04-21/report.json"
}
```

---

#### `POST /compliance/reports/run`

Trigger an on-demand compliance report run (does not replace scheduled daily run).

**Required Role:** `admin`

**Request Body**

```json
{
  "sample_size": 500,
  "period_hours": 24
}
```

**Response 202**

```json
{
  "job_id": "job_01HZ...",
  "status": "queued",
  "estimated_seconds": 120
}
```

---

### 2.7 Anomaly Detection

#### `GET /anomaly/baselines`

List anomaly baselines for all clients.

**Required Role:** `admin`, `auditor`

**Response 200**

```json
{
  "data": [
    {
      "client_id": "agent-001",
      "baseline_version": 12,
      "tools_in_baseline": ["web_search", "file_reader"],
      "sequence_patterns": 3,
      "last_updated": "2026-04-21T09:55:00Z",
      "anomaly_score_threshold": 0.85
    }
  ],
  "pagination": { "...": "..." }
}
```

---

#### `GET /anomaly/alerts`

List anomaly alerts.

**Required Role:** `admin`, `auditor`

**Query Parameters**

| Parameter | Type | Description |
|-----------|------|-------------|
| `client_id` | string | Filter by client |
| `resolved` | bool | `true` to include resolved; default `false` |
| `from` | ISO 8601 | Date range start |
| `page` | int | Pagination |

**Response 200**

```json
{
  "data": [
    {
      "alert_id": "alr_01HZ...",
      "client_id": "agent-001",
      "detected_at": "2026-04-21T10:05:00Z",
      "anomaly_score": 0.93,
      "pattern": "web_search → bulk_file_read",
      "description": "Potential exfiltration chain: 3 web_search calls followed by 12 file_reader calls in 45 seconds.",
      "invocation_ids": ["evt_01...", "evt_02..."],
      "resolved": false,
      "resolved_at": null,
      "resolved_by": null
    }
  ],
  "pagination": { "...": "..." }
}
```

---

#### `PATCH /anomaly/alerts/{alert_id}`

Resolve or annotate an anomaly alert.

**Required Role:** `admin`

**Request Body**

```json
{
  "resolved": true,
  "resolution_note": "Verified legitimate bulk export by agent-001 for authorized task."
}
```

**Response 200** — Returns updated alert record.

---

### 2.8 Audit Log Access

#### `GET /audit/events`

Query the audit event index. Returns metadata; full event content is in Loki.

**Required Role:** `admin`, `auditor`

**Query Parameters**

| Parameter | Type | Description |
|-----------|------|-------------|
| `client_id` | string | Filter by client |
| `tool_name` | string | Filter by tool |
| `outcome` | string | `allow`, `deny` |
| `from` | ISO 8601 | Date range start |
| `to` | ISO 8601 | Date range end |
| `page` | int | Pagination |

**Response 200**

```json
{
  "data": [
    {
      "event_id": "evt_01HZ...",
      "timestamp": "2026-04-21T10:00:00Z",
      "client_id": "agent-001",
      "tool_name": "file_reader",
      "tool_id": "550e8400-...",
      "outcome": "allow",
      "latency_ms": 43,
      "sha256_hash": "a3f8c9d2...",
      "anomaly_score": 0.12
    }
  ],
  "pagination": { "...": "..." }
}
```

---

### 2.9 Authentication (OIDC) — ⛔ NOT BUILT (Planned)

> **Status: stub.** `GET /auth/oidc/login` and `GET /auth/oidc/callback` currently return **HTTP 501 "not yet implemented"** (`proxy/app/routers/auth.py`). The `oidc_role_mappings` table exists but no code consumes it. Treat this section as forward design, not a contract. Tracked: ROADMAP Phase 3.

`GET /auth/oidc/login` *(planned — 501 today)* — initiate OIDC auth-code flow.
`GET /auth/oidc/callback` *(planned — 501 today)* — exchange code, resolve roles. Planned body: `{ "access_token": "eyJ...", "token_type": "bearer", "expires_in": 3600, "roles": ["auditor"] }`.

---

### 2.9b Credential Broker — OAuth Enrollment ✅ (implemented)

Lets an authenticated caller link a third-party account (M365 / Bitbucket / Dex) so the proxy can inject a brokered credential into upstream tool calls. Refresh tokens are envelope-encrypted at rest (SECURITY_NONNEGATABLES **INV-013**).

#### `GET /auth/enroll/{service}`

`service` ∈ `m365` | `bitbucket` | `dex`.

**Authentication: required** (mTLS CN / API key, resolved by `AuthMiddleware`). The enrolled identity is the *authenticated* `client_id`, **never** a request header (CB-001).

**Behaviour:** mints a single-use server-side nonce in Redis (TTL 300 s) + PKCE S256 challenge, then **302** to the IdP authorize URL with `state=<nonce>`. **Errors:** `401` unauthenticated, `404` unknown/non-OAuth service.

#### `GET /auth/callback/{service}?code=&state=`

**Authentication:** public path (browser redirect from the IdP). Identity is **not** read from any header — it is recovered from the single-use nonce minted at enroll and consumed atomically (replay → `400`).

**Behaviour:** exchanges `code` (+ PKCE verifier) for a refresh token, envelope-encrypts it under `HKDF(master, authenticated client_id)`, upserts `credential_store`, emits a synchronous `CREDENTIAL_ENROLLED` audit event, returns **200** HTML. **Errors:** `400` invalid/expired/replayed state or state↔service mismatch, `404` unknown service.

---

### 2.10 Integration Webhooks

#### `POST /integrations/jira/webhook`

Receive Jira issue state change webhooks (e.g., security review completion).

**Authentication:** Verified via `X-Jira-Webhook-Secret` header (shared secret, configured via `JIRA_WEBHOOK_SECRET` env var).

**Required Role:** None (webhook endpoint; verified by secret).

**Request Body** — Jira webhook payload; platform extracts `issue.key` and `issue.status.name`.

**Response 200**

```json
{
  "processed": true,
  "action": "tool_activated",
  "tool_id": "550e8400-..."
}
```

---

## 3. Webhook Schemas (Outbound)

The platform emits outbound webhooks to configured `WEBHOOK_TARGET_URL` on these events:

| Event | Payload |
|-------|---------|
| `tool.registered` | `{event, tool_id, name, version, risk_level, timestamp}` |
| `tool.quarantined` | `{event, tool_id, name, risk_level, risk_reasons, timestamp}` |
| `anomaly.detected` | `{event, alert_id, client_id, pattern, anomaly_score, timestamp}` |
| `compliance.report.failed` | `{event, report_id, categories_failed, timestamp}` |

All webhook payloads are signed with `WEBHOOK_SIGNING_KEY` (HMAC-SHA-256). The signature is in the `X-MCP-Signature-256` header.

---

*End of API Specification*
