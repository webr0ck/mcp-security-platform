# MCP Security Platform — Role-Based Access Control

Version: 1.0.0
Date: 2026-04-21

---

## 1. Overview

The MCP Security Platform implements a flat, non-hierarchical RBAC model with four defined roles. Role assignments are stored in PostgreSQL (`role_assignments` table) and cached in Redis per client session. All permission checks are enforced at two layers:

1. **FastAPI middleware** (`proxy/app/middleware/rbac.py`) — checks role membership before route handlers execute
2. **OPA Rego policies** (`policies/rego/authz.rego`) — evaluates fine-grained permission rules including resource ownership and context

There is no role hierarchy or inheritance. A principal holds exactly one role per namespace.

---

## 2. Role Definitions

### 2.1 `admin`

**Description:** Full platform operator. Registers and manages tools, manages RBAC assignments, triggers compliance runs, reads all audit data.

**Principals:** Human operators, CI/CD service accounts responsible for platform configuration.

**Session type:** Human (OIDC JWT) or service account (API key with admin grant).

---

### 2.2 `agent`

**Description:** An AI agent or automated system that invokes MCP tools through the proxy. Agents are the primary call-path clients.

**Principals:** AI agent processes connecting via mTLS client certificate or API key.

**Session type:** Programmatic (mTLS cert or API key).

**Constraint:** An agent can only invoke tools that it is explicitly granted access to via an OPA allow rule. No tool invocations are allowed by default (deny-by-default).

---

### 2.3 `auditor`

**Description:** Security analyst or compliance officer with read access to all security data: tool registry, SBOM records, audit events, compliance reports, anomaly alerts. No write access anywhere.

**Principals:** Human security reviewers, external auditors, SIEM integrations.

**Session type:** Human (OIDC JWT) or read-only service account.

---

### 2.4 `readonly`

**Description:** Minimal read access to non-sensitive platform information: tool list (no schemas), own audit events only. Intended for dashboards, monitoring integrations, and external stakeholders who need basic visibility.

**Principals:** Monitoring systems, external stakeholders, developer preview access.

**Session type:** API key or OIDC JWT.

---

## 3. Permission Matrix

The table below defines the complete permission model. Columns are API endpoints; rows are roles.

Legend:
- **Y** — Allowed unconditionally (for that role)
- **N** — Denied; returns 403
- **Own** — Allowed only for resources owned by or associated with the principal
- **Admin-gate** — Allowed, but gated by additional condition noted in the cell

### 3.1 Tool Registry

| Operation | `admin` | `agent` | `auditor` | `readonly` |
|-----------|---------|---------|-----------|------------|
| `POST /tools/register` | Y | N | N | N |
| `GET /tools` | Y | N | Y | Y (name/version only, no schema) |
| `GET /tools/{id}` | Y | N | Y | Y (name/version only, no schema) |
| `PATCH /tools/{id}` | Y | N | N | N |
| `DELETE /tools/{id}` | Y | N | N | N |

**Note on `readonly` tool listing:** The `schema`, `upstream_url`, `source_commit`, and `risk_reasons` fields are omitted from `GET /tools` and `GET /tools/{id}` responses for `readonly` role. `auditor` receives full records.

### 3.2 Tool Audit and SBOM

| Operation | `admin` | `agent` | `auditor` | `readonly` |
|-----------|---------|---------|-----------|------------|
| `GET /tools/{id}/audit` | Y | N | Y | N |
| `POST /tools/{id}/audit/rerun` | Y | N | N | N |
| `GET /tools/{id}/sbom` | Y | N | Y | Y (CycloneDX only, no signature field) |

### 3.3 Tool Invocation

| Operation | `admin` | `agent` | `auditor` | `readonly` |
|-----------|---------|---------|-----------|------------|
| `POST /tools/{id}/invoke` | Y (testing) | OPA-gated | N | N |

**OPA gating for `agent`:** Even for the `agent` role, every invocation request is evaluated by OPA. OPA evaluates:
- Is the tool `status: active`?
- Is the client explicitly allowed for this tool (by tool name, tag, or explicit grant)?
- Is the tool `risk_level` within the client's allowed risk threshold?
- Does the invocation sequence trigger anomaly threshold?
- Do the parameter values match any deny patterns?

All conditions must pass; any deny terminates the request with 403.

**`admin` invocation:** Admins can invoke tools for testing purposes. Admin invocations are subject to OPA evaluation but bypass anomaly scoring. All admin invocations are flagged as `testing=true` in the audit record.

### 3.4 Policy Management

| Operation | `admin` | `agent` | `auditor` | `readonly` |
|-----------|---------|---------|-----------|------------|
| `GET /policy/rules` | Y | N | Y | N |
| `POST /policy/evaluate` | Y | N | N | N |

**Policy authoring:** OPA Rego files are managed via git, not the API. The API exposes read-only policy metadata. Policy changes require a git commit → CI pipeline → OPA bundle reload.

### 3.5 Compliance

| Operation | `admin` | `agent` | `auditor` | `readonly` |
|-----------|---------|---------|-----------|------------|
| `GET /compliance/reports` | Y | N | Y | N |
| `GET /compliance/reports/{id}` | Y | N | Y | N |
| `POST /compliance/reports/run` | Y | N | N | N |

### 3.6 Anomaly Detection

| Operation | `admin` | `agent` | `auditor` | `readonly` |
|-----------|---------|---------|-----------|------------|
| `GET /anomaly/baselines` | Y | N | Y | N |
| `GET /anomaly/alerts` | Y | N | Y | N |
| `PATCH /anomaly/alerts/{id}` | Y | N | N | N |

### 3.7 Audit Log Access

| Operation | `admin` | `agent` | `auditor` | `readonly` |
|-----------|---------|---------|-----------|------------|
| `GET /audit/events` | Y | Own (client_id filter auto-applied) | Y | N |

**`agent` audit access:** An agent may query its own audit events (automatically filtered by `client_id = calling_client_id`). Cross-client audit access is denied.

### 3.8 System Health

| Operation | `admin` | `agent` | `auditor` | `readonly` |
|-----------|---------|---------|-----------|------------|
| `GET /health` | Y | Y | Y | Y (public) |
| `GET /health/ready` | Y | Y | Y | Y (public) |

### 3.9 Authentication

| Operation | `admin` | `agent` | `auditor` | `readonly` |
|-----------|---------|---------|-----------|------------|
| `GET /auth/oidc/login` | Y | Y | Y | Y (public) |
| `GET /auth/oidc/callback` | Y | Y | Y | Y (public) |

### 3.10 Integrations

| Operation | `admin` | `agent` | `auditor` | `readonly` |
|-----------|---------|---------|-----------|------------|
| `POST /integrations/jira/webhook` | — | — | — | — (webhook secret only) |

---

## 4. Protected Entities and Ownership Rules

### 4.1 Tool Registry Records

- **Owner:** The `admin` who registered the tool (stored as `registered_by` in `tool_registry`).
- **Ownership does not grant additional privilege.** All admins have equal access to all tool records.
- **Quarantine gate:** A tool with `risk_level: critical` can only be set to `status: active` by an admin. The system cannot auto-activate critical-risk tools.

### 4.2 API Keys

- **Owner:** The `admin` who created the key, or the `agent` the key is issued to.
- `agent` principals can read their own key metadata (not the raw key value; only `key_id`, `created_at`, `last_used_at`).
- Only `admin` can create, rotate, or revoke API keys for other principals.

### 4.3 Anomaly Baselines

- Baselines are associated with a `client_id`.
- `agents` cannot read or modify baselines (prevents adversarial baseline poisoning).
- `admin` can reset a baseline for a client; this triggers re-learning from scratch.

### 4.4 Compliance Reports

- Reports are system-generated; no principal "owns" a report.
- Report archive URLs (S3/MinIO) are returned in API responses but the MinIO bucket requires separate credentials (not exposed via the API).

### 4.5 OPA Policies

- OPA Rego files are owned by the `policies/` git directory. No API writes to policy files.
- Policy reload is triggered by a health webhook from the CI pipeline posting to `POST /internal/policy/reload` (internal network only, not exposed externally).

---

## 5. RBAC Enforcement Points

Enforcement occurs at three layers, in order:

```
Request
  │
  ▼
[1] Nginx Gateway
    Rate limiting by client CN/API key.
    No RBAC enforcement (identity not yet resolved).
  │
  ▼
[2] FastAPI RBAC Middleware (proxy/app/middleware/rbac.py)
    Resolves identity (cert CN / JWT / API key).
    Checks role from PostgreSQL/Redis cache.
    Returns 401 if no identity; 403 if role lacks endpoint permission.
    Field-level filtering applied for readonly role.
  │
  ▼
[3] OPA Sidecar (for invocation endpoints)
    Fine-grained policy evaluation.
    Evaluates: client × tool × params × anomaly score × risk level.
    Returns allow/deny with reasons.
    Deny returns 403 OPA_DENY.
```

Enforcement is fail-closed at every layer: if OPA is unreachable, all tool invocations return 503 (not allowed by default).

---

## 6. Role Assignment Operations

Role assignments are managed out-of-band (not via API in v1). They are managed via:

1. **Seed migration** — `infra/db/migrations/V002__rbac_seed.sql` seeds default roles
2. **Admin CLI** — `make assign-role CLIENT_ID=... ROLE=...` (wraps a direct DB insert)
3. **OIDC claim mapping** — OIDC JWT claims are mapped to roles via `oidc_role_mappings` table; configured at deployment time

A future v2 API may expose role assignment management endpoints (out of scope for v1).

---

## 7. Audit Requirements for Privileged Operations

All operations by `admin` role that modify platform state generate an audit event. The `mcp-audit-logger` library is used for all audit emissions.

| Operation | Audit Event Type | Fields |
|-----------|-----------------|--------|
| Tool registered | `TOOL_REGISTERED` | `tool_id`, `name`, `version`, `risk_level`, `admin_id` |
| Tool status changed | `TOOL_STATUS_CHANGED` | `tool_id`, `old_status`, `new_status`, `admin_id` |
| Tool deleted | `TOOL_DELETED` | `tool_id`, `name`, `admin_id` |
| Audit re-run triggered | `AUDIT_RERUN_TRIGGERED` | `tool_id`, `admin_id` |
| Compliance run triggered | `COMPLIANCE_RUN_TRIGGERED` | `job_id`, `admin_id` |
| Anomaly alert resolved | `ANOMALY_ALERT_RESOLVED` | `alert_id`, `admin_id`, `resolution_note` |
| Policy evaluate called | `POLICY_EVAL_MANUAL` | `input_hash`, `result`, `admin_id` |
| API key created | `API_KEY_CREATED` | `key_id`, `client_id`, `admin_id` |
| API key revoked | `API_KEY_REVOKED` | `key_id`, `client_id`, `admin_id` |

All tool invocations (ALLOW and DENY) generate audit events regardless of role.

---

## 8. OIDC Role Claim Mapping

When OIDC is enabled, the proxy maps JWT claims to platform roles via the `oidc_role_mappings` table:

| OIDC Claim Path | Claim Value | Platform Role |
|----------------|-------------|---------------|
| `roles[]` | `mcp-admin` | `admin` |
| `roles[]` | `mcp-agent` | `agent` |
| `roles[]` | `mcp-auditor` | `auditor` |
| `roles[]` | `mcp-readonly` | `readonly` |
| (default if no match) | — | request rejected (401) |

The claim path is configurable via `OIDC_ROLE_CLAIM_PATH` env var (default: `roles`).

---

*End of RBAC Document*
