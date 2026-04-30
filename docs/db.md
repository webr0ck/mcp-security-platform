# Database Design

MCP Security Platform — PostgreSQL 16
Version: 1.0.0 | Updated: 2026-04-21

---

## Overview

The platform uses a single PostgreSQL 16 database (`mcp_security`) as the persistent state store for tool registry, SBOM records, audit event index, anomaly detection state, compliance reports, and RBAC configuration. Log content lives in Loki + MinIO; this database stores metadata and integrity hashes used for compliance queries.

**Two application roles** access the database (INV-011):
- `proxy_app` — the MCP Security Proxy (FastAPI); writes tool registry, SBOMs, audit events, anomaly state, API keys, and OIDC mappings.
- `compliance_checker_app` — the daily compliance cron; reads audit events, writes compliance reports.

No other service has direct database write access.

**Append-only enforcement** on `audit_events` and `audit_events_archive`:
1. Role grants: neither application role has UPDATE or DELETE privileges on these tables (V003).
2. Trigger guard: `fn_audit_events_immutability_guard()` raises a PostgreSQL exception (`insufficient_privilege`) if any UPDATE or DELETE is attempted by any role. This fires regardless of role grants, providing defence-in-depth.

---

## Table Reference

### tool_registry

**Purpose:** Central registry of all MCP tools. Single source of truth for tool identity, schema, risk posture, and lifecycle status.

| Column | Type | Constraints | Description |
|--------|------|-------------|-------------|
| `tool_id` | UUID | PK, DEFAULT gen_random_uuid() | Stable internal identifier |
| `name` | VARCHAR(64) | NOT NULL | Tool name (lowercase, hyphen-separated) |
| `version` | VARCHAR(32) | NOT NULL | Semver string |
| `description` | TEXT | NOT NULL | Human description; scanned for injection patterns |
| `schema` | JSONB | NOT NULL | JSON Schema for tool call parameters |
| `source_repo` | TEXT | NULL | Source repository URL |
| `source_commit` | CHAR(40) | NULL | Full 40-char git SHA (CHAR enforces length) |
| `upstream_url` | TEXT | NOT NULL | Upstream MCP server endpoint |
| `tags` | TEXT[] | NOT NULL DEFAULT '{}' | Taxonomy tags |
| `metadata` | JSONB | NOT NULL DEFAULT '{}' | Arbitrary key-value metadata |
| `status` | VARCHAR(20) | NOT NULL, CHECK IN ('active','quarantined','deprecated') | Lifecycle status |
| `risk_score` | INTEGER | CHECK BETWEEN 0 AND 100 | 0-100 risk score from Tool Manifest Auditor |
| `risk_level` | VARCHAR(10) | CHECK IN ('low','medium','high','critical') | Risk category |
| `risk_reasons` | JSONB | NOT NULL DEFAULT '[]' | Explanations for risk assessment |
| `registered_by` | TEXT | NOT NULL | Identity that registered the tool |
| `created_at` | TIMESTAMPTZ | NOT NULL DEFAULT NOW() | Registration timestamp (canonical "registered_at") |
| `updated_at` | TIMESTAMPTZ | NOT NULL DEFAULT NOW() | Last update; maintained by trigger |
| `deleted_at` | TIMESTAMPTZ | NULL | Soft-delete timestamp; NULL = active |

**Unique constraint:** `(name, version)` — one row per tool version.

**Indexes:**
- `idx_tool_registry_active_status` — `(status, name) WHERE deleted_at IS NULL` — partial index for active tool listing
- `idx_tool_registry_risk_level` — `(risk_level) WHERE deleted_at IS NULL` — risk-level filtering
- `idx_tool_registry_created_at` — `(created_at DESC)` — registration history
- `idx_tool_registry_tags` — GIN on `tags` — array containment queries (`?tag=filesystem`)
- `idx_tool_registry_metadata` — GIN on `metadata` — JSONB containment
- `idx_tool_registry_name_trgm` — GIN trigram on `name` — fuzzy name search
- Automatic B-tree on `(name, version)` from the UNIQUE constraint

**Relations:**
- Referenced by: `sbom_records.tool_id`, `audit_events.tool_id`, `tool_audit_results.tool_id`

**Retention:** Soft-deleted records retained indefinitely (historical audit references require them). Physical deletion requires out-of-band DBA operation (cascades to sbom_records, tool_audit_results).

---

### sbom_records

**Purpose:** CycloneDX 1.5 SBOM documents (and optional SPDX 2.3) generated at tool registration. Immutable after creation. INV-006: `signature` is NOT NULL + CHECK LENGTH > 0.

| Column | Type | Constraints | Description |
|--------|------|-------------|-------------|
| `sbom_id` | UUID | PK | Stable SBOM record identifier |
| `tool_id` | UUID | NOT NULL, FK → tool_registry(tool_id) ON DELETE CASCADE | Parent tool |
| `bom_ref` | UUID | NOT NULL DEFAULT gen_random_uuid() | CycloneDX `serialNumber` / `bom-ref` value |
| `cyclonedx_json` | JSONB | NOT NULL | Full CycloneDX 1.5 document |
| `spdx_json` | JSONB | NULL | SPDX 2.3 document (generated when SPDX_ENABLED=true) |
| `schema_hash` | CHAR(64) | NOT NULL | SHA-256 of canonical tool schema JSON; drift detection |
| `signature` | TEXT | NOT NULL, CHECK LENGTH > 0 | HMAC-SHA-256 of cyclonedx_json (INV-006) |
| `auditor_version` | VARCHAR(32) | NOT NULL | Auditor version that generated this SBOM |
| `generated_at` | TIMESTAMPTZ | NOT NULL DEFAULT NOW() | Generation timestamp |

**Indexes:**
- `idx_sbom_records_tool_id` — `(tool_id)`
- `idx_sbom_records_tool_id_generated_at` — `(tool_id, generated_at DESC)` — latest SBOM per tool without sort step
- `idx_sbom_records_generated_at` — `(generated_at DESC)`

**Relations:** FK to `tool_registry.tool_id` with CASCADE DELETE.

**Append-only:** No UPDATE or DELETE via application roles. A new row is created for each registration or re-run.

**Retention:** Permanent (follows parent tool; cascade on physical tool deletion by DBA).

---

### audit_events

**Purpose:** Append-only index of every tool invocation event (allow and deny). Full event payload lives in Loki + MinIO. This table stores metadata for compliance queries, anomaly correlation, and SHA-256 hash integrity verification per INV-001.

| Column | Type | Constraints | Description |
|--------|------|-------------|-------------|
| `event_id` | UUID | PK | Stable event identifier |
| `event_ts` | TIMESTAMPTZ | NOT NULL DEFAULT NOW() | When the event occurred |
| `client_id` | TEXT | NOT NULL | Client identity (cert CN or API key client_id) |
| `tool_name` | TEXT | NOT NULL | Tool name at invocation time |
| `tool_id` | UUID | NULL, FK → tool_registry ON DELETE SET NULL | Tool registry FK (nullable: tool may not be registered) |
| `outcome` | VARCHAR(10) | NOT NULL, CHECK IN ('allow','deny') | OPA decision |
| `latency_ms` | INTEGER | NULL | End-to-end latency in milliseconds |
| `bytes_in` | INTEGER | NULL | Request payload size |
| `bytes_out` | INTEGER | NULL | Response payload size |
| `sha256_hash` | CHAR(64) | NOT NULL | SHA-256 of full event payload (Loki content hash) |
| `anomaly_score` | FLOAT | CHECK >= 0.0 AND <= 1.0 | Anomaly detector score at invocation time |
| `opa_reasons` | JSONB | NOT NULL DEFAULT '[]' | OPA deny reasons (empty for allow events) |
| `request_id` | TEXT | NOT NULL | Client-assigned request ID for cross-system correlation |
| `source_ip` | INET | NULL | Source IP (may be redacted per INV-002) |
| `created_at` | TIMESTAMPTZ | NOT NULL DEFAULT NOW() | Row insertion timestamp |

**Indexes (V001 + V004):**
- `idx_audit_events_event_ts` — `(event_ts DESC)` — time-range scans
- `idx_audit_events_client_ts` — `(client_id, event_ts DESC)` — per-client audit trail
- `idx_audit_events_tool_id` — `(tool_id, event_ts DESC)`
- `idx_audit_events_outcome` — `(outcome, event_ts DESC)` — deny-rate queries
- `idx_audit_events_high_anomaly` — `(anomaly_score DESC, event_ts DESC) WHERE anomaly_score > 0.80` — partial, anomaly investigation
- `idx_audit_events_ts_outcome` — `(event_ts DESC, outcome)` — dashboard outcome-rate queries
- `idx_audit_events_tool_name_ts` — `(tool_name, event_ts DESC)` — name-based filter without known tool_id
- `idx_audit_events_request_id` — `(request_id)` — cross-system correlation lookups

**Relations:** FK to `tool_registry.tool_id` with SET NULL (audit events survive tool deletion).

**Append-only enforcement:**
- `proxy_app`: INSERT only. No UPDATE, no DELETE (REVOKE in V003).
- Trigger `trg_audit_events_immutability` raises exception on any UPDATE or DELETE attempt.

**Retention:** 90 days active. Older rows are moved to `audit_events_archive` by `archive_old_audit_events()` (scheduled daily at 01:00 UTC per V005). Archive is permanent.

---

### audit_events_archive

**Purpose:** Cold-storage copy of `audit_events` rows older than 90 days. Schema mirrors `audit_events` plus an `archived_at` timestamp. No FK to `tool_registry` (tool may be deleted by archive time).

**Append-only enforcement:** Identical trigger guard (`trg_audit_events_archive_immutability`). No application role has UPDATE or DELETE. Physical removal requires DBA + trigger disable.

**Retention:** Permanent (compliance-critical; 7-year regulatory minimum recommended).

**Indexes:**
- `idx_audit_events_archive_event_ts` — `(event_ts DESC)`
- `idx_audit_events_archive_client_id` — `(client_id, event_ts DESC)`
- `idx_audit_archive_outcome_ts` — `(outcome, event_ts DESC)` (V004)

---

### anomaly_baselines

**Purpose:** Per-client behavioral baselines maintained by the Anomaly Detector. Updated asynchronously after each invocation. One row per client_id.

| Column | Type | Constraints | Description |
|--------|------|-------------|-------------|
| `baseline_id` | UUID | PK | |
| `client_id` | TEXT | NOT NULL UNIQUE | One baseline per client |
| `baseline_version` | INTEGER | NOT NULL DEFAULT 1 | Incremented on each update |
| `tool_sequence_patterns` | JSONB | NOT NULL DEFAULT '[]' | N-gram / Markov sequence patterns |
| `tools_in_baseline` | TEXT[] | NOT NULL DEFAULT '{}' | Flat list of observed tool names |
| `anomaly_score_threshold` | FLOAT | NOT NULL DEFAULT 0.85, CHECK > 0.0 AND <= 1.0 | Alert threshold |
| `last_updated` | TIMESTAMPTZ | NOT NULL DEFAULT NOW() | Last model update time |
| `created_at` | TIMESTAMPTZ | NOT NULL DEFAULT NOW() | |
| `updated_at` | TIMESTAMPTZ | NOT NULL DEFAULT NOW() | Trigger-maintained |

**Retention:** 1 year after client last seen (application-level TTL job).

---

### anomaly_alerts

**Purpose:** Records of detected anomalous behavior. Resolution fields (resolved, resolved_at, resolved_by, resolution_note) are mutable; initial record is immutable.

| Column | Type | Constraints | Description |
|--------|------|-------------|-------------|
| `alert_id` | UUID | PK | |
| `client_id` | TEXT | NOT NULL | Client that triggered the alert |
| `detected_at` | TIMESTAMPTZ | NOT NULL DEFAULT NOW() | When anomaly was detected |
| `anomaly_score` | FLOAT | NOT NULL, CHECK >= 0.0 AND <= 1.0 | Score that exceeded threshold |
| `pattern` | TEXT | NOT NULL | Human-readable pattern description |
| `description` | TEXT | NOT NULL | Full narrative |
| `invocation_ids` | UUID[] | NOT NULL DEFAULT '{}' | audit_events.event_id references |
| `resolved` | BOOLEAN | NOT NULL DEFAULT FALSE | |
| `resolved_at` | TIMESTAMPTZ | NULL | |
| `resolved_by` | TEXT | NULL | |
| `resolution_note` | TEXT | NULL | |
| `created_at` | TIMESTAMPTZ | NOT NULL DEFAULT NOW() | |
| `updated_at` | TIMESTAMPTZ | NOT NULL DEFAULT NOW() | |

**Constraint:** `resolved = TRUE` requires `resolved_by IS NOT NULL` (cannot resolve without a resolver identity).

**Indexes:**
- `idx_anomaly_alerts_client_unresolved` — `(client_id, resolved, detected_at DESC)` — default dashboard view
- `idx_anomaly_alerts_high_score` — `(anomaly_score DESC) WHERE resolved = FALSE` — priority triage
- `idx_anomaly_alerts_resolved_ts` — `(detected_at DESC) WHERE resolved = TRUE` — historical review (V004)

**Retention:** 1 year from `detected_at` (application-level soft-purge).

---

### api_keys

**Purpose:** Hashed API keys for non-mTLS client authentication. Raw key is never stored — only SHA-256 hex digest (INV-008 / INV-002).

| Column | Type | Constraints | Description |
|--------|------|-------------|-------------|
| `key_id` | UUID | PK | |
| `key_hash` | CHAR(64) | NOT NULL UNIQUE, CHECK LENGTH = 64 | SHA-256 hex of raw key |
| `client_id` | TEXT | NOT NULL | Client identity this key represents |
| `roles` | TEXT[] | NOT NULL DEFAULT '{"agent"}' | Roles granted to this key |
| `rate_limit_rpm` | INTEGER | NOT NULL DEFAULT 120, CHECK > 0 | Per-key rate limit |
| `created_at` | TIMESTAMPTZ | NOT NULL DEFAULT NOW() | |
| `expires_at` | TIMESTAMPTZ | NULL | Optional expiry |
| `revoked_at` | TIMESTAMPTZ | NULL | NULL = active; SET to revoke |
| `created_by` | TEXT | NOT NULL | Identity that created this key |

**Indexes:**
- `idx_api_keys_active_hash` — `(key_hash) WHERE revoked_at IS NULL` — hot auth middleware path
- `idx_api_keys_client_id` — `(client_id)`

**Retention:** 2 years after `revoked_at` (audit hold). Active keys retained until revoked.

---

### compliance_reports

**Purpose:** Metadata and results for each compliance check run. Written only by `compliance_checker_app`.

| Column | Type | Constraints | Description |
|--------|------|-------------|-------------|
| `report_id` | UUID | PK | |
| `run_at` | TIMESTAMPTZ | NOT NULL DEFAULT NOW() | When the run completed |
| `status` | VARCHAR(20) | NOT NULL, CHECK IN ('pass','fail','in_progress') | |
| `sample_size` | INTEGER | NOT NULL, CHECK > 0 | Number of audit events sampled |
| `period_start` | TIMESTAMPTZ | NOT NULL | Sample window start |
| `period_end` | TIMESTAMPTZ | NOT NULL | Sample window end |
| `categories_checked` | INTEGER | NOT NULL | Number of PII/credential categories checked |
| `categories_failed` | INTEGER | NOT NULL DEFAULT 0 | Count of failing categories |
| `category_results` | JSONB | NOT NULL DEFAULT '[]' | Per-category breakdown |
| `hash_integrity` | JSONB | NOT NULL DEFAULT '{}' | Hash verification summary |
| `archive_url` | TEXT | NULL | S3/MinIO WORM object URL |
| `triggered_by` | TEXT | NOT NULL DEFAULT 'scheduler' | 'scheduler' or admin identity |
| `created_at` | TIMESTAMPTZ | NOT NULL DEFAULT NOW() | |
| `updated_at` | TIMESTAMPTZ | NOT NULL DEFAULT NOW() | |

**Constraint:** `period_end > period_start`

**Indexes:**
- `idx_compliance_reports_run_at` — `(run_at DESC, status)` — list with status filter
- `idx_compliance_reports_failed` — `(run_at DESC) WHERE status = 'fail'` — failed reports view (V004)

**Retention:** 7 years (regulatory minimum for compliance audit records).

---

### tool_audit_results

**Purpose:** Immutable record of each Tool Manifest Auditor run per tool. Multiple rows per `tool_id` (one per run).

| Column | Type | Constraints | Description |
|--------|------|-------------|-------------|
| `audit_result_id` | UUID | PK | |
| `tool_id` | UUID | NOT NULL, FK → tool_registry ON DELETE CASCADE | |
| `audited_at` | TIMESTAMPTZ | NOT NULL DEFAULT NOW() | |
| `auditor_version` | TEXT | NOT NULL | Auditor version string |
| `risk_score` | INTEGER | CHECK BETWEEN 0 AND 100 | |
| `risk_level` | TEXT | CHECK IN ('low','medium','high','critical') | |
| `findings` | JSONB | NOT NULL DEFAULT '[]' | Array of finding objects |
| `llm_analysis` | JSONB | NULL | Ollama LLM response (absent if Ollama unavailable) |
| `static_analysis` | JSONB | NOT NULL DEFAULT '{}' | Static pattern results |
| `audit_job_id` | UUID | NULL | Back-reference to audit_jobs row |
| `created_at` | TIMESTAMPTZ | NOT NULL DEFAULT NOW() | |

**Indexes:**
- `idx_tool_audit_results_tool_id` — `(tool_id, audited_at DESC)` — latest audit per tool
- `idx_tool_audit_results_risk_level` — `(risk_level, audited_at DESC)`

**Retention:** Permanent while tool exists; cascade-deleted on physical tool removal by DBA.

---

### oidc_role_mappings

**Purpose:** Maps OIDC issuer + claim key/value pairs to platform roles. Used by auth middleware to resolve roles from OIDC JWTs.

| Column | Type | Constraints | Description |
|--------|------|-------------|-------------|
| `mapping_id` | UUID | PK | |
| `oidc_issuer` | TEXT | NOT NULL | OIDC provider issuer URL |
| `claim_key` | TEXT | NOT NULL | JWT claim name (e.g. 'roles', 'groups') |
| `claim_value` | TEXT | NOT NULL | Claim value to match |
| `roles` | TEXT[] | NOT NULL | Platform roles granted |
| `created_at` | TIMESTAMPTZ | NOT NULL DEFAULT NOW() | |

**Unique constraint:** `(oidc_issuer, claim_key, claim_value)`

**Index:** `idx_oidc_role_mappings_issuer` — `(oidc_issuer, claim_key)`

**Retention:** Indefinite; managed by admin through API.

---

### audit_jobs

**Purpose:** Tracks async background job state for tool audit re-runs and on-demand compliance runs.

| Column | Type | Description |
|--------|------|-------------|
| `job_id` | UUID PK | |
| `job_type` | VARCHAR(50) | 'tool_audit' or 'compliance_run' |
| `status` | VARCHAR(20) | 'queued', 'running', 'completed', 'failed' |
| `reference_id` | UUID NULL | tool_id or report_id |
| `started_at` | TIMESTAMPTZ NULL | |
| `completed_at` | TIMESTAMPTZ NULL | |
| `error_message` | TEXT NULL | |
| `created_by` | TEXT NOT NULL | |
| `created_at` | TIMESTAMPTZ | |
| `updated_at` | TIMESTAMPTZ | |

**Retention:** 90 days (operational; pruned by `purge_old_audit_jobs()` per V005).

---

## Key Query Patterns

### P1 — Auth middleware API key lookup (hot path, p50 < 1ms with Redis cache)
```sql
SELECT key_id, client_id, roles, rate_limit_rpm, expires_at
FROM api_keys
WHERE key_hash = $1
  AND revoked_at IS NULL;
```
Index: `idx_api_keys_active_hash` (partial B-tree on key_hash WHERE revoked_at IS NULL)

### P2 — Compliance checker daily sample (p95 < 500ms at 50M rows)
```sql
SELECT event_id, sha256_hash, client_id, tool_name, outcome, opa_reasons
FROM audit_events
WHERE event_ts >= $1 AND event_ts < $2
ORDER BY event_ts DESC
LIMIT 1000;
```
Index: `idx_audit_events_event_ts`

### P3 — Per-client audit trail (GET /audit/events?client_id=X)
```sql
SELECT * FROM audit_events
WHERE client_id = $1
  AND event_ts BETWEEN $2 AND $3
ORDER BY event_ts DESC
LIMIT 50;
```
Index: `idx_audit_events_client_ts` (composite: client_id, event_ts DESC)

### P4 — Latest SBOM for a tool (GET /tools/{id}/sbom)
```sql
SELECT cyclonedx_json, spdx_json, signature, bom_ref, schema_hash
FROM sbom_records
WHERE tool_id = $1
ORDER BY generated_at DESC
LIMIT 1;
```
Index: `idx_sbom_records_tool_id_generated_at`

### P5 — Latest audit result for a tool (GET /tools/{id}/audit)
```sql
SELECT * FROM tool_audit_results
WHERE tool_id = $1
ORDER BY audited_at DESC
LIMIT 1;
```
Index: `idx_tool_audit_results_tool_id`

### P6 — Tool list with status and risk filter (GET /tools?status=active&risk_level=high)
```sql
SELECT tool_id, name, version, status, risk_score, risk_level, tags, created_at
FROM tool_registry
WHERE status = $1 AND risk_level = $2 AND deleted_at IS NULL
ORDER BY created_at DESC
LIMIT 50;
```
Index: `idx_tool_registry_status_risk` (V004 composite)

### P7 — Open anomaly alerts for a client (GET /anomaly/alerts?client_id=X&resolved=false)
```sql
SELECT * FROM anomaly_alerts
WHERE client_id = $1 AND resolved = FALSE
ORDER BY detected_at DESC
LIMIT 50;
```
Index: `idx_anomaly_alerts_client_unresolved`

### P8 — OIDC role resolution (auth middleware on OIDC JWT validation)
```sql
SELECT roles FROM oidc_role_mappings
WHERE oidc_issuer = $1
  AND claim_key = $2
  AND claim_value = ANY($3::text[]);
```
Index: `idx_oidc_role_mappings_issuer`

---

## Retention & Archival Summary

| Table | Active Retention | Archival Strategy | Physical Deletion |
|-------|-----------------|-------------------|-------------------|
| `audit_events` | 90 days | Move to `audit_events_archive` via `archive_old_audit_events()` (daily 01:00 UTC) | Never (only DBA + trigger disable) |
| `audit_events_archive` | Permanent | Cold storage in same DB | Never |
| `compliance_reports` | 7 years | No archival (table is small; in-DB) | DBA only after 7-year hold |
| `tool_registry` | Indefinite (soft-delete) | No archival | DBA only; cascades to sbom + audit results |
| `sbom_records` | Permanent (follows tool) | No archival | Cascade on tool physical delete |
| `tool_audit_results` | Permanent (follows tool) | No archival | Cascade on tool physical delete |
| `anomaly_alerts` | 1 year from `detected_at` | Application-level soft-purge | Application job |
| `anomaly_baselines` | 1 year after client last seen | Application-level TTL | Application job |
| `api_keys` | 2 years after `revoked_at` | No archival | Application job after hold period |
| `audit_jobs` | 90 days | No archival | `purge_old_audit_jobs()` (daily 01:05 UTC) |
| `oidc_role_mappings` | Indefinite | No archival | Admin via API |

---

## Architect Deviations & Review Notes

### RN-001 — `tool_registry.created_at` vs `registered_at`
The Architect's spec uses `registered_at` as the column name for the registration timestamp. This schema uses `created_at` (the platform-wide convention for all tables) to keep cross-table consistency and simplify ORMs. The API layer maps `created_at → registered_at` in response serialisation. The column is logically identical.

### RN-002 — `sbom_records`: split `bom_document` into `cyclonedx_json` + `spdx_json`
The Architect's original V001 stub used a single `bom_document JSONB` column. This design separates CycloneDX and SPDX into distinct nullable columns. Rationale: `GET /tools/{id}/sbom?format=spdx` is a direct column read rather than a JSONB path extraction, avoiding runtime JSON parsing. CycloneDX is mandatory (NOT NULL); SPDX is optional (nullable). The `bom_ref`, `schema_hash`, `auditor_version`, and `generated_at` columns align with the Architect's spec §11.

### RN-003 — `audit_events.event_ts` vs `timestamp`
The Architect's spec names the column `timestamp`. This was renamed to `event_ts` to avoid colliding with the PostgreSQL reserved word `TIMESTAMP`, which requires quoting in every query and is error-prone. The API response shape continues to expose this field as `"timestamp"`. We retain `created_at` as the row-insertion time (may differ from `event_ts` in async batch scenarios).

### RN-004 — Table name: `tool_audit_results` vs `tool_audits`
The Architect's original V001 stub used the table name `tool_audits` with PK `audit_id`. The Architect's spec (the task definition) names this table `tool_audit_results` with PK `audit_result_id`. We adopt the spec name for forward API compatibility (`GET /tools/{id}/audit` exposes `audit_result_id`). Any backend code referencing `tool_audits` must be updated.

### RN-005 — `oidc_role_mappings`: added `oidc_issuer`, changed `roles` to `TEXT[]`
The original V001 stub used `(claim_path, claim_value, platform_role)` without an `oidc_issuer` discriminator, which would merge mappings from all OIDC providers into a single namespace. The Architect's spec §8.1 explicitly includes `oidc_issuer` to scope mappings per provider. We adopt the spec. Additionally, `roles` is `TEXT[]` (not a single `VARCHAR`) to support multi-role grants from a single claim value.

### RN-006 — `api_keys`: kept `roles TEXT[]` instead of separate `role_assignments` table
The original V001 stub included a separate `role_assignments` table for client-level role management. The Architect's spec embeds `roles TEXT[]` directly in `api_keys`. We adopt the spec's embedded-roles approach for API keys (simpler auth middleware — one query resolves key and roles together) and omit the redundant `role_assignments` table. OIDC role resolution continues to use `oidc_role_mappings`. If per-client mTLS role management is needed, `role_assignments` can be reintroduced in a future migration.

### RN-007 — `audit_events_archive` created in V001, not V005
The archive table is defined in V001 alongside `audit_events` to ensure schema consistency between live and archive tables. V005 adds only the archival function and pg_cron schedule. This avoids a migration ordering risk where the archival function could be created before its target table exists.

---

## Migration History

| Version | File | Description |
|---------|------|-------------|
| V001 | `V001__initial_schema.sql` | All core tables: tool_registry, sbom_records, audit_events, audit_events_archive, anomaly_baselines, anomaly_alerts, api_keys, compliance_reports, tool_audit_results, oidc_role_mappings, audit_jobs |
| V002 | `V002__rbac_seed.sql` | Default OIDC role mappings; bootstrap admin API key placeholder |
| V003 | `V003__db_roles.sql` | Create proxy_app and compliance_checker_app roles; grant/revoke permissions; immutability trigger guards on audit tables |
| V004 | `V004__indexes.sql` | Performance indexes (CONCURRENTLY) for production query patterns |
| V005 | `V005__retention_policy.sql` | archive_old_audit_events() function; purge_old_audit_jobs() function; pg_cron schedules |

**Apply order:** V001 → V002 → V003 → V004 → V005

**Rollback procedures:**
- V005: DROP FUNCTION archive_old_audit_events; DROP FUNCTION purge_old_audit_jobs; unschedule pg_cron jobs (if applicable). Archive table retained.
- V004: DROP INDEX for each index created in V004 (use CONCURRENTLY).
- V003: Cannot trivially roll back (would remove role grants; application becomes inoperable). Treat as a forward-only migration in practice.
- V002: DELETE FROM oidc_role_mappings WHERE oidc_issuer = '__OIDC_ISSUER_PLACEHOLDER__'; DELETE FROM api_keys WHERE key_id = '00000000-0000-0000-0000-000000000001';
- V001: DROP TABLE in reverse FK order: audit_jobs, oidc_role_mappings, tool_audit_results, compliance_reports, api_keys, anomaly_alerts, anomaly_baselines, audit_events_archive, audit_events, sbom_records, tool_registry; DROP FUNCTION fn_set_updated_at; DROP EXTENSION pg_trgm; DROP EXTENSION pgcrypto.

---

## Handoff Notes

### For `backend_dev`

**New/modified tables vs original V001 stub:**

| Change | Detail |
|--------|--------|
| `tool_audits` → `tool_audit_results` | Rename (RN-004). PK is now `audit_result_id`. Update all ORM models and queries. |
| `audit_events.event_ts` | Column is `event_ts`, not `timestamp`. Map to `"timestamp"` in API response serialiser. |
| `sbom_records` | Split into `cyclonedx_json` + `spdx_json`. Remove `bom_document`, `format`, `spec_version`, `serial_number`. Add `bom_ref`, `auditor_version`, `generated_at`. |
| `oidc_role_mappings` | New columns: `oidc_issuer`. `claim_path` → `claim_key`. `platform_role VARCHAR` → `roles TEXT[]`. Unique key changed. |
| `api_keys` | `key_hash` is CHAR(64) (enforces exact 64-char length). Added `roles TEXT[]`, `rate_limit_rpm`. Removed `key_prefix`, `description`, `revoked BOOLEAN`, `revoked_by`. Revocation is now `revoked_at IS NOT NULL`. |
| `anomaly_baselines` | `sequence_patterns` → `tool_sequence_patterns`. `anomaly_threshold` → `anomaly_score_threshold`. `transition_matrix` removed (embed in `tool_sequence_patterns` JSONB). |
| `role_assignments` table | Removed (see RN-006). |

**Application-level constraints to enforce:**
1. Never issue `UPDATE` or `DELETE` on `audit_events` or `audit_events_archive`. The trigger will raise an exception, causing a 500 error. Use INSERT only.
2. Never store raw API key values. Always hash with SHA-256 before any database operation.
3. `sbom_records.signature` must be set before INSERT. Application must reject the INSERT if `SBOM_SIGNING_KEY` is unavailable (not an empty string — the CHECK constraint will catch empty strings, but None/null will be rejected by NOT NULL).
4. `compliance_checker_app` role: connect with `COMPLIANCE_DB_PASSWORD`. `proxy_app` role: connect with `PROXY_DB_PASSWORD`. Never use the migration superuser account (`mcp_app`) from application code.
5. Tool invocations for `status = 'quarantined'` tools must be rejected at the application layer before any OPA call (INV-005).

### For `qa`

**Migration apply order:** V001 → V002 → V003 → V004 → V005

**Pre-migration checks:**
- PostgreSQL 16+ required (gen_random_uuid() built-in, JSONB, INET, FLOAT type)
- Extensions: `pgcrypto`, `pg_trgm` must be installable (superuser required)
- Optional: `pg_cron` for V005 scheduled archival

**Post-migration data integrity checks:**

```sql
-- 1. All tables created
SELECT tablename FROM pg_tables
WHERE schemaname = 'public'
ORDER BY tablename;
-- Expect: anomaly_alerts, anomaly_baselines, api_keys, audit_events,
--         audit_events_archive, audit_jobs, compliance_reports,
--         oidc_role_mappings, sbom_records, tool_audit_results, tool_registry

-- 2. Roles created with correct privileges
SELECT rolname FROM pg_roles WHERE rolname IN ('proxy_app','compliance_checker_app');

-- 3. Immutability trigger exists on audit_events
SELECT trigger_name FROM information_schema.triggers
WHERE event_object_table = 'audit_events'
  AND trigger_name = 'trg_audit_events_immutability';

-- 4. SBOM signature NOT NULL constraint
SELECT column_name, is_nullable FROM information_schema.columns
WHERE table_name = 'sbom_records' AND column_name = 'signature';
-- Expect: is_nullable = 'NO'

-- 5. Bootstrap API key seeded
SELECT client_id, roles, key_hash FROM api_keys
WHERE key_id = '00000000-0000-0000-0000-000000000001';
-- Expect: 1 row, roles = {admin}, key_hash = 64 chars

-- 6. OIDC seed data present
SELECT COUNT(*) FROM oidc_role_mappings
WHERE oidc_issuer = '__OIDC_ISSUER_PLACEHOLDER__';
-- Expect: 4

-- 7. Archive function exists
SELECT proname FROM pg_proc WHERE proname = 'archive_old_audit_events';
-- Expect: 1 row

-- 8. V004 indexes exist (sample)
SELECT indexname FROM pg_indexes
WHERE tablename = 'audit_events'
  AND indexname LIKE 'idx_audit_events_%'
ORDER BY indexname;
```

**Rollback test procedure:**
1. Run V005 rollback SQL (drop functions, unschedule cron)
2. Run V004 rollback (drop concurrent indexes)
3. Verify V003 cannot be safely rolled back without taking the application offline — document this as a known forward-only migration
4. Confirm `audit_events_archive` is retained after V005 rollback (no data loss)
