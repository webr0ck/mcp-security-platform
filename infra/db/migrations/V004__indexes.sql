-- =============================================================================
-- V004__indexes.sql
-- MCP Security Platform — Performance Indexes
-- =============================================================================
-- This migration adds indexes beyond those in V001 that are needed for
-- production query performance at expected data volumes.
--
-- All indexes use CREATE INDEX CONCURRENTLY IF NOT EXISTS for production safety
-- (does not hold an exclusive table lock).
--
-- IMPORTANT: CONCURRENTLY cannot run inside a transaction block.
-- Flyway users: set flyway.mixed=true OR run this migration outside a
-- transaction (annotate with @NonTransactional if using Flyway Java API).
-- The PostgreSQL driver will still execute these statements successfully;
-- each CREATE INDEX CONCURRENTLY runs in its own implicit transaction.
--
-- Expected row volumes at 6 months:
--   audit_events:        ~50M rows (high-frequency write)
--   tool_registry:       ~500 rows (low write frequency)
--   anomaly_alerts:      ~10K rows
--   sbom_records:        ~500 rows
--   compliance_reports:  ~200 rows
-- =============================================================================

-- ---------------------------------------------------------------------------
-- audit_events — highest query pressure
-- ---------------------------------------------------------------------------
-- Pattern 1: compliance checker daily sample
--   SELECT ... FROM audit_events
--   WHERE event_ts >= $1 AND event_ts < $2
--   ORDER BY event_ts DESC LIMIT 1000
-- Served by: idx_audit_events_event_ts (from V001)

-- Pattern 2: GET /audit/events?client_id=X&from=Y&to=Z
--   SELECT ... FROM audit_events
--   WHERE client_id = $1 AND event_ts BETWEEN $2 AND $3
-- Served by: idx_audit_events_client_ts (from V001)

-- Pattern 3: Outcome rate dashboard (deny rate per time bucket)
--   SELECT outcome, DATE_TRUNC('hour', event_ts), COUNT(*)
--   FROM audit_events
--   WHERE event_ts >= NOW() - INTERVAL '24 hours'
--   GROUP BY 1, 2
-- Adding a dedicated composite covering both filter and grouping columns:
CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_audit_events_ts_outcome
    ON audit_events (event_ts DESC, outcome);

-- Pattern 4: Tool-specific audit trail for GET /audit/events?tool_name=X
--   Covered partially by idx_audit_events_tool_id but tool_name is TEXT
--   and sometimes queried without a known tool_id (unregistered tools).
CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_audit_events_tool_name_ts
    ON audit_events (tool_name, event_ts DESC);

-- Pattern 5: request_id lookup for cross-system log correlation
--   SELECT * FROM audit_events WHERE request_id = $1
CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_audit_events_request_id
    ON audit_events (request_id);


-- ---------------------------------------------------------------------------
-- tool_registry — low cardinality columns benefit from partial indexes
-- ---------------------------------------------------------------------------
-- Pattern: GET /tools?status=active&risk_level=high (admin dashboard)
--   Covered by idx_tool_registry_active_status (from V001), but add a
--   composite for status + risk_level filtering together.
CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_tool_registry_status_risk
    ON tool_registry (status, risk_level)
    WHERE deleted_at IS NULL;

-- Pattern: tool name exact lookup (auth middleware: resolve tool_id by name)
--   SELECT tool_id FROM tool_registry WHERE name = $1 AND version = $2
--   Covered by the UNIQUE constraint index (name, version).
--   No additional index needed — UNIQUE constraint creates a B-tree automatically.


-- ---------------------------------------------------------------------------
-- anomaly_alerts — dashboard and alert-management queries
-- ---------------------------------------------------------------------------
-- Pattern: GET /anomaly/alerts?client_id=X&resolved=false (default view)
--   Served by idx_anomaly_alerts_client_unresolved (from V001)
--   Adding partial index for the resolved=true path (historical review):
CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_anomaly_alerts_resolved_ts
    ON anomaly_alerts (detected_at DESC)
    WHERE resolved = TRUE;

-- Pattern: High-score open alerts (priority triage view)
--   Served by idx_anomaly_alerts_high_score (from V001)


-- ---------------------------------------------------------------------------
-- sbom_records — low write rate; query patterns are simple FK lookups
-- ---------------------------------------------------------------------------
-- Pattern: GET /tools/{tool_id}/sbom → latest SBOM for a tool
--   SELECT * FROM sbom_records WHERE tool_id = $1 ORDER BY generated_at DESC LIMIT 1
--   Served by idx_sbom_records_tool_id (from V001).
--   Adding a composite to avoid a sort step:
CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_sbom_records_tool_id_generated_at
    ON sbom_records (tool_id, generated_at DESC);

-- Pattern: signature verification lookup (compliance checker cross-checks)
--   SELECT signature, schema_hash FROM sbom_records WHERE tool_id = $1
--   Covered by the composite above.


-- ---------------------------------------------------------------------------
-- compliance_reports — low cardinality, modest row count
-- ---------------------------------------------------------------------------
-- Pattern: GET /compliance/reports?status=fail&from=X
--   Served by idx_compliance_reports_run_at (from V001).
--   Adding a partial index for failed reports (most actionable subset):
CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_compliance_reports_failed
    ON compliance_reports (run_at DESC)
    WHERE status = 'fail';


-- ---------------------------------------------------------------------------
-- tool_audit_results — latest audit result per tool is the hot path
-- ---------------------------------------------------------------------------
-- Pattern: GET /tools/{tool_id}/audit → latest result
--   SELECT * FROM tool_audit_results WHERE tool_id = $1 ORDER BY audited_at DESC LIMIT 1
--   Served by idx_tool_audit_results_tool_id (from V001)


-- ---------------------------------------------------------------------------
-- api_keys — hot path for auth middleware
-- ---------------------------------------------------------------------------
-- Pattern: auth middleware hashes incoming Bearer token → lookup in pg
--   SELECT * FROM api_keys WHERE key_hash = $1 AND revoked_at IS NULL
--   Served by idx_api_keys_active_hash (from V001)
--   Redis cache sits in front; this index handles cold cache misses.


-- ---------------------------------------------------------------------------
-- audit_events_archive — range scans for historical compliance windows
-- ---------------------------------------------------------------------------
CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_audit_archive_client_ts
    ON audit_events_archive (client_id, event_ts DESC);

CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_audit_archive_outcome_ts
    ON audit_events_archive (outcome, event_ts DESC);
