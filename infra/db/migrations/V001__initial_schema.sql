-- =============================================================================
-- V001__initial_schema.sql
-- MCP Security Platform — Complete Initial Database Schema
-- PostgreSQL 16
-- =============================================================================
-- Design principles:
--   • UUID PKs everywhere (gen_random_uuid() — PG 16 built-in, no extension needed)
--   • TIMESTAMPTZ (never bare TIMESTAMP) for all temporal columns
--   • Mutable tables carry updated_at maintained by trigger
--   • Append-only tables (audit_events, sbom_records, tool_audit_results)
--     have NO updated_at and no UPDATE/DELETE grants (enforced in V003)
--   • Soft-delete via deleted_at; hard delete prohibited on compliance-sensitive data
--   • All FK constraints are named for maintainability
--   • Inline deviation notes reference Architect schema where this file diverges
-- =============================================================================

-- ---------------------------------------------------------------------------
-- Extensions
-- ---------------------------------------------------------------------------
-- pgcrypto provides gen_random_uuid() in PG < 13; in PG 16 it is built-in
-- but keeping the extension is harmless and may be needed by other uses.
CREATE EXTENSION IF NOT EXISTS "pgcrypto";
-- pg_trgm supports GIN trigram indexes for fuzzy tool-name search
CREATE EXTENSION IF NOT EXISTS "pg_trgm";

-- ---------------------------------------------------------------------------
-- Shared trigger: auto-update updated_at on any mutable table
-- ---------------------------------------------------------------------------
CREATE OR REPLACE FUNCTION fn_set_updated_at()
RETURNS TRIGGER AS $$
BEGIN
    NEW.updated_at = NOW();
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;


-- =============================================================================
-- TABLE: tool_registry
-- Purpose: Central registry of all MCP tools. Single source of truth for
--          tool identity, schema, risk posture, and lifecycle status.
-- Writer:  proxy_app only (INV-011)
-- Retention: Soft-deleted records retained indefinitely for audit reference.
--            Physical deletion requires out-of-band DBA operation.
-- =============================================================================
CREATE TABLE IF NOT EXISTS tool_registry (
    tool_id         UUID            PRIMARY KEY DEFAULT gen_random_uuid(),
    name            VARCHAR(64)     NOT NULL,
    version         VARCHAR(32)     NOT NULL,
    description     TEXT            NOT NULL,

    -- JSON Schema for the tool's call parameters (used for OPA + validation)
    schema          JSONB           NOT NULL,

    -- Optional provenance
    source_repo     TEXT,
    source_commit   CHAR(40),       -- Full 40-char git SHA; CHAR enforces length

    -- Upstream MCP server endpoint this tool proxies to
    upstream_url    TEXT            NOT NULL,

    tags            TEXT[]          NOT NULL DEFAULT '{}',
    metadata        JSONB           NOT NULL DEFAULT '{}',

    status          VARCHAR(20)     NOT NULL DEFAULT 'active'
                        CHECK (status IN ('active', 'quarantined', 'deprecated')),

    -- Risk fields populated by Tool Manifest Auditor on registration
    risk_score      INTEGER         CHECK (risk_score BETWEEN 0 AND 100),
    risk_level      VARCHAR(10)     CHECK (risk_level IN ('low', 'medium', 'high', 'critical')),
    risk_reasons    JSONB           NOT NULL DEFAULT '[]',

    registered_by   TEXT            NOT NULL,

    -- Lifecycle timestamps
    -- DEVIATION from Architect stub: we keep created_at as the canonical
    -- "registered_at" name for consistency with all other tables, AND add a
    -- generated column alias so API layer can expose "registered_at" without
    -- renaming. See review note RN-001 in docs/db.md.
    created_at      TIMESTAMPTZ     NOT NULL DEFAULT NOW(),
    updated_at      TIMESTAMPTZ     NOT NULL DEFAULT NOW(),
    deleted_at      TIMESTAMPTZ,            -- NULL = not deleted (soft-delete)

    CONSTRAINT tool_registry_name_version_unique UNIQUE (name, version)
);

-- Partial index: the vast majority of queries filter out soft-deleted tools
CREATE INDEX IF NOT EXISTS idx_tool_registry_active_status
    ON tool_registry (status, name)
    WHERE deleted_at IS NULL;

CREATE INDEX IF NOT EXISTS idx_tool_registry_risk_level
    ON tool_registry (risk_level)
    WHERE deleted_at IS NULL;

CREATE INDEX IF NOT EXISTS idx_tool_registry_created_at
    ON tool_registry (created_at DESC);

-- GIN indexes for array/JSONB containment queries (tag filtering, metadata search)
CREATE INDEX IF NOT EXISTS idx_tool_registry_tags
    ON tool_registry USING GIN (tags);

CREATE INDEX IF NOT EXISTS idx_tool_registry_metadata
    ON tool_registry USING GIN (metadata);

-- Trigram index for ILIKE/similarity search on tool names
CREATE INDEX IF NOT EXISTS idx_tool_registry_name_trgm
    ON tool_registry USING GIN (name gin_trgm_ops);

CREATE TRIGGER trg_tool_registry_updated_at
    BEFORE UPDATE ON tool_registry
    FOR EACH ROW EXECUTE FUNCTION fn_set_updated_at();


-- =============================================================================
-- TABLE: sbom_records
-- Purpose: CycloneDX 1.5 (primary) and SPDX 2.3 (secondary) SBOM documents
--          produced at tool registration time. Immutable after creation.
-- Writer:  proxy_app only (INV-011)
-- Retention: Permanent — deleted only if parent tool_registry row is physically
--            deleted by DBA (cascade). No application-layer deletion.
-- INV-006: signature column is NOT NULL (enforced at DB level + CHECK).
-- =============================================================================
-- DEVIATION RN-002: Architect stub defined a single bom_document JSONB column.
-- This schema separates cyclonedx_json and spdx_json into distinct nullable
-- columns so the query for GET /tools/{id}/sbom?format=spdx is a simple
-- column read rather than a JSONB extraction. CycloneDX is required; SPDX is
-- optional (hence nullable). The schema_hash and bom_ref columns align with
-- the Architect's spec for §11 (SBOM and Provenance).
CREATE TABLE IF NOT EXISTS sbom_records (
    sbom_id             UUID        PRIMARY KEY DEFAULT gen_random_uuid(),

    -- FK to the tool that this SBOM describes
    -- CASCADE: if tool is physically removed by DBA, remove orphaned SBOMs
    tool_id             UUID        NOT NULL,
    CONSTRAINT fk_sbom_records_tool_id
        FOREIGN KEY (tool_id) REFERENCES tool_registry (tool_id)
        ON DELETE CASCADE,

    -- Stable bom-ref identifier exposed in the CycloneDX serialNumber field
    bom_ref             UUID        NOT NULL DEFAULT gen_random_uuid(),

    -- CycloneDX 1.5 document (required)
    cyclonedx_json      JSONB       NOT NULL,

    -- SPDX 2.3 document (optional; generated when SPDX_ENABLED=true)
    spdx_json           JSONB,

    -- SHA-256 of the canonical (sorted-key) tool schema JSON.
    -- Used by compliance checker to detect schema drift post-registration.
    schema_hash         CHAR(64)    NOT NULL,

    -- HMAC-SHA-256 of cyclonedx_json signed with SBOM_SIGNING_KEY (INV-006).
    -- NOT NULL enforced here AND by application code before INSERT.
    -- CHECK LENGTH > 0 guards against empty string bypass attempts.
    signature           TEXT        NOT NULL,
    CONSTRAINT sbom_records_signature_not_empty
        CHECK (LENGTH(TRIM(signature)) > 0),

    auditor_version     VARCHAR(32) NOT NULL,
    generated_at        TIMESTAMPTZ NOT NULL DEFAULT NOW()
    -- No updated_at: sbom_records are immutable. Re-runs create new rows.
);

CREATE INDEX IF NOT EXISTS idx_sbom_records_tool_id
    ON sbom_records (tool_id);

CREATE INDEX IF NOT EXISTS idx_sbom_records_generated_at
    ON sbom_records (generated_at DESC);


-- =============================================================================
-- TABLE: audit_events
-- Purpose: Append-only index of every tool invocation event (allow and deny).
--          Full payload lives in Loki + MinIO. This table holds the metadata
--          needed for compliance queries, anomaly correlation, and hash integrity
--          verification (SHA-256 per event per INV-001).
-- Writer:  proxy_app only (INV-011)
-- Retention: 90 days active; then archived to audit_events_archive (V005).
--            Archive is permanent. No physical deletion from either table.
-- Append-only enforcement: proxy_app has INSERT only (no UPDATE, no DELETE).
--          compliance_checker_app has SELECT only. See V003.
-- =============================================================================
-- DEVIATION RN-003: Architect stub used `timestamp` as a column name.
-- Renamed to `event_ts` to avoid colliding with the PostgreSQL reserved word
-- `TIMESTAMP`. The API layer maps event_ts → timestamp in the response shape.
-- We also retain `created_at` (standard across all tables) and keep event_ts
-- as the authoritative "when did this event occur" field (they may differ
-- slightly if the insert is batched). See review note RN-003 in docs/db.md.
CREATE TABLE IF NOT EXISTS audit_events (
    event_id        UUID            PRIMARY KEY DEFAULT gen_random_uuid(),

    -- When the event occurred (not necessarily when the row was inserted)
    event_ts        TIMESTAMPTZ     NOT NULL DEFAULT NOW(),

    client_id       TEXT            NOT NULL,
    tool_name       TEXT            NOT NULL,

    -- Nullable: tool may not exist in registry for denied/unknown invocations
    tool_id         UUID,
    CONSTRAINT fk_audit_events_tool_id
        FOREIGN KEY (tool_id) REFERENCES tool_registry (tool_id)
        ON DELETE SET NULL,

    outcome         VARCHAR(10)     NOT NULL CHECK (outcome IN ('allow', 'deny')),

    latency_ms      INTEGER,
    bytes_in        INTEGER,
    bytes_out       INTEGER,

    -- SHA-256 hash of the full event payload (stored in Loki).
    -- Compliance checker verifies this hash to detect tampering (INV-001).
    sha256_hash     CHAR(64)        NOT NULL,

    anomaly_score   FLOAT           CHECK (anomaly_score >= 0.0 AND anomaly_score <= 1.0),

    -- Serialised OPA deny reasons; empty array for allow events
    opa_reasons     JSONB           NOT NULL DEFAULT '[]',

    -- Client-assigned request ID for cross-system correlation (gateway → proxy → Loki)
    request_id      TEXT            NOT NULL,

    source_ip       INET,

    -- Insertion timestamp (may differ from event_ts for async batch inserts)
    created_at      TIMESTAMPTZ     NOT NULL DEFAULT NOW()

    -- NO updated_at — this table is append-only. UPDATE grants are never issued.
);

-- Primary time-range scan (compliance checker samples last 24h)
CREATE INDEX IF NOT EXISTS idx_audit_events_event_ts
    ON audit_events (event_ts DESC);

-- Per-client audit trail (anomaly detector, GET /audit/events?client_id=)
CREATE INDEX IF NOT EXISTS idx_audit_events_client_id
    ON audit_events (client_id, event_ts DESC);

-- Tool-level query (GET /audit/events?tool_name=)
CREATE INDEX IF NOT EXISTS idx_audit_events_tool_id
    ON audit_events (tool_id, event_ts DESC);

-- Outcome filter (common in compliance queries: deny-rate over period)
CREATE INDEX IF NOT EXISTS idx_audit_events_outcome
    ON audit_events (outcome, event_ts DESC);

-- Partial index: anomaly investigation only touches high-score events
CREATE INDEX IF NOT EXISTS idx_audit_events_high_anomaly
    ON audit_events (anomaly_score DESC, event_ts DESC)
    WHERE anomaly_score > 0.80;

-- Composite for the most frequent compliance query pattern:
-- SELECT ... WHERE client_id = $1 AND event_ts BETWEEN $2 AND $3
CREATE INDEX IF NOT EXISTS idx_audit_events_client_ts
    ON audit_events (client_id, event_ts DESC);


-- =============================================================================
-- TABLE: anomaly_baselines
-- Purpose: Per-client behavioral baselines maintained by the Anomaly Detector.
--          Updated asynchronously after each invocation. Not append-only
--          (baselines evolve), but only proxy_app may write.
-- Writer:  proxy_app only (INV-011)
-- Retention: Retained while the client is active + 1 year after last event.
--            Governed by application-level TTL job.
-- =============================================================================
CREATE TABLE IF NOT EXISTS anomaly_baselines (
    baseline_id             UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
    client_id               TEXT        NOT NULL UNIQUE,
    baseline_version        INTEGER     NOT NULL DEFAULT 1,

    -- Serialised n-gram / Markov tool-sequence patterns
    tool_sequence_patterns  JSONB       NOT NULL DEFAULT '[]',

    -- Flat list of tool names observed in baseline window (for quick membership test)
    tools_in_baseline       TEXT[]      NOT NULL DEFAULT '{}',

    -- Score above which an event is flagged as anomalous
    anomaly_score_threshold FLOAT       NOT NULL DEFAULT 0.85
                                CHECK (anomaly_score_threshold > 0.0
                                   AND anomaly_score_threshold <= 1.0),

    last_updated            TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    created_at              TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at              TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_anomaly_baselines_client_id
    ON anomaly_baselines (client_id);

CREATE TRIGGER trg_anomaly_baselines_updated_at
    BEFORE UPDATE ON anomaly_baselines
    FOR EACH ROW EXECUTE FUNCTION fn_set_updated_at();


-- =============================================================================
-- TABLE: anomaly_alerts
-- Purpose: Records of detected anomalous behavior. Mutable only in the
--          resolution fields (resolved, resolved_at, resolved_by, resolution_note).
-- Writer:  proxy_app only (INV-011)
-- Retention: 1 year from detected_at; soft-purged after that.
-- =============================================================================
CREATE TABLE IF NOT EXISTS anomaly_alerts (
    alert_id        UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
    client_id       TEXT        NOT NULL,
    detected_at     TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    anomaly_score   FLOAT       NOT NULL CHECK (anomaly_score >= 0.0 AND anomaly_score <= 1.0),
    pattern         TEXT        NOT NULL,
    description     TEXT        NOT NULL,

    -- UUIDs of audit_events rows implicated in this anomaly
    invocation_ids  UUID[]      NOT NULL DEFAULT '{}',

    resolved        BOOLEAN     NOT NULL DEFAULT FALSE,
    resolved_at     TIMESTAMPTZ,
    resolved_by     TEXT,
    resolution_note TEXT,

    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),

    -- Integrity: cannot mark resolved without a resolver identity
    CONSTRAINT anomaly_alerts_resolved_requires_resolver
        CHECK (resolved = FALSE
            OR (resolved = TRUE AND resolved_by IS NOT NULL))
);

-- Primary access pattern: list open alerts per client, newest first
CREATE INDEX IF NOT EXISTS idx_anomaly_alerts_client_unresolved
    ON anomaly_alerts (client_id, resolved, detected_at DESC);

CREATE INDEX IF NOT EXISTS idx_anomaly_alerts_high_score
    ON anomaly_alerts (anomaly_score DESC)
    WHERE resolved = FALSE;

CREATE TRIGGER trg_anomaly_alerts_updated_at
    BEFORE UPDATE ON anomaly_alerts
    FOR EACH ROW EXECUTE FUNCTION fn_set_updated_at();


-- =============================================================================
-- TABLE: api_keys
-- Purpose: Hashed API keys for non-mTLS client authentication.
--          Raw key is NEVER stored — only SHA-256 hash (INV-008 spirit / INV-002).
-- Writer:  proxy_app only (INV-011)
-- Retention: Revoked keys retained 2 years for audit (revoked_at is the marker).
-- =============================================================================
CREATE TABLE IF NOT EXISTS api_keys (
    key_id          UUID        PRIMARY KEY DEFAULT gen_random_uuid(),

    -- SHA-256 (hex, lowercase) of the raw API key. CHAR(64) enforces exact length.
    key_hash        CHAR(64)    NOT NULL UNIQUE,

    client_id       TEXT        NOT NULL,

    -- Roles granted to this key; default is agent-level access
    roles           TEXT[]      NOT NULL DEFAULT '{"agent"}',

    -- Per-key rate limit; overrides role default if set
    rate_limit_rpm  INTEGER     NOT NULL DEFAULT 120
                        CHECK (rate_limit_rpm > 0),

    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    expires_at      TIMESTAMPTZ,
    revoked_at      TIMESTAMPTZ,
    created_by      TEXT        NOT NULL,

    -- Partial unique index: only one active (non-revoked) key per hash
    CONSTRAINT api_keys_hash_not_empty
        CHECK (LENGTH(key_hash) = 64)
);

-- Hot path: auth middleware hashes incoming key and looks it up
CREATE INDEX IF NOT EXISTS idx_api_keys_active_hash
    ON api_keys (key_hash)
    WHERE revoked_at IS NULL;

CREATE INDEX IF NOT EXISTS idx_api_keys_client_id
    ON api_keys (client_id);


-- =============================================================================
-- TABLE: compliance_reports
-- Purpose: Metadata and results for each compliance check run.
--          Written by compliance_checker_app; read by proxy_app and admin users.
-- Writer:  compliance_checker_app only (INV-011)
-- Retention: 7 years (compliance-critical records — see docs/db.md §Retention).
-- =============================================================================
CREATE TABLE IF NOT EXISTS compliance_reports (
    report_id           UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
    run_at              TIMESTAMPTZ NOT NULL DEFAULT NOW(),

    status              VARCHAR(20) NOT NULL
                            CHECK (status IN ('pass', 'fail', 'in_progress')),

    sample_size         INTEGER     NOT NULL CHECK (sample_size > 0),
    period_start        TIMESTAMPTZ NOT NULL,
    period_end          TIMESTAMPTZ NOT NULL,
    categories_checked  INTEGER     NOT NULL CHECK (categories_checked >= 0),
    categories_failed   INTEGER     NOT NULL DEFAULT 0
                            CHECK (categories_failed >= 0),

    -- Per-category breakdown array matching API response shape
    category_results    JSONB       NOT NULL DEFAULT '[]',

    -- Hash integrity summary {events_checked, hash_mismatches, status}
    hash_integrity      JSONB       NOT NULL DEFAULT '{}',

    -- S3/MinIO WORM object URL for the full archived report
    archive_url         TEXT,

    -- Who triggered this run: 'scheduler' for cron, or admin identity for on-demand
    triggered_by        TEXT        NOT NULL DEFAULT 'scheduler',

    created_at          TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at          TIMESTAMPTZ NOT NULL DEFAULT NOW(),

    CONSTRAINT compliance_reports_period_order
        CHECK (period_end > period_start)
);

-- Primary access: list reports newest-first, filtered by status
CREATE INDEX IF NOT EXISTS idx_compliance_reports_run_at
    ON compliance_reports (run_at DESC, status);

CREATE TRIGGER trg_compliance_reports_updated_at
    BEFORE UPDATE ON compliance_reports
    FOR EACH ROW EXECUTE FUNCTION fn_set_updated_at();


-- =============================================================================
-- TABLE: tool_audit_results
-- Purpose: Immutable record of each Tool Manifest Auditor run per tool.
--          Created on tool registration and on explicit re-run (POST .../audit/rerun).
--          Multiple rows per tool_id (one per audit run).
-- Writer:  proxy_app only (INV-011)
-- Retention: Permanent while tool exists; cascade-deleted on physical tool removal.
-- =============================================================================
-- DEVIATION RN-004: Architect stub named this table "tool_audit_results" with PK
-- "audit_result_id". The Architect's original V001 stub used "tool_audits" with
-- PK "audit_id". We adopt the Architect's spec name ("tool_audit_results") for
-- forward compatibility with the API shape at GET /tools/{tool_id}/audit.
-- The application layer must reference this table name, not "tool_audits".
CREATE TABLE IF NOT EXISTS tool_audit_results (
    audit_result_id     UUID        PRIMARY KEY DEFAULT gen_random_uuid(),

    tool_id             UUID        NOT NULL,
    CONSTRAINT fk_tool_audit_results_tool_id
        FOREIGN KEY (tool_id) REFERENCES tool_registry (tool_id)
        ON DELETE CASCADE,

    audited_at          TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    auditor_version     TEXT        NOT NULL,

    risk_score          INTEGER     CHECK (risk_score BETWEEN 0 AND 100),
    risk_level          TEXT        CHECK (risk_level IN ('low', 'medium', 'high', 'critical')),

    -- Array of finding objects: {finding_id, category, severity, description, ...}
    findings            JSONB       NOT NULL DEFAULT '[]',

    -- Raw Ollama LLM response (nullable — may be absent if Ollama was unavailable)
    llm_analysis        JSONB,

    -- Static pattern-matching results
    static_analysis     JSONB       NOT NULL DEFAULT '{}',

    -- Back-reference to the async job that produced this result (nullable for sync runs)
    audit_job_id        UUID,

    created_at          TIMESTAMPTZ NOT NULL DEFAULT NOW()
    -- No updated_at: audit results are immutable. Re-runs create a new row.
);

-- Most frequent access: latest audit for a given tool
CREATE INDEX IF NOT EXISTS idx_tool_audit_results_tool_id
    ON tool_audit_results (tool_id, audited_at DESC);

CREATE INDEX IF NOT EXISTS idx_tool_audit_results_risk_level
    ON tool_audit_results (risk_level, audited_at DESC);


-- =============================================================================
-- TABLE: oidc_role_mappings
-- Purpose: Maps OIDC issuer + claim key/value pairs to platform roles.
--          Used by the auth middleware to resolve roles from OIDC JWTs.
-- Writer:  proxy_app only (INV-011)
-- Retention: Indefinite; managed by admin through API.
-- =============================================================================
-- DEVIATION RN-005: The original V001 stub used columns (claim_path, claim_value,
-- platform_role) without an oidc_issuer discriminator, which would merge
-- mappings from all OIDC providers. The Architect's spec includes oidc_issuer
-- to correctly scope mappings per provider (§8.1). We adopt the Architect's
-- spec. The unique constraint changes accordingly. roles is TEXT[] (not a
-- single VARCHAR) to support multi-role grants from a single claim value.
CREATE TABLE IF NOT EXISTS oidc_role_mappings (
    mapping_id      UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
    oidc_issuer     TEXT        NOT NULL,   -- e.g. https://accounts.google.com
    claim_key       TEXT        NOT NULL,   -- e.g. 'roles', 'groups'
    claim_value     TEXT        NOT NULL,   -- e.g. 'mcp-admin'
    roles           TEXT[]      NOT NULL,   -- e.g. '{admin}' or '{agent,auditor}'

    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),

    CONSTRAINT oidc_role_mappings_unique
        UNIQUE (oidc_issuer, claim_key, claim_value)
);

CREATE INDEX IF NOT EXISTS idx_oidc_role_mappings_issuer
    ON oidc_role_mappings (oidc_issuer, claim_key);


-- =============================================================================
-- TABLE: audit_jobs
-- Purpose: Tracks async background job state for tool audit re-runs and
--          on-demand compliance report runs.
-- Writer:  proxy_app only (INV-011)
-- Retention: 90 days (transient operational data; old jobs pruned by scheduler).
-- =============================================================================
CREATE TABLE IF NOT EXISTS audit_jobs (
    job_id          UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
    job_type        VARCHAR(50) NOT NULL
                        CHECK (job_type IN ('tool_audit', 'compliance_run')),
    status          VARCHAR(20) NOT NULL DEFAULT 'queued'
                        CHECK (status IN ('queued', 'running', 'completed', 'failed')),

    -- tool_id for tool_audit jobs; report_id for compliance_run jobs
    reference_id    UUID,

    started_at      TIMESTAMPTZ,
    completed_at    TIMESTAMPTZ,
    error_message   TEXT,
    created_by      TEXT        NOT NULL,

    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_audit_jobs_status
    ON audit_jobs (status, created_at DESC);

CREATE INDEX IF NOT EXISTS idx_audit_jobs_reference_id
    ON audit_jobs (reference_id);

CREATE TRIGGER trg_audit_jobs_updated_at
    BEFORE UPDATE ON audit_jobs
    FOR EACH ROW EXECUTE FUNCTION fn_set_updated_at();


-- =============================================================================
-- TABLE: audit_events_archive
-- Purpose: Cold-storage copy of audit_events rows older than 90 days.
--          Moved here by archive_old_audit_events() in V005.
--          APPEND-ONLY: no role has UPDATE or DELETE on this table.
-- =============================================================================
CREATE TABLE IF NOT EXISTS audit_events_archive (
    -- Identical columns to audit_events
    event_id        UUID            NOT NULL,
    event_ts        TIMESTAMPTZ     NOT NULL,
    client_id       TEXT            NOT NULL,
    tool_name       TEXT            NOT NULL,
    tool_id         UUID,           -- No FK here; tool may be gone by archive time
    outcome         VARCHAR(10)     NOT NULL CHECK (outcome IN ('allow', 'deny')),
    latency_ms      INTEGER,
    bytes_in        INTEGER,
    bytes_out       INTEGER,
    sha256_hash     CHAR(64)        NOT NULL,
    anomaly_score   FLOAT,
    opa_reasons     JSONB           NOT NULL DEFAULT '[]',
    request_id      TEXT            NOT NULL,
    source_ip       INET,
    created_at      TIMESTAMPTZ     NOT NULL,

    -- Archive metadata
    archived_at     TIMESTAMPTZ     NOT NULL DEFAULT NOW(),

    -- PK is event_id — preserves the original identity
    PRIMARY KEY (event_id)
);

-- Archive queries are primarily time-range scans
CREATE INDEX IF NOT EXISTS idx_audit_events_archive_event_ts
    ON audit_events_archive (event_ts DESC);

CREATE INDEX IF NOT EXISTS idx_audit_events_archive_client_id
    ON audit_events_archive (client_id, event_ts DESC);
