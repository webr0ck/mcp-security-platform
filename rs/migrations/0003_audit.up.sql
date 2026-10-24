-- 0003_audit.up.sql — mcphub-store consolidated schema, part 3/4
--
-- audit_events — the append-only invocation ledger. Per ARCHITECTURE.md
-- invariant 4, a row here is durably written BEFORE the caller gets a
-- response, and audit-write failure is itself a Deny.
--
-- Query pattern (HOT — the first of the two hottest queries at 3000
-- concurrent agents): one INSERT per invocation, on the critical path.
-- Everything else here (compliance scans, per-principal trails) is cold by
-- comparison and indexed accordingly.

CREATE TABLE IF NOT EXISTS audit_events (
    event_id        UUID            PRIMARY KEY DEFAULT gen_random_uuid(),
    event_ts        TIMESTAMPTZ     NOT NULL DEFAULT now(),
    request_id      TEXT            NOT NULL,
    principal_id    TEXT            NOT NULL,
    issuer          TEXT,
    -- Nullable: a denied-at-ingress call may never resolve a server/tool row.
    server_id       UUID            REFERENCES servers (server_id) ON DELETE SET NULL,
    tool_id         UUID            REFERENCES tool_registry (tool_id) ON DELETE SET NULL,
    tool_name       TEXT            NOT NULL,
    outcome         TEXT            NOT NULL CHECK (outcome IN ('allow', 'deny')),
    -- Stable machine code from mcphub_types::DenyReason::code(); NULL on allow.
    deny_reason     TEXT,
    latency_ms      INTEGER,
    source_ip       INET,

    -- sha256 hex digest over the canonical core fields (event_id, event_ts,
    -- request_id, principal_id, tool_name, tool_id, outcome, deny_reason) —
    -- see mcphub-store's audit::canonical_json(). Independent of the redis
    -- stream copy so on-disk rows are self-verifying.
    sha256_hash     CHAR(64)        NOT NULL,
    -- Hash chain: this row's predecessor's sha256_hash (global chain, most
    -- recent committed row at insert time). NULL only for the very first
    -- row ever written. Lets an auditor detect a deleted/reordered row even
    -- though the append-only trigger below should make that unreachable
    -- through normal SQL.
    prev_hash       CHAR(64),

    -- Allowlisted enrichment fields only (roles, notices, taint state, ...).
    -- Never raw request/response payloads — see mcphub-store's redact
    -- module. A new field is redacted by default; it must be explicitly
    -- added to the allowlist to appear here.
    redacted_fields JSONB           NOT NULL DEFAULT '{}',

    created_at      TIMESTAMPTZ     NOT NULL DEFAULT now()

    -- No updated_at: this table is append-only by design.
);

-- Compliance scan: time-range sweep.
CREATE INDEX IF NOT EXISTS idx_audit_events_event_ts
    ON audit_events (event_ts DESC);

-- Per-principal audit trail (GET /audit/events?principal_id=).
CREATE INDEX IF NOT EXISTS idx_audit_events_principal_ts
    ON audit_events (principal_id, event_ts DESC);

-- Per-tool audit trail.
CREATE INDEX IF NOT EXISTS idx_audit_events_tool_ts
    ON audit_events (tool_id, event_ts DESC);

-- Deny-rate compliance queries.
CREATE INDEX IF NOT EXISTS idx_audit_events_outcome_ts
    ON audit_events (outcome, event_ts DESC);

-- ---------------------------------------------------------------------------
-- Append-only enforcement: reject UPDATE and DELETE unconditionally, at the
-- database level, regardless of which role issues the statement. This is
-- belt-and-braces alongside the REVOKE below — the trigger holds even if a
-- future migration accidentally re-grants UPDATE/DELETE to some role.
-- ---------------------------------------------------------------------------
CREATE OR REPLACE FUNCTION fn_audit_events_immutability_guard()
RETURNS TRIGGER AS $$
BEGIN
    RAISE EXCEPTION 'audit_events is append-only: % is not permitted', TG_OP
        USING ERRCODE = 'restrict_violation';
    RETURN NULL;
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER trg_audit_events_no_update
    BEFORE UPDATE ON audit_events
    FOR EACH ROW EXECUTE FUNCTION fn_audit_events_immutability_guard();

CREATE TRIGGER trg_audit_events_no_delete
    BEFORE DELETE ON audit_events
    FOR EACH ROW EXECUTE FUNCTION fn_audit_events_immutability_guard();
