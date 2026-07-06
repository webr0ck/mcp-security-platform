-- =============================================================================
-- V066__scan_waivers.sql
-- MCP Security Platform — CR-12 (WP-B2) dependency-CVE waivers
-- PostgreSQL 16
-- =============================================================================
-- Waivers let a reviewer accept the risk of a specific known vulnerability
-- (exact package + version + vuln_id, never fuzzy/prefix) for a bounded
-- time. "Signed" here means DB-role-enforced provenance + an audit-trail
-- event — deliberately NOT a cryptographic signature scheme (no key custody
-- problem to invent; see scanner_worker/README.md's execution/adjudication
-- split for the same reasoning pattern applied to scan verdicts).
--
-- Integrity model (CR-14-consistent, non-negotiable):
--   - scanner_worker_app gets NO grant whatsoever on this table. That role
--     executes untrusted repo content; it must never be able to author its
--     own waiver. Only proxy_app (the reviewer-authorized/evaluator path —
--     i.e. a human reviewer acting through an authenticated admin/reviewer
--     API endpoint) may INSERT/SELECT/UPDATE.
--   - `waived_by_principal_id` is the FULL typed principal id (CR-10 /
--     WP-A1 pattern, e.g. "human:kc-realm:alice") — never a bare subject —
--     so waiver provenance survives the same cross-principal-type collision
--     class CR-10 exists to close.
--   - Waived findings are NEVER deleted from scan_report/scan_raw_results —
--     a waiver only suppresses block/review-required in the evaluator's
--     decision (see proxy/app/services/dependency_policy.py); the finding
--     stays visible in the SBOM/review UI with waiver_id set.
-- =============================================================================

CREATE TABLE IF NOT EXISTS scan_waivers (
    waiver_id                    UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    server_id                    UUID NOT NULL REFERENCES server_registry(server_id),

    -- Exact match target — CR-12 hardening requires exact package+version+
    -- vuln_id, never fuzzy/prefix matching (see dependency_policy.py
    -- _waiver_matches_group). vuln_id may be any identifier in the
    -- alias-collapsed group (CVE/GHSA/GO/RUSTSEC all refer to the same
    -- underlying vuln, so matching against any one of them is still exact
    -- identity, not fuzzy).
    package                       TEXT NOT NULL,
    version                       TEXT NOT NULL,
    vuln_id                       TEXT NOT NULL,
    ecosystem                     TEXT,

    reason                        TEXT NOT NULL,

    -- Typed principal provenance (CR-10 pattern) — who authorized this risk
    -- acceptance. NEVER a bare subject string.
    waived_by_principal_id       TEXT NOT NULL,
    waived_by_principal_type     TEXT NOT NULL
                                  CHECK (waived_by_principal_type IN ('human', 'agent', 'service')),
    waived_by_principal_issuer   TEXT,

    created_at                   TIMESTAMPTZ NOT NULL DEFAULT now(),
    expires_at                   TIMESTAMPTZ NOT NULL,
    -- Early revocation (e.g. reviewer changes their mind before expiry).
    -- NULL = still active (subject to expires_at). Rows are never deleted —
    -- an expired/revoked waiver remains a permanent audit record of what was
    -- once accepted and by whom.
    revoked_at                   TIMESTAMPTZ,
    revoked_by_principal_id      TEXT,

    CONSTRAINT ck_scan_waivers_expiry_after_creation CHECK (expires_at > created_at)
);

-- The evaluator's per-scan lookup: "give me every still-possibly-active
-- waiver for this server" (expiry/revocation is re-checked in application
-- code at evaluation time — see dependency_policy._waiver_active — this
-- index just narrows the candidate set).
CREATE INDEX IF NOT EXISTS ix_scan_waivers_server_active
    ON scan_waivers (server_id, expires_at)
    WHERE revoked_at IS NULL;

CREATE INDEX IF NOT EXISTS ix_scan_waivers_lookup
    ON scan_waivers (server_id, package, version, vuln_id);

-- ---------------------------------------------------------------------------
-- GRANTS (INV-011: explicit per-role, never wildcard)
-- ---------------------------------------------------------------------------
GRANT SELECT, INSERT ON scan_waivers TO proxy_app;
-- UPDATE limited to the revocation columns only — a waiver's identity
-- (package/version/vuln_id/waived_by/expires_at) is immutable once written;
-- "changing your mind" is a revoke, not a mutation of the original grant.
GRANT UPDATE (revoked_at, revoked_by_principal_id) ON scan_waivers TO proxy_app;
REVOKE DELETE ON scan_waivers FROM proxy_app;

-- compliance_checker_app: read-only visibility (waived findings must stay
-- visible in compliance/SBOM tooling, never silently suppressed).
DO $$
BEGIN
    IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'compliance_checker_app') THEN
        GRANT SELECT ON scan_waivers TO compliance_checker_app;
    END IF;
END
$$;

-- scanner_worker_app: explicit belt-and-suspenders NO ACCESS. The worker
-- executes untrusted repo content — it must never be able to author or even
-- read a waiver (a compromised worker could otherwise probe which
-- vulnerabilities are already waived to plan around them).
DO $$
BEGIN
    IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'scanner_worker_app') THEN
        REVOKE ALL ON scan_waivers FROM scanner_worker_app;
    END IF;
END
$$;

COMMENT ON TABLE scan_waivers IS
    'CR-12 (WP-B2): expiring, exact-match (package+version+vuln_id) dependency-CVE '
    'risk acceptances. Written only via the reviewer-authorized proxy_app path — '
    'never scanner_worker_app. See proxy/app/services/scan_waivers.py and '
    'proxy/app/services/dependency_policy.py.';
