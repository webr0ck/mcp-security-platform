-- =============================================================================
-- V038__trust_envelope.sql
-- MCP Security Platform — Signed Trust-Envelope POC (PRD-0001 M1 / RFC-0001 §4)
-- PostgreSQL 16
-- =============================================================================
-- Adds the Biba integrity columns the B-coarse taint floor (RFC-0001 §8.1) reads:
--
--   server_registry.trust_tier      SEP-1913 source rank (0..4) of the SERVER.
--                                    The proxy stamps a result's integrity from
--                                    this (NOT from anything the server claims).
--   tool_registry.required_integrity Biba floor: the minimum source integrity a
--                                    session must hold to invoke this SINK.
--
-- Defaults are deliberately asymmetric and BOTH fail closed:
--   * trust_tier DEFAULT 0  -> an unclassified SERVER is untrusted (its results
--                              taint the session).
--   * required_integrity DEFAULT 1 -> an unclassified TOOL is "deny-on-unknown":
--                              a tainted/low-integrity session is DENIED until an
--                              admin LOWERS it. A clean, trusted session still
--                              clears it (RFC §4.3). Default 0 would make the whole
--                              B-coarse layer allow-by-default (the round-2 fail-open).
--
-- Ranges are 0..4 (the full SEP-1913 lattice) even though the POC collapses them
-- to binary (untrusted = ranks 0..1, trusted = ranks 2..4); storing the full rank
-- now means the lattice upgrade is a code change, not a migration (RFC §4.3).
--
-- INV-011: explicit GRANT per-role; no wildcards.
-- =============================================================================

-- --- server_registry.trust_tier --------------------------------------------------
ALTER TABLE server_registry
    ADD COLUMN IF NOT EXISTS trust_tier SMALLINT NOT NULL DEFAULT 0
        CHECK (trust_tier BETWEEN 0 AND 4);

ALTER TABLE server_registry
    ADD COLUMN IF NOT EXISTS trust_tier_label TEXT
        CHECK (trust_tier_label IS NULL OR trust_tier_label IN
            ('untrustedPublic', 'trustedPublic', 'internal', 'user', 'system'));

COMMENT ON COLUMN server_registry.trust_tier IS
    'SEP-1913 source integrity rank (0=untrustedPublic .. 4=system) assigned by the '
    'platform to this server. The proxy stamps each result''s integrity_rank from '
    'this value; a server never sets its own trust tier (RFC-0001 P1). DEFAULT 0 = '
    'unclassified server is untrusted and taints sessions (fail-closed).';

-- --- tool_registry.required_integrity --------------------------------------------
ALTER TABLE tool_registry
    ADD COLUMN IF NOT EXISTS required_integrity SMALLINT NOT NULL DEFAULT 1
        CHECK (required_integrity BETWEEN 0 AND 4);

ALTER TABLE tool_registry
    ADD COLUMN IF NOT EXISTS sensitivity_label TEXT
        CHECK (sensitivity_label IS NULL OR sensitivity_label IN ('low', 'medium', 'high'));

COMMENT ON COLUMN tool_registry.required_integrity IS
    'Biba taint floor: minimum source integrity rank a session must hold to invoke '
    'this tool. DEFAULT 1 = deny-on-unknown (a tainted/untrusted session is denied an '
    'unclassified sink; a clean trusted session still clears it). The credential-'
    'injection safety bump (RFC-0001 W1.2) is applied at invoke time, not stored here.';

-- =============================================================================
-- GRANTs (INV-011: explicit, never wildcard)
-- =============================================================================
-- proxy_app: SELECT to read the floor/tier at invoke time; UPDATE so the admin
-- classification endpoints (PATCH tool required_integrity, server approve trust_tier)
-- can set them. New columns inherit table grants in PostgreSQL; re-stated here so the
-- per-column grant chain is explicit and verifiable by `make security-check`.
GRANT SELECT, UPDATE ON tool_registry   TO proxy_app;
GRANT SELECT, UPDATE ON server_registry TO proxy_app;
