-- =============================================================================
-- V081__clarify_self_service_profile_tool_descriptions.sql
-- Fix 5 (docs/spec/11-server-lifecycle-and-hardening-batch.md, finding 5):
-- "profile" naming collision. The 5 self-service meta-tools seeded by V078
-- (get_profile/enable_mcp/disable_mcp/enable_function/disable_function,
-- `target_profile` argument) operate on PER-IDENTITY rows in
-- `mcp_profiles`/`profile_mcp_bindings` keyed by the caller's own principal.
-- They are a *different system* from the admin-only, session-bound NAMED
-- profiles (routers/profiles.py `/named` endpoints, bound at OIDC login via
-- `?profile=<name>`, REST-only — no MCP tool covers them). Both call
-- themselves "profile" in ordinary language, which has led to callers
-- building against the wrong one. Append a one-line disambiguator to each
-- description so it's visible directly in `tools/list` output, without
-- reading external docs first. See
-- docs/troubleshooting/profile-naming.md for the full explanation.
--
-- Idempotent (plain UPDATE ... SET, safe to re-run) and audit-safe (no DELETE,
-- no schema change).
-- =============================================================================
BEGIN;

UPDATE tool_registry
SET description = description || ' (Per-identity self-service profile — NOT the '
  || 'session-bound named profile set via ?profile= at login. See '
  || 'docs/troubleshooting/profile-naming.md.)',
    updated_at = now()
WHERE deleted_at IS NULL
  AND name IN ('get_profile', 'enable_mcp', 'disable_mcp', 'enable_function', 'disable_function')
  AND description NOT LIKE '%docs/troubleshooting/profile-naming.md%';

COMMIT;

-- =============================================================================
-- Down migration: not provided — this only appends a documentation suffix to
-- existing description text; reversing it would require string-matching the
-- exact suffix back out, which is more risk than value for a text-only change.
-- =============================================================================
