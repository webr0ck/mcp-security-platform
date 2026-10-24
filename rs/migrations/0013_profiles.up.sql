-- 0013_profiles.up.sql — backs `mcphub-selfservice`'s per-identity MCP
-- profile management (the self-service port of the Python platform's
-- `proxy/app/routers/profiles.py` + `mcp_profiles` table).
--
-- `profiles` is a genuinely different shape from `grants`
-- (0002_grants_credentials.up.sql), not an overlapping/competing table for
-- the same concept:
--   - `grants` (existing): what a principal is PERMITTED to call at all —
--     an allowlist of tool names/tags plus a max risk ceiling, written by
--     admins/`grant_role`-equivalent flows, read by the RBAC/entitlement
--     gate on every invoke.
--   - `profiles` (this table): a principal's own OPT-OUT of MCPs/functions
--     they ARE otherwise permitted to call — a self-service toggle, written
--     by the principal about themselves (or by an admin on their behalf),
--     read to further narrow what an already-permitted call may do.
--
-- Composition at enforcement time (this is the load-bearing decision — see
-- ARCHITECTURE.md's enforcement-order note for where this plugs into the
-- chain): a call is allowed only if BOTH `grants` permits it AND `profiles`
-- does not exclude it. Neither table alone is sufficient, and neither can
-- override the other in the permissive direction — `profiles` can only ever
-- narrow, never widen, what `grants` already allows. Concretely: enabled=
-- false always denies regardless of grants; allowed_functions (when
-- non-NULL) is an additional allowlist intersected with whatever functions
-- grants/RBAC would otherwise permit, never a superset of it.
--
-- allowed_functions NULL semantics — deliberately mirrors the Python
-- platform's `mcp_profiles.allowed_functions` exactly, including its odd
-- disable-from-unrestricted behavior (see
-- `mcphub-selfservice::profile_tools::disable_function`'s doc comment for
-- the full rationale): NULL means "unrestricted — every function this MCP
-- exposes is allowed" (the common/default state). A non-NULL value is an
-- explicit allowlist — a function absent from a non-NULL list is denied.
-- Disabling a function while unrestricted (NULL) does NOT drop just that
-- one function; it collapses the profile to an EMPTY allowlist (deny all,
-- including every function not yet inspected) — the caller must then
-- explicitly re-enable what they still want. This is intentional, not
-- ported carelessly: the alternative (materializing "every function name
-- except this one" into the allowlist) requires knowing the MCP's full
-- function set at write time, which this table has no way to know.
CREATE TABLE IF NOT EXISTS profiles (
    profile_id          UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
    principal_id        TEXT        NOT NULL,
    mcp_name            TEXT        NOT NULL,
    enabled             BOOLEAN     NOT NULL DEFAULT TRUE,
    allowed_functions   TEXT[],
    updated_by          TEXT        NOT NULL,
    created_at          TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at          TIMESTAMPTZ NOT NULL DEFAULT now(),

    CONSTRAINT uq_profiles_principal_mcp UNIQUE (principal_id, mcp_name)
);

COMMENT ON COLUMN profiles.allowed_functions IS
    'NULL = unrestricted (all functions of this MCP allowed) — the default. Non-NULL = explicit allowlist; absence from a non-NULL list denies. NEVER read as a denylist.';

-- Hot query: read on the profile-composition gate for every invoke against
-- an MCP that has any profile row at all (absence of a row = unrestricted,
-- same default as allowed_functions=NULL, so a principal with zero
-- self-service activity pays no extra lookup cost beyond the index probe).
CREATE INDEX IF NOT EXISTS idx_profiles_principal_mcp
    ON profiles (principal_id, mcp_name);

CREATE TRIGGER trg_profiles_updated_at
    BEFORE UPDATE ON profiles
    FOR EACH ROW EXECUTE FUNCTION fn_set_updated_at();
