-- 0012_tool_required_role.up.sql — backs `mcphub-gateway::invocation::
-- check_rbac`'s per-tool required-role gate, ARCHITECTURE.md's mandated
-- enforcement chain step 4. Previously this had no schema column at all,
-- so `bin/mcphubd`'s `EntitlementStore` adapter hardcoded `required_role:
-- None` for every tool — the gate was live and unit-tested in
-- `mcphub-gateway` but structurally unreachable in production (no tool it
-- ever saw carried a required role).
--
-- NULL semantics (deliberately the OPPOSITE of tool_registry.risk_level,
-- and that difference is intentional, not an inconsistency to "fix" later
-- — see mcphub-gateway::invocation::check_rbac's doc comment for the same
-- note from the code side):
--   - risk_level NULL means "unscanned" and must fail closed (strictest
--     tier) — the tool exists and its risk is genuinely unknown, and an
--     unknown risk defaulting to permissive would silently widen every
--     grant's ceiling.
--   - required_role NULL means "no per-tool role requirement" (allow,
--     subject to every other gate) — this is not "unknown", it is the
--     TRUE, common, unremarkable state for a tool: most tools have no
--     extra role requirement above whatever RBAC/grants already demand.
--     Every existing row is NULL after this migration; reading NULL as
--     "deny everything" would instantly lock out the entire platform on
--     deploy, which is not what an operator adding this column ever
--     intends. A tool that genuinely needs a role floor gets one by
--     explicitly setting this column — the requirement is opt-in, not
--     opt-out.
ALTER TABLE tool_registry ADD COLUMN required_role role_enum;

COMMENT ON COLUMN tool_registry.required_role IS
    'Per-tool RBAC floor (ARCHITECTURE.md chain step 4). NULL = no extra role requirement beyond grants/RBAC (the common case, and the default for every existing row) — NOT "unknown, deny". Set explicitly to require a specific role (e.g. quarantine-release tools requiring security_analyst).';
