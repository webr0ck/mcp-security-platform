-- V042: Add 'disabled' as a valid tool_registry status.
-- 'disabled' = service not deployed/available (not a security block).
-- 'quarantined' remains the status for security-blocked tools.
ALTER TABLE tool_registry
    DROP CONSTRAINT tool_registry_status_check;

ALTER TABLE tool_registry
    ADD CONSTRAINT tool_registry_status_check
    CHECK (status::text = ANY (ARRAY[
        'active'::text,
        'quarantined'::text,
        'deprecated'::text,
        'disabled'::text
    ]));
