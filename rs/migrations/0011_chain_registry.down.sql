-- 0011_chain_registry.down.sql — reverse of 0011_chain_registry.up.sql
--
-- Same rationale as 0003_audit.down.sql: `chains` is the only independent
-- record of "how far did each chain legitimately get", which is exactly
-- what makes tail-truncation and whole-chain-deletion detectable in
-- `audit_verify::verify_chain`. An unattended `sqlx migrate revert` that
-- silently drops this table would quietly disable both detections with no
-- operator ever having decided that was acceptable. As with 0003, if this
-- genuinely needs to go away, that is a deliberate, manual, superuser-
-- attended DBA operation, not something automated tooling should do.
DO $$
BEGIN
    RAISE EXCEPTION
        'refusing to revert 0011_chain_registry: this would DROP the chains registry, silently '
        'disabling tail-truncation and whole-chain-deletion detection in audit_verify::verify_chain. '
        'If you genuinely intend to remove it, do so manually as a superuser, not through automated tooling.'
        USING ERRCODE = 'restrict_violation';
END
$$;
