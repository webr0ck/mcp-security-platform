-- 0003_audit.down.sql — reverse of 0003_audit.up.sql
--
-- REVIEW NOTE (db-engineer, D7 fix — deviation from the original
-- Architect design, documented per this crate's conventions): the
-- original version of this file was `DROP TABLE IF EXISTS audit_events`,
-- meaning `sqlx migrate revert` was a single, unconfirmed command that
-- permanently destroyed the append-only compliance ledger — the exact
-- data this table exists to make undestroyable. That is irreconcilable
-- with `audit_events` being append-only: a migration tool operator with
-- no special privileges beyond "can run migrations" could erase the
-- entire audit trail with one ordinary revert.
--
-- This migration is intentionally made irreversible via automated
-- tooling. If audit_events genuinely needs to be removed (e.g.
-- decommissioning an environment for good), that is a deliberate,
-- manual, superuser-attended DBA operation — archive the table's
-- contents out to cold storage first (see docs/db.md's retention policy
-- for this table), then drop it by hand — never something `sqlx migrate
-- revert` should be able to do unattended.
DO $$
BEGIN
    RAISE EXCEPTION
        'refusing to revert 0003_audit: this would DROP the append-only audit_events ledger. '
        'If you genuinely intend to destroy this table, archive its contents first and drop it '
        'manually as a superuser — do not run this down-migration through automated tooling.'
        USING ERRCODE = 'restrict_violation';
END
$$;
