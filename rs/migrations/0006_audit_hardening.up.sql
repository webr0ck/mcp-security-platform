-- 0006_audit_hardening.up.sql — close append-only bypass vectors left open
-- by 0003_audit.up.sql (db-engineer review, see the defect report this
-- migration responds to: D7).
--
-- Deviation from the original 0003 design, documented per this crate's
-- "Architect Deviations" convention: we add to the schema here (a new
-- migration) rather than editing 0003's up-script in place, so an
-- already-applied 0003 is never invalidated by a checksum mismatch.
-- 0003_audit.down.sql IS edited directly by this same change (see its
-- diff) — that file guarded nothing today (`DROP TABLE IF EXISTS
-- audit_events` was a one-command unguarded destruction of the ledger) and
-- there is no way to layer a "refuse to destroy" behavior on top of an
-- unconditional DROP from a later migration; the fix has to live at the
-- point of destruction.

-- ---------------------------------------------------------------------------
-- Vector 1: TRUNCATE. Row-level triggers (BEFORE UPDATE/DELETE FOR EACH ROW,
-- added in 0003) never fire for TRUNCATE — it is a statement-level DDL-ish
-- operation. A statement-level guard is the only way to intercept it.
-- ---------------------------------------------------------------------------
CREATE TRIGGER trg_audit_events_no_truncate
    BEFORE TRUNCATE ON audit_events
    FOR EACH STATEMENT EXECUTE FUNCTION fn_audit_events_immutability_guard();

-- ---------------------------------------------------------------------------
-- Vector 2 (partial — see review notes): `ON DELETE SET NULL` on the
-- server_id/tool_id FKs is itself an UPDATE against audit_events, which
-- contradicts append-only. In practice the row-level UPDATE guard trigger
-- wins and the DELETE on `servers`/`tool_registry` fails — but with a
-- confusing error that blames audit_events's trigger rather than the
-- actual constraint conflict. Since servers/tool_registry are already
-- soft-delete-only tables (never hard-deleted through the sanctioned
-- write path — see repo::tools's `hard_delete_is_blocked` regression
-- test and the equivalent guard on servers), a hard DELETE reaching this
-- FK at all is already an anomaly; RESTRICT makes that anomaly fail with
-- a clear, correctly-attributed foreign-key-violation error instead of a
-- confusing trigger error, and makes the schema's own DDL assert the
-- append-only invariant rather than relying on the trigger to catch a
-- self-inflicted UPDATE.
-- ---------------------------------------------------------------------------
ALTER TABLE audit_events DROP CONSTRAINT audit_events_server_id_fkey;
ALTER TABLE audit_events
    ADD CONSTRAINT audit_events_server_id_fkey
    FOREIGN KEY (server_id) REFERENCES servers (server_id) ON DELETE RESTRICT;

ALTER TABLE audit_events DROP CONSTRAINT audit_events_tool_id_fkey;
ALTER TABLE audit_events
    ADD CONSTRAINT audit_events_tool_id_fkey
    FOREIGN KEY (tool_id) REFERENCES tool_registry (tool_id) ON DELETE RESTRICT;

-- ---------------------------------------------------------------------------
-- Vectors 3 & 4 (DROP TABLE, ALTER TABLE ... DISABLE TRIGGER ALL) are not
-- fixable in SQL alone: both require table ownership (or superuser), and
-- Postgres has no "even the owner can't do this" mode. The structural fix
-- is that the RUNTIME must never connect as the table owner or a
-- superuser — mcphub_app already lacks TRUNCATE/ALTER/DROP privileges
-- (0004_ops.up.sql only grants SELECT/INSERT on audit_events), so as long
-- as `mcphubd` actually authenticates as mcphub_app (not `postgres` or
-- whichever role ran the migrations), these two vectors are already
-- closed by privilege, not by trigger. `mcphub-store::security::
-- assert_non_privileged_connection` (new in this change) is the
-- fail-closed runtime check that this precondition actually holds at
-- startup — see this crate's handoff report for the exact `bin/mcphubd`
-- wiring this requires.
-- ---------------------------------------------------------------------------
