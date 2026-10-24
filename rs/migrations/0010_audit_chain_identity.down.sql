-- 0010_audit_chain_identity.down.sql — reverse of
-- 0010_audit_chain_identity.up.sql. Dropping columns is schema-only; no
-- row content is lost for the columns that predate this migration.

DROP INDEX IF EXISTS idx_audit_events_chain;
ALTER TABLE audit_events DROP CONSTRAINT IF EXISTS uq_audit_events_chain_id_seq;
ALTER TABLE audit_events DROP COLUMN IF EXISTS chain_seq;
ALTER TABLE audit_events DROP COLUMN IF EXISTS chain_id;
