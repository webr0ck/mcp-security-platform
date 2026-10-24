-- 0010_audit_chain_identity.up.sql — per-replica chain identity for
-- audit_events (team-lead review, item 3): `prev_hash` was a per-process
-- chain with no identity of its own. With exactly one replica that's
-- invisible; with two, both replicas' rows interleave in the single
-- `audit_events` table and an auditor walking `prev_hash` links with no
-- way to tell which chain a row belongs to sees what looks like a broken
-- or forked chain — the ledger would verify as tampered even though
-- nothing is wrong. This is a hard blocker on horizontal scaling, not a
-- nicety (per the review).
--
-- `chain_id` — one per process boot (assigned by `PgRedisAuditSink::new`,
-- not by the database) — and `chain_seq` — a per-chain monotonic counter
-- starting at 0 (the genesis row) — let a verifier partition the table by
-- chain_id and validate each chain's own prev_hash links independently of
-- how its rows interleave with any other chain's in insertion order.
--
-- A global total order across chains was considered (per the review) and
-- rejected: it needs a global serializer (e.g. a cross-replica advisory
-- lock around read-last-hash-then-insert), which is the exact latency
-- wall the group-commit work (item 2) is removing, not something to
-- reintroduce here.

ALTER TABLE audit_events ADD COLUMN chain_id UUID;
ALTER TABLE audit_events ADD COLUMN chain_seq BIGINT;

-- Backfill for any pre-existing rows (a single implicit chain, ordered by
-- the only ordering that existed before this migration: event_ts). Fresh
-- deployments have no rows at this point (this is a pre-release rewrite —
-- every test database reaches this migration with zero rows, since the
-- app never runs mid-migration); this exists so upgrading an environment
-- that already has audit history doesn't leave those rows permanently
-- unverifiable.
--
-- audit_events blocks UPDATE unconditionally (0003_audit.up.sql), for
-- every role, with no exception for migrations — so this backfill must
-- disable that guard for its own duration. This is the same "manual,
-- privileged, one-time DBA operation" carve-out documented on
-- 0003_audit.down.sql's refusal: a reviewed migration backfilling a new
-- column is not the ad-hoc tampering the trigger exists to stop.
ALTER TABLE audit_events DISABLE TRIGGER trg_audit_events_no_update;

DO $$
DECLARE
    legacy_chain_id UUID := gen_random_uuid();
BEGIN
    UPDATE audit_events
    SET chain_id = legacy_chain_id,
        chain_seq = sub.rn - 1
    FROM (
        SELECT event_id, row_number() OVER (ORDER BY event_ts, event_id) AS rn
        FROM audit_events
    ) sub
    WHERE audit_events.event_id = sub.event_id;
END
$$;

ALTER TABLE audit_events ENABLE TRIGGER trg_audit_events_no_update;

ALTER TABLE audit_events ALTER COLUMN chain_id SET NOT NULL;
ALTER TABLE audit_events ALTER COLUMN chain_seq SET NOT NULL;

-- A chain can never have two rows claiming the same position — this is a
-- structural guard against a corrupted/duplicate-seq write, independent
-- of the hash chain itself.
ALTER TABLE audit_events ADD CONSTRAINT uq_audit_events_chain_id_seq UNIQUE (chain_id, chain_seq);

-- Serves the verifier's per-chain partition + ordered walk.
CREATE INDEX IF NOT EXISTS idx_audit_events_chain
    ON audit_events (chain_id, chain_seq);
