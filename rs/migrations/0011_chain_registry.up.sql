-- 0011_chain_registry.up.sql — a write-once-per-batch registry of each
-- chain's high-water mark, closing two false negatives in
-- `audit_verify::verify_chain` that the hash-chain walk alone cannot see
-- (team-lead review):
--
-- 1. TAIL TRUNCATION is invisible to the hash-chain walk. Delete the last
--    N rows of a chain and every surviving row still names its exact
--    predecessor correctly — nothing anchors the chain's END, only its
--    genesis (via `prev_hash IS NULL`) and its interior links.
-- 2. WHOLE-CHAIN DELETION is invisible. `verify_chain` discovers chains by
--    selecting DISTINCT `chain_id` out of `audit_events` itself — there is
--    no independent registry of which chains ever existed, so deleting
--    every row of one chain leaves nothing to report.
--
-- `chains` is that independent registry: one row per chain, holding the
-- highest `chain_seq`/`sha256_hash` that chain has ever reached. It is
-- updated by `mcphub_store::audit::insert_rows` in the SAME transaction as
-- the `audit_events` batch INSERT it accompanies (both commit together or
-- neither does), so it can never drift out of sync with a legitimately
-- written ledger. The verifier then has two independent checks: does every
-- `chains` row have at least one matching `audit_events` row (catches #2),
-- and does that chain's actual max `chain_seq` in `audit_events` match
-- what `chains` last recorded (catches #1).
--
-- This is deliberately a REGISTRY, not a full copy of the ledger — it
-- carries no `prev_hash` chain of its own and needs none: its only job is
-- to remember "how far did this chain legitimately get", which the
-- monotonic-increase trigger below makes expensive to falsify even for a
-- write-privileged (but non-owner, non-superuser) attacker.
CREATE TABLE IF NOT EXISTS chains (
    chain_id          UUID        PRIMARY KEY,
    started_at        TIMESTAMPTZ NOT NULL DEFAULT now(),
    last_chain_seq    BIGINT      NOT NULL,
    last_sha256_hash  CHAR(64)    NOT NULL,
    updated_at        TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- ---------------------------------------------------------------------------
-- Immutability, tuned for this table's actual write pattern (unlike
-- audit_events, `chains` IS legitimately UPDATEd — once per batch, to
-- advance the high-water mark). What must never happen, regardless of
-- which role issues the statement:
--   - DELETE: would let an attacker who deleted every row of a chain from
--     audit_events also erase the only evidence that chain ever existed.
--   - chain_id/started_at changing: identity of the row must be stable.
--   - last_chain_seq (or its paired hash) moving BACKWARD: the exact
--     falsification a tail-truncation attacker would want — delete rows,
--     then roll the registry back to match. Forward-only is enforced here
--     so the registry can lag behind a legitimate write (never happens in
--     practice — see the transactional wiring above) but can never be
--     walked backward.
-- ---------------------------------------------------------------------------
CREATE OR REPLACE FUNCTION fn_chains_no_delete()
RETURNS TRIGGER AS $$
BEGIN
    RAISE EXCEPTION 'chains is append/advance-only: DELETE is not permitted'
        USING ERRCODE = 'restrict_violation';
    RETURN NULL;
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER trg_chains_no_delete
    BEFORE DELETE ON chains
    FOR EACH ROW EXECUTE FUNCTION fn_chains_no_delete();

CREATE TRIGGER trg_chains_no_truncate
    BEFORE TRUNCATE ON chains
    FOR EACH STATEMENT EXECUTE FUNCTION fn_chains_no_delete();

CREATE OR REPLACE FUNCTION fn_chains_forward_only_update()
RETURNS TRIGGER AS $$
BEGIN
    IF NEW.chain_id IS DISTINCT FROM OLD.chain_id OR NEW.started_at IS DISTINCT FROM OLD.started_at THEN
        RAISE EXCEPTION 'chains row identity (chain_id, started_at) is immutable'
            USING ERRCODE = 'restrict_violation';
    END IF;
    IF NEW.last_chain_seq < OLD.last_chain_seq THEN
        RAISE EXCEPTION 'chains.last_chain_seq must never move backward (got % after %)', NEW.last_chain_seq, OLD.last_chain_seq
            USING ERRCODE = 'restrict_violation';
    END IF;
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER trg_chains_forward_only_update
    BEFORE UPDATE ON chains
    FOR EACH ROW EXECUTE FUNCTION fn_chains_forward_only_update();

-- mcphub_app needs to INSERT the genesis row and UPDATE the high-water
-- mark; DELETE/TRUNCATE stay ungranted (belt-and-braces alongside the
-- triggers above, same model as audit_events in 0004_ops.up.sql).
GRANT SELECT, INSERT, UPDATE ON chains TO mcphub_app;
