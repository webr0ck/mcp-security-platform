//! Offline/online chain verifier for `audit_events` (D3).
//!
//! Before this module existed, nothing anywhere in the codebase (no
//! verifier, no CLI, no test) ever recomputed a stored row's hash and
//! compared it — the tamper-evidence the schema's doc comments promised
//! was entirely theoretical. This module is that verifier:
//!
//! - **Hash integrity**: recompute each row's HMAC-SHA256 core-field
//!   digest (`audit::canonical_core_json`, keyed by the same
//!   `hmac_key` the sink used to write it) from the row's own stored
//!   columns, and compare against the stored `sha256_hash`. A mismatch
//!   means the row's content was rewritten after the fact (or the row
//!   was never written by a process holding the correct key).
//! - **Chain continuity**: for every row with a non-NULL `prev_hash`,
//!   confirm some row in the table has that value as its `sha256_hash`.
//!   A `prev_hash` with no matching row is evidence of a deleted or
//!   rewritten predecessor — the append-only trigger should make that
//!   unreachable through normal SQL, so surfacing it here is exactly the
//!   point (a DB-owner-level bypass, per D7, is the scenario this catches).
//!
//! `bin/mcphubd` (or a standalone ops binary) should expose
//! [`verify_chain`] behind a CLI subcommand for auditors — see this
//! crate's handoff report for the exact wiring this needs (the HMAC key
//! must be available wherever the verifier runs, same as the sink).

use crate::audit::{canonical_core_json, AuditEnrichment, AuditRecord, Outcome};
use crate::error::StoreError;
use crate::hash::hmac_sha256_hex;
use sqlx::PgPool;
use std::collections::BTreeMap;
use uuid::Uuid;

#[derive(Debug, Clone, Default)]
pub struct ChainVerifyReport {
    pub total_checked: usize,
    /// event_ids whose recomputed hash does not match the stored hash —
    /// the row's own content was altered after being written.
    pub hash_mismatches: Vec<Uuid>,
    /// event_ids whose `prev_hash` does not resolve to any row's
    /// `sha256_hash` in the checked set — a broken chain link.
    pub broken_links: Vec<Uuid>,
    /// chain_ids present in the `chains` registry but with ZERO rows in
    /// `audit_events` — an entire chain's history was deleted. Neither the
    /// hash check nor the link walk above can ever see this: both only
    /// examine rows that still exist.
    pub deleted_chains: Vec<Uuid>,
    /// chain_ids whose registered high-water mark (`chains.last_chain_seq`)
    /// is GREATER than the highest `chain_seq` actually present in
    /// `audit_events` for that chain — the chain's tail was truncated.
    /// Every surviving row can still name its exact predecessor correctly
    /// (so the link walk stays clean), which is exactly why this needs its
    /// own independent check.
    pub truncated_chains: Vec<Uuid>,
}

impl ChainVerifyReport {
    pub fn is_clean(&self) -> bool {
        self.hash_mismatches.is_empty()
            && self.broken_links.is_empty()
            && self.deleted_chains.is_empty()
            && self.truncated_chains.is_empty()
    }
}

#[derive(Debug, sqlx::FromRow)]
struct ChainRegistryRow {
    chain_id: Uuid,
    last_chain_seq: i64,
    last_sha256_hash: String,
}

#[derive(Debug, sqlx::FromRow)]
struct AuditRow {
    event_id: Uuid,
    event_ts: time::OffsetDateTime,
    request_id: String,
    principal_id: String,
    issuer: Option<String>,
    server_id: Option<Uuid>,
    tool_id: Option<Uuid>,
    tool_name: String,
    outcome: String,
    deny_reason: Option<String>,
    latency_ms: Option<i32>,
    source_ip: Option<String>,
    sha256_hash: String,
    prev_hash: Option<String>,
    redacted_fields: serde_json::Value,
    created_at: time::OffsetDateTime,
    chain_id: Uuid,
    chain_seq: i64,
}

/// Verifies every row currently in `audit_events`. For a large table a
/// real deployment would want a time-ranged variant (`WHERE event_ts
/// BETWEEN ...`) run incrementally by a compliance job; the query shape
/// here is the same, just without the bound — left as a follow-up rather
/// than speculative scope for this fix.
pub async fn verify_chain(pool: &PgPool, hmac_key: &[u8]) -> Result<ChainVerifyReport, StoreError> {
    let rows: Vec<AuditRow> = sqlx::query_as(
        r#"
        SELECT event_id, event_ts, request_id, principal_id, issuer, server_id, tool_id,
               tool_name, outcome::text, deny_reason, latency_ms, host(source_ip) AS source_ip,
               sha256_hash, prev_hash, redacted_fields, created_at,
               chain_id, chain_seq
        FROM audit_events
        ORDER BY chain_id, chain_seq ASC
        "#,
    )
    .fetch_all(pool)
    .await?;

    // Partition by chain, then walk each chain in `chain_seq` order. The
    // previous check ("does this prev_hash exist ANYWHERE in the table?") was
    // far too weak: it passed for a row spliced into the wrong position, or
    // reassigned to another chain entirely, as long as the hash it pointed at
    // existed somewhere. Ordering by (chain_id, chain_seq) lets us assert the
    // exact predecessor instead.
    let mut by_chain: BTreeMap<Uuid, Vec<&AuditRow>> = BTreeMap::new();
    for row in &rows {
        by_chain.entry(row.chain_id).or_default().push(row);
    }

    let mut report = ChainVerifyReport { total_checked: rows.len(), ..Default::default() };

    for row in &rows {
        let outcome = Outcome::from_db_str(&row.outcome).ok_or_else(|| {
            StoreError::InvariantViolation(format!("audit_events row {} has unrecognized outcome {:?}", row.event_id, row.outcome))
        })?;
        let record = AuditRecord {
            event_id: row.event_id,
            request_id: row.request_id.clone(),
            principal_id: row.principal_id.clone(),
            issuer: row.issuer.clone(),
            server_id: row.server_id,
            tool_id: row.tool_id,
            tool_name: row.tool_name.clone(),
            outcome,
            deny_reason: row.deny_reason.clone(),
            latency_ms: row.latency_ms,
            source_ip: row.source_ip.clone(),
            enrichment: AuditEnrichment::default(), // unused by canonical_core_json; redacted_fields passed explicitly below
        };

        let event_ts_iso = row
            .event_ts
            .format(&time::format_description::well_known::Rfc3339)
            .map_err(|e| StoreError::InvariantViolation(e.to_string()))?;
        let created_at_iso = row
            .created_at
            .format(&time::format_description::well_known::Rfc3339)
            .map_err(|e| StoreError::InvariantViolation(e.to_string()))?;

        let core_json =
            canonical_core_json(&record, &event_ts_iso, &created_at_iso, &row.redacted_fields, row.chain_id, row.chain_seq);
        let core_bytes = serde_json::to_vec(&core_json)?;
        let expected = hmac_sha256_hex(hmac_key, &core_bytes);

        if expected != row.sha256_hash {
            report.hash_mismatches.push(row.event_id);
        }

    }

    // Per-chain link walk. Within a chain, row N's `prev_hash` must be exactly
    // row N-1's `sha256_hash`, and the genesis row (lowest `chain_seq`) must
    // have no predecessor. Anything else is a break, a splice, or a fork.
    for (_chain_id, chain_rows) in &by_chain {
        let mut expected_prev: Option<&str> = None;
        for row in chain_rows {
            let ok = match (expected_prev, row.prev_hash.as_deref()) {
                // Genesis: no predecessor, and none claimed.
                (None, None) => true,
                // Genesis position but claims a predecessor => spliced head.
                (None, Some(_)) => false,
                // Mid-chain: must name its immediate predecessor exactly.
                (Some(want), Some(got)) => want == got,
                // Mid-chain but claims nothing => severed link.
                (Some(_), None) => false,
            };
            if !ok {
                report.broken_links.push(row.event_id);
            }
            expected_prev = Some(row.sha256_hash.as_str());
        }
    }

    // Cross-check against the independent `chains` registry (0011): this
    // is the only thing in this function that can see a chain whose rows
    // are GONE, or a chain whose tail is shorter than it should be — both
    // invisible to the hash check and the link walk above, which only ever
    // look at rows that still exist. See 0011_chain_registry.up.sql for why
    // this registry can be trusted to lag behind reality but never lie
    // ahead of it (forward-only update trigger, no DELETE grant).
    let registry: Vec<ChainRegistryRow> =
        sqlx::query_as("SELECT chain_id, last_chain_seq, last_sha256_hash FROM chains").fetch_all(pool).await?;

    for entry in &registry {
        match by_chain.get(&entry.chain_id) {
            None => {
                // The registry knows this chain existed; audit_events has
                // not one row from it. Whole-chain deletion.
                report.deleted_chains.push(entry.chain_id);
            }
            Some(chain_rows) => {
                // `by_chain`'s rows are already ordered by chain_seq ASC
                // (the top query's ORDER BY), so the last element is this
                // chain's highest surviving row.
                let last_row = chain_rows.last().expect("by_chain groups are only ever built from a non-empty push, never empty");
                let seq_shrunk = entry.last_chain_seq > last_row.chain_seq;
                // Belt-and-braces beyond the seq count: even if the
                // surviving row COUNT matches, the registry's recorded
                // tail hash must match the actual surviving tail row's
                // hash — catches a tail row deleted and replaced by a
                // forged row at the same chain_seq (only defeats an
                // attacker without the HMAC key if the forged content
                // also fails its own hash_mismatch check above; this is
                // the layer that still catches it if they somehow have
                // the key too).
                let tail_hash_diverged = entry.last_chain_seq == last_row.chain_seq && entry.last_sha256_hash != last_row.sha256_hash;
                if seq_shrunk || tail_hash_diverged {
                    report.truncated_chains.push(entry.chain_id);
                }
            }
        }
    }

    Ok(report)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Fixed chain identity for hashing tests. These tests compare hashes to
    /// each other (determinism, field coverage, tamper detection), so the chain
    /// values only need to be consistent, not meaningful.
    const TEST_CHAIN_ID: Uuid = Uuid::nil();
    const TEST_CHAIN_SEQ: i64 = 0;

    use crate::testing::test_pool_migrated;

    const TEST_HMAC_KEY: &[u8] = b"test-only-hmac-key-32-bytes-min!";

    /// `event_ts` is bound explicitly (NOT `now()`) and used for BOTH
    /// `event_ts` and `created_at` — the hash a caller computes to pass as
    /// `sha256_hash` MUST be over this exact same timestamp, or
    /// `verify_chain`'s recompute will (correctly!) disagree with what's
    /// stored, which is a real bug this test caught in an earlier draft:
    /// computing the hash against a fixed ISO string while letting the
    /// INSERT default to `now()` guarantees a mismatch even for an
    /// untampered row.
    async fn insert_row_in_chain(
        pool: &sqlx::PgPool,
        event_id: Uuid,
        event_ts: time::OffsetDateTime,
        sha256_hash: &str,
        prev_hash: Option<&str>,
        chain_id: Uuid,
        chain_seq: i64,
    ) {
        sqlx::query(
            r#"
            INSERT INTO audit_events (
                event_id, event_ts, request_id, principal_id, issuer, server_id, tool_id,
                tool_name, outcome, deny_reason, latency_ms, source_ip, sha256_hash, prev_hash,
                redacted_fields, created_at, chain_id, chain_seq
            ) VALUES ($1, $4, 'req-1', 'alice', 'https://idp.example.com', NULL, NULL,
                      'echo', 'allow', NULL, 3, '127.0.0.1'::inet, $2, $3, '{}'::jsonb, $4, $5, $6)
            "#,
        )
        .bind(event_id)
        .bind(sha256_hash)
        .bind(prev_hash)
        .bind(event_ts)
        .bind(chain_id)
        .bind(chain_seq)
        .execute(pool)
        .await
        .unwrap();
    }

    /// Seeds the `chains` registry row a real `PgRedisAuditSink` writer
    /// would have committed transactionally alongside the batch that wrote
    /// this chain's true last row — these tests bypass the sink entirely
    /// (no live redis needed), so they seed both tables by hand to
    /// reproduce exactly what a legitimate writer leaves behind.
    async fn insert_chain_registry_row(pool: &sqlx::PgPool, chain_id: Uuid, last_chain_seq: i64, last_sha256_hash: &str) {
        sqlx::query("INSERT INTO chains (chain_id, last_chain_seq, last_sha256_hash) VALUES ($1, $2, $3)")
            .bind(chain_id)
            .bind(last_chain_seq)
            .bind(last_sha256_hash)
            .execute(pool)
            .await
            .unwrap();
    }

    /// `chain_id`/`chain_seq` became NOT NULL in 0010 and are part of the
    /// hashed preimage, so they must match TEST_CHAIN_ID/TEST_CHAIN_SEQ —
    /// the same values these tests hash against.
    async fn insert_row(
        pool: &sqlx::PgPool,
        event_id: Uuid,
        event_ts: time::OffsetDateTime,
        sha256_hash: &str,
        prev_hash: Option<&str>,
    ) {
        insert_row_in_chain(pool, event_id, event_ts, sha256_hash, prev_hash, TEST_CHAIN_ID, TEST_CHAIN_SEQ).await;
    }

    /// Shared record shape for the multi-row chain tests below — only
    /// `event_id` varies.
    fn sample_record(event_id: Uuid) -> AuditRecord {
        AuditRecord {
            event_id,
            request_id: "req-1".into(),
            principal_id: "alice".into(),
            issuer: Some("https://idp.example.com".into()),
            server_id: None,
            tool_id: None,
            tool_name: "echo".into(),
            outcome: Outcome::Allow,
            deny_reason: None,
            latency_ms: Some(3),
            source_ip: Some("127.0.0.1".into()),
            enrichment: AuditEnrichment::default(),
        }
    }

    /// Computes the hash a correctly-behaving sink would have stored for
    /// this record at this chain position.
    fn hash_for(event_id: Uuid, event_ts: time::OffsetDateTime, chain_id: Uuid, chain_seq: i64) -> String {
        let ts_iso = event_ts.format(&time::format_description::well_known::Rfc3339).unwrap();
        let record = sample_record(event_id);
        let redacted = serde_json::json!({});
        let core_json = canonical_core_json(&record, &ts_iso, &ts_iso, &redacted, chain_id, chain_seq);
        hmac_sha256_hex(TEST_HMAC_KEY, &serde_json::to_vec(&core_json).unwrap())
    }

    #[tokio::test]
    #[ignore = "requires a live Postgres; run with `cargo test -- --ignored`"]
    async fn detects_a_row_whose_content_was_rewritten_after_the_fact() {
        // Mutation proof for D3's "nothing verifies the chain" half: write
        // one row through the real sink-shaped INSERT with a CORRECT hash,
        // confirm verify_chain passes, then directly rewrite the row's
        // content (bypassing the app entirely, simulating the "attacker
        // with DB write access" threat model) WITHOUT recomputing the
        // hash, and confirm verify_chain now flags it.
        //
        // audit_events blocks UPDATE at the trigger level (0003_audit.up.sql)
        // — even for this test we must disable the guard the same way a
        // privileged DB-level attacker would (D7's exact scenario), proving
        // this is a realistic tamper path, not a synthetic one.
        let pool = test_pool_migrated().await;

        let event_id = Uuid::new_v4();
        let record = AuditRecord {
            event_id,
            request_id: "req-1".into(),
            principal_id: "alice".into(),
            issuer: Some("https://idp.example.com".into()),
            server_id: None,
            tool_id: None,
            tool_name: "echo".into(),
            outcome: Outcome::Allow,
            deny_reason: None,
            latency_ms: Some(3),
            source_ip: Some("127.0.0.1".into()),
            enrichment: AuditEnrichment::default(),
        };
        let redacted = serde_json::json!({});
        let event_ts = time::OffsetDateTime::from_unix_timestamp(1_700_000_000).unwrap();
        let ts_iso = event_ts.format(&time::format_description::well_known::Rfc3339).unwrap();
        let core_json = canonical_core_json(&record, &ts_iso, &ts_iso, &redacted, TEST_CHAIN_ID, TEST_CHAIN_SEQ);
        let correct_hash = hmac_sha256_hex(TEST_HMAC_KEY, &serde_json::to_vec(&core_json).unwrap());

        insert_row(&pool, event_id, event_ts, &correct_hash, None).await;

        let before = verify_chain(&pool, TEST_HMAC_KEY).await.unwrap();
        assert!(before.hash_mismatches.is_empty(), "freshly-written, untampered row must verify clean: {before:?}");

        // Simulate a DB-owner-level attacker: disable the append-only
        // guard, rewrite source_ip (a forensically decisive field, per
        // D6) without touching sha256_hash, re-enable the guard.
        sqlx::query("ALTER TABLE audit_events DISABLE TRIGGER trg_audit_events_no_update")
            .execute(&pool)
            .await
            .unwrap();
        sqlx::query("UPDATE audit_events SET source_ip = '203.0.113.99'::inet WHERE event_id = $1")
            .bind(event_id)
            .execute(&pool)
            .await
            .unwrap();
        sqlx::query("ALTER TABLE audit_events ENABLE TRIGGER trg_audit_events_no_update")
            .execute(&pool)
            .await
            .unwrap();

        let after = verify_chain(&pool, TEST_HMAC_KEY).await.unwrap();
        assert!(
            after.hash_mismatches.contains(&event_id),
            "tampered row must be flagged by the verifier: {after:?}"
        );
    }

    #[tokio::test]
    #[ignore = "requires a live Postgres; run with `cargo test -- --ignored`"]
    async fn detects_a_broken_chain_link() {
        let pool = test_pool_migrated().await;
        let event_id = Uuid::new_v4();
        let event_ts = time::OffsetDateTime::from_unix_timestamp(1_700_000_001).unwrap();
        // prev_hash points at a hash no row in the table actually has. Hash
        // itself is bogus too (this test only cares about broken_links, not
        // hash_mismatches — a spurious hash mismatch here is expected and
        // ignored).
        insert_row(&pool, event_id, event_ts, &"a".repeat(64), Some(&"b".repeat(64))).await;

        let report = verify_chain(&pool, TEST_HMAC_KEY).await.unwrap();
        assert!(report.broken_links.contains(&event_id), "dangling prev_hash must be flagged: {report:?}");
    }

    /// Mutation proof for the mid-chain arm of the per-chain link walk,
    /// `(Some(want), Some(got)) => want == got`. The critic replaced this
    /// arm with a bare `true` and all 40 live-DB tests stayed green,
    /// because `detects_a_broken_chain_link` above only exercises the
    /// GENESIS arm (`(None, Some(_)) => false`, a single-row chain with a
    /// dangling `prev_hash`) — never a chain deep enough to reach the
    /// mid-chain comparison at all. Three properly-linked rows; row 2's
    /// `prev_hash` is then rewritten to row 0's hash instead of row 1's —
    /// a real, valid hash that exists in the table, just not this row's
    /// immediate predecessor. With the mutation (`true`), this passes
    /// silently; with the real comparison, it must be flagged.
    #[tokio::test]
    #[ignore = "requires a live Postgres; run with `cargo test -- --ignored`"]
    async fn mid_chain_row_naming_a_skipped_predecessor_is_flagged_broken() {
        let pool = test_pool_migrated().await;
        let chain_id = Uuid::new_v4();
        let base_ts = 1_700_100_000i64;

        let ids: Vec<Uuid> = (0..3).map(|_| Uuid::new_v4()).collect();
        let mut hashes: Vec<String> = Vec::with_capacity(3);
        let mut prev: Option<String> = None;
        for (seq, &event_id) in ids.iter().enumerate() {
            let event_ts = time::OffsetDateTime::from_unix_timestamp(base_ts + seq as i64).unwrap();
            let hash = hash_for(event_id, event_ts, chain_id, seq as i64);
            insert_row_in_chain(&pool, event_id, event_ts, &hash, prev.as_deref(), chain_id, seq as i64).await;
            prev = Some(hash.clone());
            hashes.push(hash);
        }

        let before = verify_chain(&pool, TEST_HMAC_KEY).await.unwrap();
        assert!(before.broken_links.is_empty(), "freshly-written, correctly-linked chain must verify clean: {before:?}");

        // Attack: row 2 (chain_seq=2) claims row 0's hash as its
        // predecessor instead of row 1's. sha256_hash is untouched, so
        // this is purely a broken_links case, not a hash_mismatch — the
        // point is to isolate the mid-chain arm specifically.
        sqlx::query("ALTER TABLE audit_events DISABLE TRIGGER trg_audit_events_no_update").execute(&pool).await.unwrap();
        sqlx::query("UPDATE audit_events SET prev_hash = $1 WHERE event_id = $2")
            .bind(&hashes[0])
            .bind(ids[2])
            .execute(&pool)
            .await
            .unwrap();
        sqlx::query("ALTER TABLE audit_events ENABLE TRIGGER trg_audit_events_no_update").execute(&pool).await.unwrap();

        let after = verify_chain(&pool, TEST_HMAC_KEY).await.unwrap();
        assert!(after.broken_links.contains(&ids[2]), "a row naming a non-immediate predecessor must be flagged: {after:?}");
        assert!(
            !after.broken_links.contains(&ids[0]) && !after.broken_links.contains(&ids[1]),
            "only the tampered row should be flagged: {after:?}"
        );
    }

    /// Regression pin for the exact bug this module's own doc comment
    /// describes: the OLD check ("does this prev_hash exist ANYWHERE in
    /// the table?") passed for a row "reassigned to another chain
    /// entirely, as long as the hash it pointed at existed somewhere" — a
    /// row could be spliced into a chain it was never written into. The
    /// per-chain partition walk is supposed to close this; this proves it
    /// still does.
    #[tokio::test]
    #[ignore = "requires a live Postgres; run with `cargo test -- --ignored`"]
    async fn row_reassigned_to_a_different_chain_is_flagged_broken() {
        let pool = test_pool_migrated().await;
        let chain_a = Uuid::new_v4();
        let chain_b = Uuid::new_v4();

        // Chain A: two properly linked rows.
        let a0 = Uuid::new_v4();
        let a0_ts = time::OffsetDateTime::from_unix_timestamp(1_700_200_000).unwrap();
        let a0_hash = hash_for(a0, a0_ts, chain_a, 0);
        insert_row_in_chain(&pool, a0, a0_ts, &a0_hash, None, chain_a, 0).await;

        let a1 = Uuid::new_v4();
        let a1_ts = time::OffsetDateTime::from_unix_timestamp(1_700_200_001).unwrap();
        let a1_hash = hash_for(a1, a1_ts, chain_a, 1);
        insert_row_in_chain(&pool, a1, a1_ts, &a1_hash, Some(&a0_hash), chain_a, 1).await;

        // Chain B: one genesis row, no predecessor.
        let b0 = Uuid::new_v4();
        let b0_ts = time::OffsetDateTime::from_unix_timestamp(1_700_200_002).unwrap();
        let b0_hash = hash_for(b0, b0_ts, chain_b, 0);
        insert_row_in_chain(&pool, b0, b0_ts, &b0_hash, None, chain_b, 0).await;

        let before = verify_chain(&pool, TEST_HMAC_KEY).await.unwrap();
        assert!(
            before.broken_links.is_empty() && before.hash_mismatches.is_empty(),
            "before the attack, both independent chains must verify clean: {before:?}"
        );

        // Attack: reassign chain A's second row (a1) into chain B, keeping
        // its ORIGINAL prev_hash (naming chain A's genesis — a real hash,
        // just not anything in chain B) and its chain_seq (=1, so it sorts
        // after b0's seq=0 in its new partition).
        sqlx::query("ALTER TABLE audit_events DISABLE TRIGGER trg_audit_events_no_update").execute(&pool).await.unwrap();
        sqlx::query("UPDATE audit_events SET chain_id = $1 WHERE event_id = $2")
            .bind(chain_b)
            .bind(a1)
            .execute(&pool)
            .await
            .unwrap();
        sqlx::query("ALTER TABLE audit_events ENABLE TRIGGER trg_audit_events_no_update").execute(&pool).await.unwrap();

        let after = verify_chain(&pool, TEST_HMAC_KEY).await.unwrap();
        assert!(
            after.broken_links.contains(&a1),
            "a row spliced into a different chain, still naming its ORIGINAL chain's predecessor, must be flagged: {after:?}"
        );
    }

    /// Tail truncation: delete the last row(s) of a chain and every
    /// surviving row still names its exact predecessor correctly (the
    /// per-chain link walk stays clean, and so does the hash check — see
    /// the assertions on `before`/`after` above the attack, then note
    /// `hash_mismatches`/`broken_links` are asserted EMPTY again after it
    /// too). Only the `chains` registry cross-check — added in 0011 for
    /// exactly this gap — can see it: the registry still remembers a
    /// higher `chain_seq` than any row left on disk.
    #[tokio::test]
    #[ignore = "requires a live Postgres; run with `cargo test -- --ignored`"]
    async fn truncated_chain_tail_is_flagged() {
        let pool = test_pool_migrated().await;
        let chain_id = Uuid::new_v4();
        let base_ts = 1_700_300_000i64;

        let ids: Vec<Uuid> = (0..3).map(|_| Uuid::new_v4()).collect();
        let mut prev: Option<String> = None;
        let mut last_hash = String::new();
        for (seq, &event_id) in ids.iter().enumerate() {
            let event_ts = time::OffsetDateTime::from_unix_timestamp(base_ts + seq as i64).unwrap();
            let hash = hash_for(event_id, event_ts, chain_id, seq as i64);
            insert_row_in_chain(&pool, event_id, event_ts, &hash, prev.as_deref(), chain_id, seq as i64).await;
            prev = Some(hash.clone());
            last_hash = hash;
        }
        // What a real `PgRedisAuditSink` writer would have committed
        // transactionally alongside row 2 (chain_seq=2, the true tail).
        insert_chain_registry_row(&pool, chain_id, 2, &last_hash).await;

        let before = verify_chain(&pool, TEST_HMAC_KEY).await.unwrap();
        assert!(before.is_clean(), "freshly-written, untampered chain (rows + registry) must verify clean: {before:?}");

        // Attack: delete the true tail row (chain_seq=2) straight out of
        // audit_events, bypassing the append-only guard the same way D7's
        // DB-owner-level attacker would — and, critically, WITHOUT touching
        // `chains` (an attacker deleting rows has no reason to also know
        // about, or be able to roll back, the forward-only registry).
        sqlx::query("ALTER TABLE audit_events DISABLE TRIGGER trg_audit_events_no_delete").execute(&pool).await.unwrap();
        sqlx::query("DELETE FROM audit_events WHERE event_id = $1").bind(ids[2]).execute(&pool).await.unwrap();
        sqlx::query("ALTER TABLE audit_events ENABLE TRIGGER trg_audit_events_no_delete").execute(&pool).await.unwrap();

        let after = verify_chain(&pool, TEST_HMAC_KEY).await.unwrap();
        assert!(after.truncated_chains.contains(&chain_id), "a chain whose tail was deleted must be flagged truncated: {after:?}");
        assert!(after.hash_mismatches.is_empty(), "the two surviving rows are untouched — no hash mismatch should fire: {after:?}");
        assert!(
            after.broken_links.is_empty(),
            "the two surviving rows still link to each other correctly — the link walk alone cannot see a truncated tail: {after:?}"
        );
    }

    /// Whole-chain deletion: drop every row of one chain and, since chains
    /// are discovered by `SELECT DISTINCT chain_id FROM audit_events`
    /// itself, there is nothing left for the hash check or link walk to
    /// even iterate over — a naive verifier reports clean. The `chains`
    /// registry is the only thing that remembers this chain ever existed.
    #[tokio::test]
    #[ignore = "requires a live Postgres; run with `cargo test -- --ignored`"]
    async fn deleted_chain_is_flagged() {
        let pool = test_pool_migrated().await;
        let chain_id = Uuid::new_v4();
        let event_ts = time::OffsetDateTime::from_unix_timestamp(1_700_400_000).unwrap();
        let event_id = Uuid::new_v4();
        let hash = hash_for(event_id, event_ts, chain_id, 0);
        insert_row_in_chain(&pool, event_id, event_ts, &hash, None, chain_id, 0).await;
        insert_chain_registry_row(&pool, chain_id, 0, &hash).await;

        let before = verify_chain(&pool, TEST_HMAC_KEY).await.unwrap();
        assert!(before.is_clean(), "freshly-written, untampered chain (rows + registry) must verify clean: {before:?}");

        sqlx::query("ALTER TABLE audit_events DISABLE TRIGGER trg_audit_events_no_delete").execute(&pool).await.unwrap();
        sqlx::query("DELETE FROM audit_events WHERE chain_id = $1").bind(chain_id).execute(&pool).await.unwrap();
        sqlx::query("ALTER TABLE audit_events ENABLE TRIGGER trg_audit_events_no_delete").execute(&pool).await.unwrap();

        let after = verify_chain(&pool, TEST_HMAC_KEY).await.unwrap();
        assert!(
            after.deleted_chains.contains(&chain_id),
            "a chain the registry remembers but that has zero rows left must be flagged deleted: {after:?}"
        );
    }

    #[tokio::test]
    #[ignore = "requires a live Postgres; run with `cargo test -- --ignored`"]
    async fn wrong_hmac_key_flags_every_row_as_tampered() {
        // Pins the "keyed, not just SHA-256" half of D3: a verifier run
        // with the wrong key must not silently pass.
        let pool = test_pool_migrated().await;
        let event_id = Uuid::new_v4();
        let record = AuditRecord {
            event_id,
            request_id: "req-1".into(),
            principal_id: "alice".into(),
            issuer: Some("https://idp.example.com".into()),
            server_id: None,
            tool_id: None,
            tool_name: "echo".into(),
            outcome: Outcome::Allow,
            deny_reason: None,
            latency_ms: Some(3),
            source_ip: Some("127.0.0.1".into()),
            enrichment: AuditEnrichment::default(),
        };
        let redacted = serde_json::json!({});
        let event_ts = time::OffsetDateTime::from_unix_timestamp(1_700_000_002).unwrap();
        let ts_iso = event_ts.format(&time::format_description::well_known::Rfc3339).unwrap();
        let core_json = canonical_core_json(&record, &ts_iso, &ts_iso, &redacted, TEST_CHAIN_ID, TEST_CHAIN_SEQ);
        let correct_hash = hmac_sha256_hex(TEST_HMAC_KEY, &serde_json::to_vec(&core_json).unwrap());
        insert_row(&pool, event_id, event_ts, &correct_hash, None).await;

        let with_correct_key = verify_chain(&pool, TEST_HMAC_KEY).await.unwrap();
        assert!(with_correct_key.hash_mismatches.is_empty());

        let with_wrong_key = verify_chain(&pool, b"wrong-key-also-32-bytes-long!!!!").await.unwrap();
        assert!(with_wrong_key.hash_mismatches.contains(&event_id));
    }
}
