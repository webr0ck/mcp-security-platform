//! Redis-backed hot state: rate-limit counters, the token-exchange cache,
//! quarantine flags, and the audit stream. Every method returns
//! `Result<_, StoreError>` — there is no method here that swallows a redis
//! error and returns a default "allow" value. Per ARCHITECTURE.md
//! invariant 1, the caller (a gate in `mcphub-gateway`) is responsible for
//! mapping `Err` to `Decision::Deny`; this module's job is only to make
//! sure that mapping is possible, never to pre-decide it.

use crate::error::StoreError;
use redis::aio::ConnectionManager;
use redis::AsyncCommands;
use serde::{Deserialize, Serialize};
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use uuid::Uuid;

#[derive(Clone)]
pub struct RedisStore {
    conn: ConnectionManager,
}

/// One entry in a principal's anomaly sliding window, in exactly the shape
/// `policies/anomaly.rego` expects on `input.recent_calls`:
/// `[{tool_name: string, timestamp: number}]` (see that file's header
/// comment — this crate does not own the Rego bundle, but the wire shape
/// is a hard contract with it).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct RecentCall {
    pub tool_name: String,
    pub timestamp: f64,
}

/// Matches the Python platform's `_ANOMALY_WINDOW_SECONDS` (`proxy/app/
/// core/redis_client.py`) and the hardcoded `window_seconds: 300` already
/// baked into this rewrite's `authz.rego`.
pub const ANOMALY_WINDOW_SECONDS: i64 = 300;

/// `redis` crate's `ConnectionManagerConfig` default has NO response/connection
/// timeout (`None` — verified against the redis 0.27.6 source: unbounded).
/// That means every method on `RedisStore` was, until this fix, exposed to an
/// unbounded hang if the underlying TCP connection died without a clean RST
/// (e.g. the peer process killed mid-operation, a stalled network path) — the
/// `ConnectionManager` would retry with backoff and the `.await` on the
/// in-flight command simply never resolves. Discovered empirically while
/// mutation-testing the anomaly-window fail-closed behavior: a killed-mid-flight
/// redis produced a multi-second-plus hang, not a prompt `Err`, undermining
/// every fail-closed timing guarantee in the gateway (not just anomaly
/// detection — rate limiting, the audit stream, everything routed through
/// this connection). Bounded here so EVERY caller gets a bounded failure,
/// matching the same philosophy as `audit::LOCK_ACQUIRE_TIMEOUT` and
/// `pool::PoolConfig::acquire_timeout`.
const REDIS_RESPONSE_TIMEOUT: Duration = Duration::from_secs(1);
const REDIS_CONNECTION_TIMEOUT: Duration = Duration::from_secs(2);

impl RedisStore {
    pub async fn connect(redis_url: &str) -> Result<Self, StoreError> {
        let client = redis::Client::open(redis_url)?;
        let config = redis::aio::ConnectionManagerConfig::new()
            .set_response_timeout(REDIS_RESPONSE_TIMEOUT)
            .set_connection_timeout(REDIS_CONNECTION_TIMEOUT);
        let conn = client.get_connection_manager_with_config(config).await?;
        Ok(Self { conn })
    }

    /// Rate-limit counter: fixed-window `INCR` + first-write `EXPIRE`. The
    /// caller compares the returned count against the configured limit and
    /// denies (`RateLimited`) when it's exceeded — this method never makes
    /// that decision itself, it only reports the current count.
    pub async fn rate_limit_incr(&self, principal_id: &str, window: Duration) -> Result<i64, StoreError> {
        let key = format!("mcphub:ratelimit:{principal_id}");
        let mut conn = self.conn.clone();
        let count: i64 = conn.incr(&key, 1).await?;
        if count == 1 {
            // Only the first request in the window sets the TTL, so the
            // window doesn't get pushed back by every subsequent hit.
            let _: () = conn.expire(&key, window.as_secs() as i64).await?;
        }
        Ok(count)
    }

    /// Token-exchange cache (RFC 8693 downstream tokens), keyed by
    /// `(sub, server_id)`. TTL must always be set shorter than the
    /// downstream token's own expiry by the caller — this method does not
    /// inspect the token to compute that itself.
    pub async fn token_exchange_get(&self, sub: &str, server_id: &str) -> Result<Option<String>, StoreError> {
        let key = format!("mcphub:tokenx:{sub}:{server_id}");
        let mut conn = self.conn.clone();
        let value: Option<String> = conn.get(&key).await?;
        Ok(value)
    }

    pub async fn token_exchange_set(
        &self,
        sub: &str,
        server_id: &str,
        downstream_token: &str,
        ttl: Duration,
    ) -> Result<(), StoreError> {
        let key = format!("mcphub:tokenx:{sub}:{server_id}");
        let mut conn = self.conn.clone();
        let _: () = conn.set_ex(&key, downstream_token, ttl.as_secs()).await?;
        Ok(())
    }

    // REVIEW NOTE (D13 fix — removal, not a patch): this module used to
    // carry `quarantine_flag` / `set_quarantine_flag` / `clear_quarantine_
    // flag`, a Redis-backed "fast path" mirror of `quarantine_events`.
    // Three defects made it worse than not having it at all:
    //   1. `quarantine_flag` used `EXISTS(key)`, so a cache MISS (redis
    //      restart, eviction, failover, `FLUSHALL`) was indistinguishable
    //      from "not quarantined" — fail-OPEN on the one gate that exists
    //      specifically to fail closed.
    //   2. `set_quarantine_flag` set no TTL, so a stale flag (or a missed
    //      clear) could linger forever with no self-healing.
    //   3. `repo::quarantine::quarantine()`/`release()` never called
    //      these setters — grepping the whole workspace at the time of
    //      this fix found ZERO callers of any of the three methods
    //      anywhere in `bin/mcphubd`. The two stores were linked by
    //      nothing; this was dead, unreachable code that happened to
    //      compile.
    // The `Result<bool>` signature also cannot express "unknown" (a redis
    // read failure and "not quarantined" would have to collapse to the
    // same `Ok(false)` or the caller has to choose fail-open/fail-closed
    // itself with no crate-level guidance either way).
    //
    // Per the review's own suggested resolution ("either make it express
    // unknown and fail closed, or delete the Redis path so nobody wires
    // it for performance later"): deleted. `repo::quarantine::
    // is_quarantined` (Postgres, `idx_quarantine_events_open`) is the
    // real quarantine-gate lookup and remains fail-closed by construction
    // (a `StoreError` propagates as `Err`, never coerces to "not
    // quarantined"). If a redis-backed cache is added back later, it MUST
    // be wired to `repo::quarantine`'s write path in the same change that
    // adds it, must carry a TTL, and its read method must return
    // `Result<Option<bool>>` (or equivalent) so a cache miss cannot be
    // silently read as "clear".

    // -------------------------------------------------------------------
    // Anomaly sliding window (team-lead review, item 1 — CRITICAL): the
    // producer `authz.rego`'s anomaly structural deny rules depend on and
    // that never existed anywhere in the Rust tree, leaving every
    // anomaly rule permanently inert. Ported from the Python platform's
    // `push_anomaly_invocation` / `get_anomaly_window_with_timestamps`
    // (`proxy/app/core/redis_client.py`), with one deliberate
    // improvement: members are JSON-encoded with a uniqueness nonce
    // instead of Python's `f"{tool_name}:{timestamp}"` string, which (a)
    // breaks if `tool_name` itself contains `:` — legal per this crate's
    // own D9 ingress allowlist — and (b) collides in the sorted set if
    // the exact same tool is called twice at a timestamp that happens to
    // hash/compare equal, silently dropping the second call as "the same
    // entry updated" rather than two entries. A `ZADD` with a colliding
    // member REPLACES the old score instead of adding a second entry —
    // exactly the silent-undercount failure mode this window must not
    // have, since the whole point is accurate call counts for anomaly
    // rules like `bulk_read_spike` (`count(...) > 10`).
    //
    // FAIL-CLOSED (the entire point, per the Python comment this ports):
    // any redis error on either method is `Err`, never a coerced empty
    // window. `recent_calls_window` returning `Ok(vec![])` means "read
    // succeeded, this principal truly has no calls in the window" — it
    // must never mean "the read failed and we're pretending it didn't."
    // -------------------------------------------------------------------

    fn anomaly_window_key(principal_id: &str) -> String {
        format!("mcphub:anomaly:window:{principal_id}")
    }

    fn unix_seconds_now() -> Result<f64, StoreError> {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_secs_f64())
            .map_err(|e| StoreError::InvariantViolation(format!("system clock before UNIX epoch: {e}")))
    }

    /// Records one invocation into `principal_id`'s sliding window. Trims
    /// entries older than `ANOMALY_WINDOW_SECONDS` on every write (so the
    /// window never grows unbounded even for a principal that never gets
    /// read back) and refreshes the key's TTL to `2 * ANOMALY_WINDOW_SECONDS`
    /// so an idle principal's key self-expires rather than lingering
    /// forever — same rationale, same multiplier, as the Python original.
    pub async fn record_invocation(&self, principal_id: &str, tool_name: &str) -> Result<(), StoreError> {
        let key = Self::anomaly_window_key(principal_id);
        let now = Self::unix_seconds_now()?;
        let cutoff = now - ANOMALY_WINDOW_SECONDS as f64;
        let member = serde_json::to_string(&serde_json::json!({
            "tool_name": tool_name,
            "timestamp": now,
            "nonce": Uuid::new_v4().to_string(),
        }))?;

        let mut conn = self.conn.clone();
        let _: () = conn.zadd(&key, &member, now).await?;
        let _: () = conn.zrembyscore(&key, "-inf", cutoff).await?;
        let _: () = conn.expire(&key, ANOMALY_WINDOW_SECONDS * 2).await?;
        Ok(())
    }

    /// Reads `principal_id`'s current window (trimming stale entries
    /// first), in the exact shape `input.recent_calls` needs. Read-only —
    /// does NOT record an invocation; callers needing both must call
    /// `record_invocation` separately, matching the Python split between
    /// `push_anomaly_invocation` (write, used for scoring) and
    /// `get_anomaly_window_with_timestamps` (read-only, used to build the
    /// OPA input).
    pub async fn recent_calls_window(&self, principal_id: &str) -> Result<Vec<RecentCall>, StoreError> {
        let key = Self::anomaly_window_key(principal_id);
        let now = Self::unix_seconds_now()?;
        let cutoff = now - ANOMALY_WINDOW_SECONDS as f64;

        let mut conn = self.conn.clone();
        let _: () = conn.zrembyscore(&key, "-inf", cutoff).await?;
        let members: Vec<(String, f64)> = conn.zrangebyscore_withscores(&key, cutoff, "+inf").await?;

        members
            .into_iter()
            .map(|(member, _score)| {
                #[derive(Deserialize)]
                struct StoredCall {
                    tool_name: String,
                    timestamp: f64,
                }
                let parsed: StoredCall = serde_json::from_str(&member)?;
                Ok(RecentCall { tool_name: parsed.tool_name, timestamp: parsed.timestamp })
            })
            .collect()
    }

    /// Appends one entry to the audit stream (`XADD`). This is one half of
    /// the dual-emit required by ARCHITECTURE.md invariant 4 (redis stream
    /// + stdout JSON, both before the caller gets a response). Field order
    /// is preserved as given by the caller.
    pub async fn audit_stream_push(&self, fields: &[(&str, String)]) -> Result<String, StoreError> {
        let mut conn = self.conn.clone();
        let mut cmd = redis::cmd("XADD");
        cmd.arg("mcphub:audit").arg("*");
        for (k, v) in fields {
            cmd.arg(*k).arg(v);
        }
        let id: String = cmd.query_async(&mut conn).await?;
        Ok(id)
    }

    /// Batch counterpart of `audit_stream_push`, for the group-commit audit
    /// writer: one pipeline round trip for N events instead of N round trips.
    ///
    /// Pipelined, NOT `MULTI`/`EXEC`. Redis pipelining is not atomic, but
    /// atomicity buys nothing here: the durable ledger is Postgres, and the
    /// batch's Postgres INSERT is what commits (or doesn't) as a unit. This
    /// stream is the SIEM tail. What matters is that a redis failure fails the
    /// WHOLE batch — which it does, since any error short-circuits `?` and the
    /// caller denies every request in the batch together. Fail-closed per
    /// invariant 4, not a per-event partial success.
    pub async fn audit_stream_push_batch(
        &self,
        batch: &[Vec<(&str, String)>],
    ) -> Result<(), StoreError> {
        if batch.is_empty() {
            return Ok(());
        }
        let mut conn = self.conn.clone();
        let mut pipe = redis::pipe();
        for fields in batch {
            let cmd = pipe.cmd("XADD").arg("mcphub:audit").arg("*");
            for (k, v) in fields {
                cmd.arg(*k).arg(v);
            }
        }
        // Ignore the returned stream IDs — nothing consumes them, and
        // collecting them would allocate per event on the hot path.
        let _: () = pipe.query_async(&mut conn).await?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// This does not require a live redis instance: `redis::Client::open`
    /// fails locally for a malformed URL before any network I/O, which is
    /// enough to pin the "redis failure surfaces as Err, never Ok" contract
    /// for the connect path without needing a live server.
    #[tokio::test]
    async fn connect_with_invalid_url_is_err_not_panic() {
        let result = RedisStore::connect("not-a-redis-url").await;
        assert!(result.is_err());
    }

    /// A connection to a port nothing is listening on must surface as
    /// `Err`, never a default/empty "success" value — this is the crux of
    /// the "redis failure surfaces as Err" must-pass test. Uses a
    /// documentation/test-only port (9) that is never a real redis
    /// instance in CI, and a very small `response_timeout` so a redis
    /// instance actually running by coincidence on that port would still
    /// need to answer PING promptly, otherwise this fails fast rather than
    /// hanging.
    #[tokio::test]
    async fn operation_against_unreachable_redis_is_err() {
        let client = redis::Client::open("redis://127.0.0.1:9/").expect("valid url");
        let conn_result = tokio::time::timeout(
            Duration::from_secs(2),
            client.get_connection_manager(),
        )
        .await;

        // Either the connection attempt itself errors, or it times out —
        // both are "not a usable connection", which is what matters here.
        match conn_result {
            Ok(Ok(conn)) => {
                let store = RedisStore { conn };
                let op = store.rate_limit_incr("does-not-matter", Duration::from_secs(60)).await;
                assert!(op.is_err(), "operation against an unreachable redis must be Err");
            }
            Ok(Err(_)) | Err(_) => {
                // connect itself failed or timed out — also satisfies the
                // fail-closed contract (no Ok path was reachable).
            }
        }
    }

    // --- Anomaly sliding window ---------------------------------------

    fn test_redis_url() -> String {
        std::env::var("TEST_REDIS_URL").unwrap_or_else(|_| "redis://127.0.0.1:6379".to_string())
    }

    #[test]
    fn recent_call_member_round_trips_through_json() {
        // Pins the wire shape independent of any live redis — a tool_name
        // containing ':' (legal per this crate's D9 ingress allowlist)
        // must not corrupt parsing the way Python's `split(':')` design
        // would have.
        let member = serde_json::to_string(&serde_json::json!({
            "tool_name": "namespace:sub:tool",
            "timestamp": 1_700_000_000.123,
            "nonce": "irrelevant-to-the-caller",
        }))
        .unwrap();

        #[derive(Deserialize)]
        struct StoredCall {
            tool_name: String,
            timestamp: f64,
        }
        let parsed: StoredCall = serde_json::from_str(&member).unwrap();
        assert_eq!(parsed.tool_name, "namespace:sub:tool");
        assert_eq!(parsed.timestamp, 1_700_000_000.123);
    }

    #[tokio::test]
    #[ignore = "requires a live redis; run with `cargo test -- --ignored`"]
    async fn record_then_read_window_roundtrips() {
        let store = RedisStore::connect(&test_redis_url()).await.expect("connect to test redis");
        let principal = format!("anomaly-test-{}", Uuid::new_v4());

        store.record_invocation(&principal, "web_search").await.unwrap();
        store.record_invocation(&principal, "file_read").await.unwrap();
        store.record_invocation(&principal, "file_read").await.unwrap();

        let window = store.recent_calls_window(&principal).await.unwrap();
        assert_eq!(window.len(), 3, "all three recorded calls must appear in the window: {window:?}");
        let names: Vec<&str> = window.iter().map(|c| c.tool_name.as_str()).collect();
        assert_eq!(names, vec!["web_search", "file_read", "file_read"]);
        assert!(window.iter().all(|c| c.timestamp > 0.0));
    }

    /// Mutation proof: an unread/never-recorded principal must produce a
    /// SUCCESSFUL empty read (`Ok(vec![])`), not an error — this is the
    /// "correct no-history case" the anomaly.rego comment describes, and
    /// it must be distinguishable from the failure case below.
    #[tokio::test]
    #[ignore = "requires a live redis; run with `cargo test -- --ignored`"]
    async fn never_recorded_principal_reads_as_ok_empty_not_err() {
        let store = RedisStore::connect(&test_redis_url()).await.expect("connect to test redis");
        let principal = format!("anomaly-never-seen-{}", Uuid::new_v4());

        let window = store.recent_calls_window(&principal).await;
        assert_eq!(window.unwrap(), Vec::<RecentCall>::new());
    }

    /// Mutation proof for the CRITICAL fail-closed requirement itself: a
    /// read against an unreachable redis must be `Err`, and specifically
    /// must NOT collapse to the same `Ok(vec![])` an empty-but-healthy
    /// window produces — those two states are exactly what the Python
    /// comment says must never be conflated (empty reads as "no anomaly").
    #[tokio::test]
    async fn window_read_against_unreachable_redis_is_err_not_empty_ok() {
        let client = redis::Client::open("redis://127.0.0.1:9/").expect("valid url");
        let conn_result = tokio::time::timeout(Duration::from_secs(2), client.get_connection_manager()).await;

        match conn_result {
            Ok(Ok(conn)) => {
                let store = RedisStore { conn };
                let result = store.recent_calls_window("does-not-matter").await;
                assert!(
                    result.is_err(),
                    "a read against unreachable redis must be Err, never Ok(vec![]) — an empty vec is \
                     indistinguishable from a successful 'no history' read, which is the exact bug this \
                     producer exists to avoid"
                );
            }
            Ok(Err(_)) | Err(_) => { /* connect itself failed/timed out — also satisfies fail-closed */ }
        }
    }

    /// Same requirement as above, but via a LIVE connection that is killed
    /// mid-flight (not a connect-time failure) — this is what actually
    /// exercises `recent_calls_window`'s error-propagation code, since a
    /// connect-time failure never reaches that code at all (see the D5
    /// live-DB gotcha noted in this crate's memory: connect() against an
    /// always-refusing port can fail before ever touching the method under
    /// test). This is the test used for the mutation proof: with
    /// `.unwrap_or(())`/`.unwrap_or_default()` substituted into
    /// `recent_calls_window` (reproducing the bug this producer exists to
    /// prevent), this test goes red; reverting the substitution restores
    /// green — verified by hand for this change, see the handoff report.
    #[tokio::test]
    #[ignore = "requires a live Postgres-free podman; run with `cargo test -- --ignored`"]
    async fn window_read_against_killed_redis_is_err_not_empty_ok() {
        use std::process::Command;

        let container = format!("mcphub-anomaly-kill-test-{}", Uuid::new_v4().simple());
        let port = 17100 + (std::process::id() % 900) as u16;
        let start = Command::new("podman")
            .args(["run", "--rm", "-d", "--name", &container, "-p", &format!("{port}:6379"), "redis:7-alpine"])
            .output();
        let Ok(start) = start else {
            eprintln!("podman not available, skipping window_read_against_killed_redis_is_err_not_empty_ok");
            return;
        };
        if !start.status.success() {
            eprintln!("podman run failed, skipping: {}", String::from_utf8_lossy(&start.stderr));
            return;
        }
        tokio::time::sleep(Duration::from_millis(800)).await;

        let store = RedisStore::connect(&format!("redis://127.0.0.1:{port}/"))
            .await
            .expect("connect to the throwaway container");

        // Prove it's live first.
        store.record_invocation("warmup", "echo").await.expect("must work against the live container");

        let _ = Command::new("podman").args(["stop", "-t", "0", &container]).output();

        // A generous outer bound (well above REDIS_RESPONSE_TIMEOUT) — if
        // this fires, `RedisStore::connect`'s bounded response_timeout
        // isn't actually bounding anything, which is itself a failure
        // worth surfacing loudly rather than treating as "also fine".
        let result = tokio::time::timeout(Duration::from_secs(10), store.recent_calls_window("does-not-matter"))
            .await
            .expect("recent_calls_window against a killed connection must return within REDIS_RESPONSE_TIMEOUT, not hang");
        assert!(result.is_err(), "read against a killed redis mid-flight must be Err, never Ok(vec![])");

        let _ = Command::new("podman").args(["rm", "-f", &container]).output();
    }

    /// Same fail-closed requirement, write side: a failed `record_invocation`
    /// must also surface as `Err`, not silently succeed-and-drop the event.
    #[tokio::test]
    async fn record_against_unreachable_redis_is_err() {
        let client = redis::Client::open("redis://127.0.0.1:9/").expect("valid url");
        let conn_result = tokio::time::timeout(Duration::from_secs(2), client.get_connection_manager()).await;

        match conn_result {
            Ok(Ok(conn)) => {
                let store = RedisStore { conn };
                let result = store.record_invocation("does-not-matter", "echo").await;
                assert!(result.is_err(), "record_invocation against unreachable redis must be Err");
            }
            Ok(Err(_)) | Err(_) => { /* also satisfies fail-closed */ }
        }
    }

    /// Mutation proof for windowing: an entry older than
    /// `ANOMALY_WINDOW_SECONDS` must be trimmed out of the read, exactly
    /// matching what `authz.rego`'s comment says the producer is
    /// responsible for (the Rego rules themselves don't filter by time).
    #[tokio::test]
    #[ignore = "requires a live redis; run with `cargo test -- --ignored`"]
    async fn entries_older_than_the_window_are_trimmed() {
        let store = RedisStore::connect(&test_redis_url()).await.expect("connect to test redis");
        let principal = format!("anomaly-stale-{}", Uuid::new_v4());
        let key = RedisStore::anomaly_window_key(&principal);

        // Insert a stale entry directly (bypassing record_invocation,
        // which always stamps "now") to simulate a call from well outside
        // the window.
        let stale_ts = RedisStore::unix_seconds_now().unwrap() - (ANOMALY_WINDOW_SECONDS as f64) - 60.0;
        let stale_member = serde_json::to_string(&serde_json::json!({
            "tool_name": "ancient_call", "timestamp": stale_ts, "nonce": Uuid::new_v4().to_string(),
        }))
        .unwrap();
        let mut conn = store.conn.clone();
        let _: () = conn.zadd(&key, &stale_member, stale_ts).await.unwrap();

        store.record_invocation(&principal, "fresh_call").await.unwrap();

        let window = store.recent_calls_window(&principal).await.unwrap();
        let names: Vec<&str> = window.iter().map(|c| c.tool_name.as_str()).collect();
        assert_eq!(names, vec!["fresh_call"], "the stale entry must be trimmed, only the fresh one remains");
    }
}
