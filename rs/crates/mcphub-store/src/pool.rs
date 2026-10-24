//! Postgres connection pool, sized for the 3000-concurrent-agent workload
//! in `rs/ARCHITECTURE.md`'s performance budget (p99 <= 15ms added
//! latency, >= 20k req/s on 8 cores).
//!
//! The pool does NOT need 3000 connections: every hot query (grant lookup,
//! audit insert, quarantine check, rate-limit read) is a single indexed
//! point lookup or insert taking low-single-digit milliseconds, so a
//! modest pool serves very high concurrency by turning connections over
//! fast. Sizing a pool at or near the client count instead just moves the
//! bottleneck to Postgres's own connection overhead (each backend is a
//! full OS process) for no throughput benefit.

use crate::error::StoreError;
use sqlx::postgres::{PgConnectOptions, PgPoolOptions};
use sqlx::PgPool;
use std::str::FromStr;
use std::time::Duration;

/// Numbers below assume a single `mcphubd` instance per Postgres. Multiple
/// gateway replicas each get their own pool sized the same way; scale
/// `max_connections` down per-replica (or raise Postgres's `max_connections`)
/// if you run more than ~4 replicas against one database.
pub struct PoolConfig {
    /// Upper bound on concurrent backends this instance holds open.
    /// 64 is deliberately far below 3000: at p50 ~3ms and p99 ~15ms per
    /// query, 64 connections clear roughly 4,000-20,000 queries/sec, which
    /// covers the throughput budget with headroom for bursts, while
    /// leaving room under Postgres's default `max_connections = 100` for
    /// the migration runner, `psql`, and the compliance/anomaly workers.
    pub max_connections: u32,
    /// Keep a small warm floor so a burst after an idle period does not
    /// pay full connection-establishment latency (TLS handshake included,
    /// since we run rustls).
    pub min_connections: u32,
    /// Fail-closed timing: `acquire` gives up quickly rather than queuing
    /// callers indefinitely behind a saturated pool. A caller that can't
    /// get a connection in 500ms denies the request (DependencyUnavailable)
    /// rather than blowing the p99.9 <= 50ms budget waiting.
    pub acquire_timeout: Duration,
    /// Recycle idle connections after 5 minutes to avoid holding backends
    /// open against a mostly-idle period (cost on the Postgres side is a
    /// full process per connection).
    pub idle_timeout: Duration,
    /// Force periodic reconnection so long-lived connections don't
    /// accumulate server-side session state or ride out a failed-over
    /// Postgres primary indefinitely.
    pub max_lifetime: Duration,
    /// Prepared-statement cache size per connection. The hot-path query
    /// set is small and fixed (grant lookup, audit insert, quarantine
    /// check, rate-limit read, tool lookup) — 100 comfortably covers it
    /// with room for admin-path queries without unbounded growth.
    pub statement_cache_capacity: usize,
}

impl Default for PoolConfig {
    fn default() -> Self {
        Self {
            max_connections: 64,
            min_connections: 8,
            acquire_timeout: Duration::from_millis(500),
            idle_timeout: Duration::from_secs(300),
            max_lifetime: Duration::from_secs(1800),
            statement_cache_capacity: 100,
        }
    }
}

pub async fn connect(database_url: &str, config: PoolConfig) -> Result<PgPool, StoreError> {
    let connect_options = PgConnectOptions::from_str(database_url)
        .map_err(StoreError::Db)?
        .statement_cache_capacity(config.statement_cache_capacity);

    let pool = PgPoolOptions::new()
        .max_connections(config.max_connections)
        .min_connections(config.min_connections)
        .acquire_timeout(config.acquire_timeout)
        .idle_timeout(config.idle_timeout)
        .max_lifetime(config.max_lifetime)
        .connect_with(connect_options)
        .await?;

    Ok(pool)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_pool_config_stays_well_below_agent_count() {
        // 3000 concurrent agents must never map 1:1 onto Postgres backends.
        let cfg = PoolConfig::default();
        assert!(cfg.max_connections < 200);
        assert!(cfg.min_connections <= cfg.max_connections);
    }

    #[test]
    fn acquire_timeout_is_bounded_for_fail_closed_deny_latency() {
        let cfg = PoolConfig::default();
        // REVIEW NOTE (D13 fix): the original bound here was `<= 1s`,
        // which cannot fail for any realistic regression — someone could
        // change `acquire_timeout` from 500ms to 950ms (nearly doubling
        // caller-visible deny latency, and blowing the p99.9 <= 50ms
        // budget by 19x) and this test would still pass. Tightened to
        // match the documented default and give real headroom above the
        // budget it's meant to protect, without being so tight that
        // legitimate tuning (e.g. 300-500ms) trips it.
        assert!(
            cfg.acquire_timeout <= Duration::from_millis(500),
            "acquire_timeout regressed to {:?} — this directly caps how long a caller waits before a \
             dependency-unavailable deny, which must stay well under the p99.9 <= 50ms budget's slack",
            cfg.acquire_timeout
        );
    }

    /// Mutation proof: this is the exact regression the tightened test
    /// above is meant to catch — a value the OLD `<= 1s` assertion let
    /// through silently.
    #[test]
    fn nine_hundred_fifty_ms_would_have_passed_the_old_bound_but_fails_the_new_one() {
        let regressed = Duration::from_millis(950);
        assert!(regressed <= Duration::from_secs(1), "sanity: this is what the old bound accepted");
        assert!(regressed > Duration::from_millis(500), "and this is what the new bound correctly rejects");
    }
}
