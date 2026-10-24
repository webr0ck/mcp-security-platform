//! Per-client rate limiting (`limits.py`'s `get_rate_limit` in the Python
//! platform), implemented with `governor`'s keyed GCRA limiter instead of a
//! Redis round trip. Keyed by `identity.sub` — one bucket per caller,
//! matching the Python `client_limits` table's per-client override model.
//!
//! Fail-closed: [`RateLimiter::check`] (the `mcphub-gateway` trait) maps a
//! governor "not yet" outcome to `GateError::RateLimited`, which
//! `to_deny_reason()` turns into `DenyReason::RateLimited` — never allow.
//! There is no dependency to go "unavailable" here (governor is in-process,
//! no I/O), so the only failure mode is the rate limit itself firing.

use governor::{DefaultKeyedRateLimiter, Quota, RateLimiter as GovernorLimiter};
use mcphub_gateway::traits::RateLimiter as RateLimiterTrait;
use mcphub_types::{GateError, Identity, ToolRef};
use std::num::NonZeroU32;

pub struct GovernorRateLimiter {
    limiter: DefaultKeyedRateLimiter<String>,
}

impl GovernorRateLimiter {
    /// `per_minute`: the role/client default quota. Per-client overrides
    /// (the Python `client_limits.rate_limit` column) are a follow-on —
    /// this crate exposes the mechanism (one limiter, swap the `Quota`) but
    /// wiring per-client quotas from Postgres is `mcphub-store`'s (component
    /// 4) job once that crate exists.
    pub fn new(per_minute: u32) -> Self {
        let quota = Quota::per_minute(NonZeroU32::new(per_minute.max(1)).expect("nonzero"));
        Self {
            limiter: GovernorLimiter::keyed(quota),
        }
    }
}

#[async_trait::async_trait]
impl RateLimiterTrait for GovernorRateLimiter {
    async fn check(&self, identity: &Identity, _tool: &ToolRef) -> Result<(), GateError> {
        self.limiter
            .check_key(&identity.sub)
            .map_err(|_not_until| GateError::RateLimited)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use mcphub_types::{GrantedRole, IssuerId, Role, ServerId, TokenRef};
    use uuid::Uuid;

    fn identity(sub: &str) -> Identity {
        Identity {
            sub: sub.into(),
            issuer: IssuerId::new("platform"),
            email: None,
            roles: vec![GrantedRole { role: Role::Employee, asserted_by: IssuerId::new("platform") }],
            groups: vec![],
            token_ref: TokenRef::none(),
        }
    }

    fn tool() -> ToolRef {
        ToolRef {
            server: ServerId::new(Uuid::nil()),
            tool: "ping".into(),
        }
    }

    #[tokio::test]
    async fn under_quota_allows_over_quota_denies() {
        let limiter = GovernorRateLimiter::new(2);
        let id = identity("alice");
        assert!(RateLimiterTrait::check(&limiter, &id, &tool()).await.is_ok());
        assert!(RateLimiterTrait::check(&limiter, &id, &tool()).await.is_ok());
        let err = RateLimiterTrait::check(&limiter, &id, &tool())
            .await
            .unwrap_err();
        assert_eq!(err.to_deny_reason(), mcphub_types::DenyReason::RateLimited);
    }

    #[tokio::test]
    async fn separate_identities_have_separate_buckets() {
        let limiter = GovernorRateLimiter::new(1);
        assert!(RateLimiterTrait::check(&limiter, &identity("alice"), &tool())
            .await
            .is_ok());
        assert!(RateLimiterTrait::check(&limiter, &identity("bob"), &tool())
            .await
            .is_ok());
    }
}
