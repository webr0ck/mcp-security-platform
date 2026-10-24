use std::collections::HashMap;

use hdrhistogram::Histogram;
use serde::Serialize;
use tokio::sync::mpsc;

/// Which lane a completed request belongs to. The deny lane MUST come out
/// faster than allow (fail-closed short-circuits the pipeline before policy
/// eval reaches credential injection / dispatch) -- if it doesn't, that's a
/// budget regression worth flagging even without an explicit assertion.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Lane {
    Allow,
    Deny,
    CredentialInjection,
}

/// One completed request, timed from its *scheduled* fire time (open-loop
/// arrival), not from when a thread actually got around to sending it. That
/// distinction is the entire coordinated-omission fix: under a closed-loop
/// client, a slow request delays the next request's send time, so queueing
/// delay never shows up in the histogram and p99 lies. Here every request's
/// intended start time is fixed by the rate scheduler up front regardless of
/// server load, so queueing delay is captured as latency, same as it would
/// be experienced by a real fleet of independent agents.
pub struct Sample {
    pub lane: Lane,
    /// Nanoseconds from scheduled fire time to response received.
    pub latency_ns: u64,
    pub outcome: Outcome,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum Outcome {
    Success,
    /// A genuine JSON-RPC-shaped policy denial (a `DenyReason` machine
    /// code) -- the request reached `invoke` and was denied by design.
    /// D6: this must NEVER be conflated with an HTTP-status failure below --
    /// they were previously both mapped to `Denied`, which let a gateway
    /// rejecting 100% of traffic (401/403/429, returned before enforcement
    /// even runs) land in the deny-lane histogram as sub-millisecond
    /// "successful denials" and report PASS.
    Denied(String),
    /// A non-2xx HTTP response with no JSON-RPC body (401/403/429/5xx) --
    /// this happened BEFORE `invoke` ran (auth/rate-limit/edge rejection),
    /// not a policy decision. Tracked separately so it can never silently
    /// inflate the deny lane's apparent throughput or pass rate.
    HttpError(u16),
    TransportError(String),
}

pub struct Collector {
    tx: mpsc::UnboundedSender<Sample>,
}

pub struct Aggregated {
    pub histograms: HashMap<Lane, Histogram<u64>>,
    pub outcomes: HashMap<Lane, HashMap<String, u64>>,
    pub total: u64,
}

impl Collector {
    /// Spawns the aggregator task and returns a cheap-to-clone sender handle
    /// plus a oneshot-style join handle that yields the final aggregate once
    /// the sender side is fully dropped.
    pub fn spawn() -> (Self, tokio::task::JoinHandle<Aggregated>) {
        let (tx, mut rx) = mpsc::unbounded_channel::<Sample>();
        let handle = tokio::spawn(async move {
            let mut histograms: HashMap<Lane, Histogram<u64>> = HashMap::new();
            let mut outcomes: HashMap<Lane, HashMap<String, u64>> = HashMap::new();
            let mut total = 0u64;
            for lane in [Lane::Allow, Lane::Deny, Lane::CredentialInjection] {
                // 1ns .. 60s range, 3 significant figures -- plenty for a
                // sub-50ms budget with room for pathological outliers.
                histograms.insert(
                    lane,
                    Histogram::new_with_bounds(1, 60_000_000_000, 3)
                        .expect("valid HDR histogram bounds"),
                );
            }
            while let Some(sample) = rx.recv().await {
                total += 1;
                // D6: only a request that actually reached `invoke` and got
                // a real decision (Success or a genuine policy Denied)
                // counts toward the lane's LATENCY histogram. An HttpError
                // (edge rejection before invoke ever ran) or a
                // TransportError (never got a response at all) measures
                // nothing about the enforcement path this harness exists to
                // budget -- letting them in was exactly how a gateway
                // rejecting 100% of traffic with fast 401s could report a
                // sub-millisecond p50 and PASS.
                let is_real_decision = matches!(sample.outcome, Outcome::Success | Outcome::Denied(_));
                if is_real_decision {
                    if let Some(h) = histograms.get_mut(&sample.lane) {
                        let _ = h.record(sample.latency_ns.max(1));
                    }
                }
                let code = match &sample.outcome {
                    Outcome::Success => "success".to_string(),
                    Outcome::Denied(reason) => reason.clone(),
                    Outcome::HttpError(status) => format!("http_error:{status}"),
                    Outcome::TransportError(e) => format!("transport_error:{e}"),
                };
                *outcomes
                    .entry(sample.lane)
                    .or_default()
                    .entry(code)
                    .or_insert(0) += 1;
            }
            Aggregated {
                histograms,
                outcomes,
                total,
            }
        });
        (Self { tx }, handle)
    }

    pub fn handle(&self) -> mpsc::UnboundedSender<Sample> {
        self.tx.clone()
    }
}
