use std::collections::HashMap;

use hdrhistogram::Histogram;
use serde::Serialize;

use crate::metrics::{Aggregated, Lane};

#[derive(Serialize)]
pub struct LaneReport {
    pub count: u64,
    pub p50_ms: f64,
    pub p90_ms: f64,
    pub p99_ms: f64,
    pub p999_ms: f64,
    pub max_ms: f64,
    pub errors: HashMap<String, u64>,
}

#[derive(Serialize)]
pub struct Report {
    pub duration_secs: u64,
    /// Actual wall-clock time from the first dispatched request to the last
    /// drained response, in seconds (D6: NOT the same as `duration_secs`,
    /// the nominal --duration-secs arrival-window length -- draining
    /// in-flight requests after the arrival window closes takes real time
    /// too, and dividing by the shorter nominal window inflated
    /// throughput_req_s).
    pub wall_clock_secs: f64,
    pub total_requests: u64,
    pub throughput_req_s: f64,
    /// Fraction of ALL completed requests (every lane, every outcome
    /// including HttpError/TransportError) that got a real decision
    /// (Success or a genuine policy Denied). D6: a gateway rejecting most
    /// traffic at the edge (401/403/429) is a harness/target-under-test
    /// failure, not something assert_budget should silently pass through
    /// because the FEW requests that did complete happened to be fast.
    pub success_rate: f64,
    pub lanes: HashMap<String, LaneReport>,
    pub rss_bytes: Option<u64>,
    pub budget: Option<BudgetResult>,
}

#[derive(Serialize)]
pub struct BudgetResult {
    pub p50_ok: bool,
    pub p99_ok: bool,
    pub p999_ok: bool,
    pub throughput_ok: bool,
    pub success_rate_ok: bool,
    pub rss_ok: Option<bool>,
    pub pass: bool,
}

fn ms(hist: &Histogram<u64>, pct: f64) -> f64 {
    hist.value_at_percentile(pct) as f64 / 1_000_000.0
}

pub fn build(agg: Aggregated, duration_secs: u64, wall_clock_secs: f64, rss_bytes: Option<u64>) -> Report {
    let mut lanes = HashMap::new();
    let mut real_decisions = 0u64;
    let mut all_completed = 0u64;
    for (lane, hist) in &agg.histograms {
        let key = match lane {
            Lane::Allow => "allow",
            Lane::Deny => "deny",
            Lane::CredentialInjection => "credential_injection",
        };
        let errors = agg.outcomes.get(lane).cloned().unwrap_or_default();
        for (code, n) in &errors {
            all_completed += n;
            if code == "success" || !(code.starts_with("http_error:") || code.starts_with("transport_error:")) {
                // "success" and any genuine DenyReason machine code both
                // count as a real decision; only the two edge-rejection
                // buckets don't.
                real_decisions += n;
            }
        }
        lanes.insert(
            key.to_string(),
            LaneReport {
                count: hist.len(),
                p50_ms: ms(hist, 50.0),
                p90_ms: ms(hist, 90.0),
                p99_ms: ms(hist, 99.0),
                p999_ms: ms(hist, 99.9),
                max_ms: hist.max() as f64 / 1_000_000.0,
                errors,
            },
        );
    }
    // D6: divide by ACTUAL wall-clock time, not the nominal arrival-window
    // duration -- requests dispatched near the end of the arrival window
    // are still being drained after it closes, so `total` reflects more
    // elapsed time than `duration_secs` alone accounts for.
    let throughput = agg.total as f64 / wall_clock_secs.max(0.001);
    let success_rate = if all_completed == 0 { 0.0 } else { real_decisions as f64 / all_completed as f64 };
    Report {
        duration_secs,
        wall_clock_secs,
        total_requests: agg.total,
        throughput_req_s: throughput,
        success_rate,
        lanes,
        rss_bytes,
        budget: None,
    }
}

/// Budget from rs/ARCHITECTURE.md "Performance budget": measured against the
/// `allow` lane (the deny lane is explicitly expected to be faster, not
/// bound by the same numbers).
///
/// CAVEAT (D6, not fixed by this function -- documented because it's easy
/// to miss): ARCHITECTURE.md's budget is stated as "measured at the
/// gateway, excluding backend time." This harness measures END TO END from
/// the client, INCLUDING backend time -- there is no gateway-side
/// instrumentation here. `--assert-budget` therefore asserts a strictly
/// harsher quantity than the budget as written; a run that fails this gate
/// is not necessarily a budget miss at the gateway. Add gateway-side
/// latency instrumentation (component 1's concern, not loadgen's) to close
/// this gap for real, or treat this assertion as an upper bound only.
pub fn assert_budget(report: &mut Report, target_rate: u64, min_success_rate: f64) {
    let allow = report.lanes.get("allow");
    let (p50_ok, p99_ok, p999_ok) = match allow {
        Some(l) => (l.p50_ms <= 3.0, l.p99_ms <= 15.0, l.p999_ms <= 50.0),
        None => (false, false, false),
    };
    // D6: no more unconditional pass below the target rate -- a run at any
    // --rate must hit its OWN target_rate (within measurement noise), not
    // silently succeed just because it wasn't asking for >=20k. The 20k
    // figure from ARCHITECTURE.md is asserted only when target_rate asked
    // for it; below that, the achieved rate is compared against what was
    // actually requested.
    let throughput_floor = (target_rate as f64) * 0.95;
    let throughput_ok = report.throughput_req_s >= throughput_floor;
    // D6 mandatory success-rate gate: previously absent entirely, so a run
    // where every request 401s (0% real decisions) had nothing stopping it
    // from reporting PASS.
    let success_rate_ok = report.success_rate >= min_success_rate;
    let rss_ok = report
        .rss_bytes
        .map(|b| b < 512 * 1024 * 1024);
    let pass = p50_ok && p99_ok && p999_ok && throughput_ok && success_rate_ok && rss_ok.unwrap_or(true);
    report.budget = Some(BudgetResult {
        p50_ok,
        p99_ok,
        p999_ok,
        throughput_ok,
        success_rate_ok,
        rss_ok,
        pass,
    });
}

pub fn print_human(report: &Report) {
    println!(
        "\n=== loadgen report ({} req, {}s nominal window / {:.1}s wall clock, {:.0} req/s, {:.1}% real decisions) ===",
        report.total_requests,
        report.duration_secs,
        report.wall_clock_secs,
        report.throughput_req_s,
        report.success_rate * 100.0
    );
    let mut lane_names: Vec<&String> = report.lanes.keys().collect();
    lane_names.sort();
    for name in lane_names {
        let l = &report.lanes[name];
        println!(
            "  [{name:22}] n={:<8} p50={:>6.2}ms p90={:>6.2}ms p99={:>6.2}ms p99.9={:>7.2}ms max={:>8.2}ms",
            l.count, l.p50_ms, l.p90_ms, l.p99_ms, l.p999_ms, l.max_ms
        );
        let mut errs: Vec<(&String, &u64)> = l.errors.iter().collect();
        errs.sort_by(|a, b| b.1.cmp(a.1));
        for (code, n) in errs {
            println!("      {code:30} {n}");
        }
    }
    match report.rss_bytes {
        Some(b) => println!("  RSS: {:.1} MB", b as f64 / (1024.0 * 1024.0)),
        None => println!("  RSS: not measured (pass --server-pid to sample it)"),
    }
    if let Some(b) = &report.budget {
        println!(
            "\n  budget: p50={} p99={} p99.9={} throughput={} success_rate={} rss={} => {}",
            okstr(b.p50_ok),
            okstr(b.p99_ok),
            okstr(b.p999_ok),
            okstr(b.throughput_ok),
            okstr(b.success_rate_ok),
            b.rss_ok.map(okstr).unwrap_or("skipped"),
            if b.pass { "PASS" } else { "FAIL" }
        );
        println!(
            "  NOTE: measured client-side end-to-end (including backend time). \
             ARCHITECTURE.md's budget is measured at the gateway, excluding backend \
             time -- this assertion is a harsher upper bound, not the same quantity."
        );
    }
}

fn okstr(ok: bool) -> &'static str {
    if ok {
        "ok"
    } else {
        "MISS"
    }
}
