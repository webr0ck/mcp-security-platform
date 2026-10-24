mod args;
mod client;
mod echo_server;
mod metrics;
mod report;
mod tokens;

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use clap::Parser;
use rand::Rng;
use tokio::sync::Semaphore;
use tracing::info;

use args::{Cli, Command, RunArgs};
use client::{build_client, call_tool, warmup_agent};
use metrics::{Collector, Lane};
use tokens::TokenPool;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
        .init();
    let cli = Cli::parse();
    match cli.command {
        Command::EchoServer(a) => echo_server::run(a).await,
        Command::Run(a) => run(a).await,
    }
}

async fn run(args: RunArgs) -> anyhow::Result<()> {
    if args.deny_fraction < 0.0 || args.deny_fraction > 1.0 {
        anyhow::bail!("--deny-fraction must be within [0.0, 1.0]");
    }
    if args.cred_fraction < 0.0 || args.cred_fraction > 1.0 {
        anyhow::bail!("--cred-fraction must be within [0.0, 1.0]");
    }

    let token_pool = match (&args.token_file, args.insecure_no_auth) {
        (Some(path), _) => Arc::new(TokenPool::from_file(path)?),
        (None, true) => Arc::new(TokenPool::insecure_noauth()),
        (None, false) => anyhow::bail!(
            "--token-file is required (pre-minted per-agent OAuth tokens); \
             pass --insecure-no-auth only against `loadgen echo-server`"
        ),
    };
    tokio::spawn(Arc::clone(&token_pool).run_refresh_loop(30));

    let client = Arc::new(build_client(args.pool_connections));

    // ── Warmup: initialize + tools/list for every agent, bounded so we
    // don't open 3000 sockets in the same instant. Not measured.
    info!(agents = args.agents, "warming up agents (initialize + tools/list)");
    let warmup_sema = Arc::new(Semaphore::new(args.pool_connections));
    let mut warmup_set = tokio::task::JoinSet::new();
    for agent_idx in 0..args.agents {
        let client = Arc::clone(&client);
        let base_url = args.base_url.clone();
        let pool = Arc::clone(&token_pool);
        let sema = Arc::clone(&warmup_sema);
        warmup_set.spawn(async move {
            let _permit = sema.acquire().await.expect("semaphore not closed");
            let token = pool.token_for_agent(agent_idx).await;
            warmup_agent(&client, &base_url, &token).await;
        });
    }
    while warmup_set.join_next().await.is_some() {}
    info!("warmup complete, entering steady-state measurement window");

    // ── Steady-state open-loop measurement.
    let (collector, agg_handle) = Collector::spawn();
    let sender = collector.handle();
    let in_flight = Arc::new(Semaphore::new(args.agents));
    let req_id = Arc::new(AtomicU64::new(2)); // 0/1 used by warmup

    let period = Duration::from_secs_f64(1.0 / args.rate as f64);
    let mut ticker = tokio::time::interval(period);
    // D6: MissedTickBehavior::Burst against a period this short (e.g. 50us
    // at --rate 20000) is nowhere near evenly spaced in practice -- tokio's
    // timer granularity is typically ~1ms on most platforms, so a 1kHz-ish
    // real wakeup cadence fires Burst catches up by dispatching ~20 queued
    // ticks back-to-back each time, i.e. actual arrivals look like 20-request
    // bursts at ~1kHz, NOT a smooth Poisson-ish 20k/s arrival process. This
    // is a real limitation of tokio::time::interval at sub-millisecond
    // periods, not a bug fixed by changing the missed-tick policy (Delay
    // would instead silently slow the whole run down to whatever the timer
    // can sustain, hiding the same problem differently). Documented here
    // per the review rather than fixed -- a true high-resolution open-loop
    // scheduler needs a spin-wait or a dedicated OS timer, out of scope for
    // this pass. `wall_clock_secs` in the report (vs. the nominal
    // `duration_secs`) is one observable symptom of this to watch.
    ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Burst);
    let wall_clock_start = Instant::now();
    let deadline = wall_clock_start + Duration::from_secs(args.duration_secs);
    let mut dispatch_set = tokio::task::JoinSet::new();
    let mut agent_cursor = 0usize;

    while Instant::now() < deadline {
        let scheduled_at = ticker.tick().await;
        // scheduled_at is the tick's fixed deadline, not "now" -- this is
        // the open-loop timestamp latency is measured against below, which
        // is what makes queueing delay under load visible instead of
        // hidden (coordinated omission).
        let lane = pick_lane(args.deny_fraction, args.cred_fraction);
        let agent_idx = agent_cursor;
        agent_cursor = (agent_cursor + 1) % args.agents.max(1);

        let client = Arc::clone(&client);
        let base_url = args.base_url.clone();
        let pool = Arc::clone(&token_pool);
        let sema = Arc::clone(&in_flight);
        let tx = sender.clone();
        let id_counter = Arc::clone(&req_id);
        // tokio::time::Interval::tick() returns the tick's scheduled
        // deadline (a tokio::time::Instant), which converts to std Instant
        // via Into -- this IS the open-loop arrival time, captured before
        // any queueing/semaphore wait below.
        let scheduled_instant: Instant = scheduled_at.into();

        dispatch_set.spawn(async move {
            // Acquiring the permit AFTER capturing scheduled_at (via
            // call_tool's use of scheduled_instant below) means any time
            // spent waiting for a free slot counts as latency, exactly as
            // a real caller queued behind a saturated pool would see.
            let _permit = sema.acquire_owned().await.expect("semaphore not closed");
            let token = pool.token_for_agent(agent_idx).await;
            let id = id_counter.fetch_add(1, Ordering::Relaxed);
            let sample = call_tool(&client, &base_url, &token, lane, scheduled_instant, id).await;
            let _ = tx.send(sample);
        });
    }
    info!("arrival window closed, draining in-flight requests");
    while dispatch_set.join_next().await.is_some() {}
    // D6: wall_clock_secs covers dispatch AND drain, not just the nominal
    // arrival window -- see report::build's doc comment on why dividing by
    // args.duration_secs alone inflated throughput_req_s.
    let wall_clock_secs = wall_clock_start.elapsed().as_secs_f64();
    // Every in-flight task's cloned sender is already dropped by now (each
    // task owns its clone and it goes out of scope when the task future
    // completes). The aggregator's `rx.recv().await` loop only terminates
    // once ALL senders are gone, including this original handle -- drop it
    // explicitly or the aggregator awaits forever and the report never
    // prints.
    drop(sender);
    drop(collector);
    let agg = agg_handle.await?;

    let rss_bytes = match args.server_pid {
        Some(pid) => sample_rss(pid).await,
        None => None,
    };

    let mut report = report::build(agg, args.duration_secs, wall_clock_secs, rss_bytes);
    if args.assert_budget {
        report::assert_budget(&mut report, args.rate, args.min_success_rate);
    }
    report::print_human(&report);
    if let Some(path) = &args.report_json {
        std::fs::write(path, serde_json::to_string_pretty(&report)?)?;
    }

    if let Some(budget) = &report.budget {
        if !budget.pass {
            anyhow::bail!("performance budget not met");
        }
    }
    Ok(())
}

fn pick_lane(deny_fraction: f64, cred_fraction: f64) -> Lane {
    let mut rng = rand::thread_rng();
    let r: f64 = rng.gen();
    if r < deny_fraction {
        Lane::Deny
    } else {
        let allowed_r: f64 = rng.gen();
        if allowed_r < cred_fraction {
            Lane::CredentialInjection
        } else {
            Lane::Allow
        }
    }
}

/// Samples RSS of `pid` via `ps -o rss=`, the same mechanism an operator
/// would use by hand; avoids a /proc dependency so this also works when the
/// harness runs on macOS against a remote Linux target over the network
/// (in which case --server-pid should be omitted -- ps only sees local
/// processes -- documented in --help).
async fn sample_rss(pid: u32) -> Option<u64> {
    let output = tokio::process::Command::new("ps")
        .args(["-o", "rss=", "-p", &pid.to_string()])
        .output()
        .await
        .ok()?;
    if !output.status.success() {
        return None;
    }
    let text = String::from_utf8_lossy(&output.stdout);
    text.trim().parse::<u64>().ok().map(|kb| kb * 1024)
}
