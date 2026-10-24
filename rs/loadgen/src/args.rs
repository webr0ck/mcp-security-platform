use clap::{Parser, Subcommand};

/// Open-loop MCP gateway load harness. Simulates N concurrent agent clients
/// doing initialize -> tools/list -> repeated tools/call against a running
/// mcphubd (or any HTTP endpoint speaking the same contract), at a fixed
/// arrival rate, with coordinated-omission-corrected latency recording.
///
/// D6: this harness has its own latency floor (client-side event-loop /
/// hyper / tokio scheduling overhead) that is included in every measurement
/// it reports -- it is not currently subtracted out or reported separately.
/// Before trusting a budget assertion against mcphubd, establish that floor
/// first: `loadgen run --base-url http://127.0.0.1:PORT --insecure-no-auth`
/// against `loadgen echo-server --latency-us 0` on the SAME host. Whatever
/// p50/p99 that reports is the harness's own overhead, not mcphubd's --
/// subtract it (or at least note it) when interpreting a real run.
#[derive(Parser, Debug)]
#[command(name = "loadgen", version, about)]
pub struct Cli {
    #[command(subcommand)]
    pub command: Command,
}

#[derive(Subcommand, Debug)]
pub enum Command {
    /// Run the load test against a target base URL.
    Run(RunArgs),
    /// Start a trivial local echo server implementing the minimal /mcp and
    /// /api/v1/tools/{id}/invoke contract, for validating the harness itself
    /// when mcphubd is not yet buildable.
    EchoServer(EchoServerArgs),
}

#[derive(Parser, Debug, Clone)]
pub struct RunArgs {
    /// Base URL of the gateway under test, e.g. https://127.0.0.1:8443
    #[arg(long)]
    pub base_url: String,

    /// Number of concurrent simulated agents (steady-state in-flight budget).
    #[arg(long, default_value_t = 3000)]
    pub agents: usize,

    /// Target open-loop arrival rate in requests/sec across all agents for
    /// the tools/call phase. This is the rate the scheduler fires at
    /// regardless of how long prior requests are taking (open-loop) --
    /// required for coordinated-omission-free measurement.
    #[arg(long, default_value_t = 20_000)]
    pub rate: u64,

    /// Duration of the steady-state measurement window, in seconds.
    /// (initialize/tools_list warmup for all agents happens before this
    /// window starts and is not counted in the histograms.)
    #[arg(long, default_value_t = 30)]
    pub duration_secs: u64,

    /// Fraction (0.0-1.0) of tools/call requests that should be denied by
    /// policy (measured in a separate histogram -- the deny path must be
    /// faster than the allow path, not slower).
    #[arg(long, default_value_t = 0.2)]
    pub deny_fraction: f64,

    /// Fraction (0.0-1.0) of ALLOWED tools/call requests that hit a tool
    /// requiring credential injection / token exchange.
    #[arg(long, default_value_t = 0.3)]
    pub cred_fraction: f64,

    /// Path to a JSON file of pre-minted OAuth tokens, one per agent (or
    /// fewer, cycled). Required unless --insecure-no-auth is passed (only
    /// valid against the echo-server for harness self-validation).
    #[arg(long)]
    pub token_file: Option<String>,

    /// Skip auth headers entirely. Only for echo-server self-validation.
    #[arg(long, default_value_t = false)]
    pub insecure_no_auth: bool,

    /// OAuth token endpoint used to refresh tokens as they approach expiry
    /// (RFC 6749 refresh_token grant). If omitted, tokens are used as-is for
    /// the whole run and a warning is logged if any expire mid-run.
    #[arg(long)]
    pub oauth_token_endpoint: Option<String>,

    /// OS pid of the server process under test, for RSS sampling via `ps`.
    /// If omitted, RSS is not measured and the RSS budget assertion is
    /// skipped (reported as "not measured").
    #[arg(long)]
    pub server_pid: Option<u32>,

    /// Write the full report as JSON to this path in addition to stdout.
    #[arg(long)]
    pub report_json: Option<String>,

    /// Assert the ARCHITECTURE.md performance budget and exit non-zero if
    /// missed: p50 <= 3ms, p99 <= 15ms, p99.9 <= 50ms (allow lane only),
    /// throughput >= 95% of the requested --rate, success_rate >=
    /// --min-success-rate, RSS < 512MB (only checked if --server-pid was
    /// given). NOTE: measured client-side end-to-end including backend
    /// time, NOT gateway-side-excluding-backend as ARCHITECTURE.md's
    /// budget is defined -- this is a harsher upper bound, not the same
    /// quantity (see the printed report note).
    #[arg(long, default_value_t = false)]
    pub assert_budget: bool,

    /// Minimum fraction (0.0-1.0) of completed requests that must get a
    /// real decision (Success or a genuine policy Denied) for
    /// --assert-budget to pass. Requests rejected at the edge before
    /// `invoke` runs (HTTP 401/403/429/5xx with no JSON-RPC body) or that
    /// fail at the transport layer count against this, never as fast
    /// "denials" -- see the D6 fix in report.rs.
    #[arg(long, default_value_t = 0.95)]
    pub min_success_rate: f64,

    /// Number of TCP connections in the client pool (hyper-util legacy
    /// pool `pool_max_idle_per_host`). This is an IDLE-CONNECTION RETENTION
    /// cap, not a hard concurrency limit: hyper-util opens new connections
    /// beyond this count under load and simply doesn't keep more than this
    /// many idle afterward. Actual in-flight concurrency is bounded by
    /// --agents (the semaphore permit count), not by this flag. Too low a
    /// value still hurts by forcing repeated connection setup instead of
    /// reuse, which would corrupt the measurement, but it will not cap
    /// concurrency the way a true pool-size limit would.
    #[arg(long, default_value_t = 512)]
    pub pool_connections: usize,
}

#[derive(Parser, Debug, Clone)]
pub struct EchoServerArgs {
    #[arg(long, default_value_t = 8099)]
    pub port: u16,

    /// Artificial per-request latency to simulate realistic backend time
    /// (microseconds). 0 = as fast as possible, useful to validate the
    /// harness measures near-zero overhead itself.
    #[arg(long, default_value_t = 200)]
    pub latency_us: u64,
}
