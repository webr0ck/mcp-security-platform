# loadgen

Open-loop load harness for `mcphubd`. Simulates N concurrent MCP agent
clients doing `initialize` -> `tools/list` -> repeated `tools/call`, and
reports latency against the budget in `rs/ARCHITECTURE.md` ("Performance
budget"):

- p50 <= 3ms, p99 <= 15ms, p99.9 <= 50ms (measured on the `allow` lane)
- >= 20,000 req/s sustained
- < 512MB RSS

## Why open-loop, and what coordinated omission means here

A naive load client sends the next request only after the previous one
completes (closed-loop). Under that model, if the server stalls for 200ms,
the client simply sends fewer requests during the stall instead of queuing
them -- so the stall never shows up as latency, and p99/p99.9 come out
artificially good. This is "coordinated omission": the measurement is
coordinating with the server's own slowdown to omit the samples that would
have been worst.

`loadgen` fixes this by fixing the *arrival* schedule up front
(`tokio::time::interval` at `--rate` req/s) independent of how long any
request takes. Each request's `scheduled_at` timestamp is the tick's
deadline, not "whenever a worker got around to sending it". Latency is
measured from `scheduled_at` to response received, so any queueing delay
under load (waiting for a connection-pool slot, waiting for the server) is
captured as latency rather than hidden. This is what "3000 concurrent
agents" needs to mean for the numbers to be trustworthy -- see `main.rs`
for the exact mechanics (`ticker.tick()` -> spawn -> `Semaphore::acquire_owned()`
-> request -> `Instant::elapsed()`).

## Usage

```bash
# 1. Mint tokens out of band (real IDP client-credentials/password grant per
#    agent -- see deploy/idp-examples/ for how the platform's IDPs are
#    configured). Shape:
#    {"token_endpoint": "...", "client_id": "...", "client_secret": "...",
#     "tokens": [{"sub": "agent-0", "access_token": "...", "expires_at": 123, "refresh_token": "..."}]}

# 2. Run against a live gateway:
loadgen run \
  --base-url http://mcphubd-host:8000 \
  --agents 3000 \
  --rate 20000 \
  --duration-secs 60 \
  --deny-fraction 0.2 \
  --cred-fraction 0.3 \
  --token-file tokens.json \
  --server-pid $(pgrep mcphubd) \
  --report-json report.json \
  --assert-budget
```

Exit code is non-zero if `--assert-budget` is passed and any budget line is
missed (p50/p99/p99.9 on the allow lane, throughput, RSS if `--server-pid`
was given).

## Self-validation without a buildable mcphubd

The Rust gateway crates were still landing in parallel with this harness, so
`loadgen` ships its own trivial echo server implementing just enough of the
`/mcp` JSON-RPC contract (three synthetic tools: `loadgen-allowed-tool`,
`loadgen-denied-tool`, `loadgen-cred-tool`) to validate the measurement
pipeline end to end:

```bash
loadgen echo-server --port 8099 --latency-us 200 &
loadgen run --base-url http://127.0.0.1:8099 --agents 300 --rate 5000 \
  --duration-secs 5 --token-file fixtures/tokens.json \
  --server-pid $(pgrep -f 'echo-server') --report-json /tmp/report.json --assert-budget
```

This was run during development (300 agents, 5000 req/s, 5s) and produced
three separate HDR histograms (allow / deny / credential_injection), correct
error taxonomy (`PolicyDenied` on the deny lane), RSS sampling via `ps`, a
JSON report, and a non-zero exit when the budget was missed -- proving the
harness itself is correct. It is not a stand-in for real enforcement
latency: run it again against the real `mcphubd` once buildable.

## Mixed profile

Each scheduled request is assigned a lane by weighted coin flip:
`--deny-fraction` of all calls go to the always-denied tool (measured
separately -- deny MUST be faster than allow, since fail-closed short-circuits
before policy eval/credential injection/dispatch); of the remaining allowed
calls, `--cred-fraction` require credential injection / token exchange.

## Known limitations / divergence from a fully spec'd harness

- HTTP only (no TLS/mTLS client support) -- point it at a plaintext listener
  or a local TLS-terminating proxy in front of the real deployment; the
  gateway's mTLS edge (nginx) is out of scope for what this binary speaks.
- Token refresh (`--oauth-token-endpoint`) implements RFC 6749
  `refresh_token` grant only; token *minting* is out of band (a separate
  script drives the real IDP, per agent, so JWKS/cache behavior under 3000
  distinct `sub` claims is actually exercised -- not simulated with one
  reused token).
- RSS sampling shells out to `ps -o rss=` and therefore only works when
  `--server-pid` refers to a process on the same host as `loadgen` itself.
