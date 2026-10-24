//! Criterion bench: cost of an `authz.rego` decision through the
//! in-process `regorus` engine, WITH the decision cache. Target from
//! ARCHITECTURE.md: sub-millisecond p99 for a single authz decision AND
//! ≥20,000 req/s sustained on 8 cores.
//!
//! Reports, separately:
//!   - cold compile (paid once globally per policy/data generation)
//!   - cache-MISS single-decision latency (genuine regorus eval)
//!   - cache-HIT single-decision latency (cache lookup only)
//!   - concurrent throughput on `available_parallelism()` threads, in two
//!     regimes: cache-saturated (every thread hammers the same input —
//!     the ~3000-agents-repeating-a-handful-of-tools case) and cache-cold
//!     (every call is a distinct input — the worst case, no reuse at all)
//!
//! The report derives implied req/s at an assumed realistic hit rate from
//! the measured hit/miss latencies rather than guessing a single number.

use criterion::{black_box, criterion_group, criterion_main, Criterion, Throughput};
use mcphub_policy::{PolicyBundle, RegorusPolicyEngine};
use serde_json::json;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

fn sample_grants() -> serde_json::Value {
    json!({
        "alice": {
            "allowed_tools": ["ping", "echo_args"],
            "allowed_tags": ["lab"],
            "max_risk_level": "medium"
        }
    })
}

fn sample_input(variant: u64) -> serde_json::Value {
    json!({
        "client_id": "alice",
        "client_roles": ["user"],
        "tool_id": "11111111-1111-1111-1111-111111111111",
        "tool_name": "ping",
        "tool_status": "active",
        "tool_risk_level": "low",
        "tool_server_id": "",
        "owned_server_ids": [],
        "owner_max_risk_level": "medium",
        // varying this field per call defeats the cache deliberately, for
        // the cache-cold benchmarks below.
        "params": {"arg": format!("value-{variant}")},
        "anomaly_score": 0.1,
        "is_testing": false,
    })
}

fn warm_engine() -> RegorusPolicyEngine {
    // Long cache TTL (well beyond a single criterion benchmark's runtime)
    // so these benches measure the algorithmic hit/miss cost, not TTL
    // expiry landing mid-run — `RegorusPolicyEngine::new`'s 5s production
    // default would otherwise cause a spurious re-miss partway through a
    // multi-second `bench_cache_hit` run.
    let engine = RegorusPolicyEngine::with_cache(Duration::from_secs(3600), Duration::from_secs(3600), 100_000);
    let bundle = PolicyBundle::unsigned_for_tests(PolicyBundle::EMBEDDED_AUTHZ_REGO);
    engine.load_bundle(&bundle).expect("bundle loads");
    engine.sync_data(sample_grants(), json!({}), json!([])).expect("data syncs");
    engine
}

/// COLD COMPILE: compiling both entrypoints from a fresh engine — what
/// `load_bundle`/`sync_data` pay, ONCE, globally, per generation.
fn bench_cold_compile(c: &mut Criterion) {
    c.bench_function("authz_cold_compile_both_entrypoints", |b| {
        b.iter(|| {
            let engine = RegorusPolicyEngine::new(Duration::from_secs(3600));
            let bundle = PolicyBundle::unsigned_for_tests(black_box(PolicyBundle::EMBEDDED_AUTHZ_REGO));
            engine.load_bundle(&bundle).expect("bundle loads");
            engine
                .sync_data(black_box(sample_grants()), json!({}), json!([]))
                .expect("data syncs");
            black_box(engine)
        })
    });
}

/// FLOOR DECOMPOSITION: splits the cache-miss cost into (a) `serde_json::
/// Value -> regorus::Value` conversion and (b) the `regorus::CompiledPolicy
/// ::eval_with_input` call itself (which internally constructs a fresh
/// `regorus::Engine` per call via `Engine::new_from_compiled_policy` — see
/// engine.rs's module docs for why that's cheap by construction, all
/// `Rc`/`Arc`-shared or zero-alloc-empty fields — and then walks the rule
/// tree). An earlier report guessed the conversion dominated; this bench
/// exists specifically to replace that guess with a measurement.
fn bench_floor_conversion_only(c: &mut Criterion) {
    let input = sample_input(0);
    c.bench_function("authz_floor_json_to_regorus_conversion_only", |b| {
        b.iter(|| {
            let v = regorus::Value::from(black_box(input.clone()));
            black_box(v)
        })
    });
}

fn bench_floor_eval_only_preconverted(c: &mut Criterion) {
    let engine = regorus::Engine::new();
    let mut engine = engine;
    engine
        .add_policy("authz.rego".to_string(), PolicyBundle::EMBEDDED_AUTHZ_REGO.to_string())
        .unwrap();
    engine.add_data(regorus::Value::from(sample_grants_wrapped())).unwrap();
    let compiled = engine.compile_with_entrypoint(&regorus::Rc::from("data.mcp.authz.allow")).unwrap();
    let regorus_input = regorus::Value::from(sample_input(0));

    c.bench_function("authz_floor_eval_with_input_preconverted", |b| {
        b.iter(|| {
            let v = compiled.eval_with_input(black_box(regorus_input.clone())).unwrap();
            black_box(v)
        })
    });
}

fn sample_grants_wrapped() -> serde_json::Value {
    json!({
        "mcp_grants": sample_grants(),
        "mcp": {"tools": {}, "injection_phrases": []},
    })
}

/// CACHE MISS: a distinct input every call (a counter folded into
/// `params.arg`) — every call is forced through the real rego evaluation.
/// This is the worst-case per-decision cost.
fn bench_cache_miss(c: &mut Criterion) {
    let engine = warm_engine();
    let counter = AtomicU64::new(0);

    c.bench_function("authz_cache_miss_single_decision", |b| {
        b.iter(|| {
            let variant = counter.fetch_add(1, Ordering::Relaxed);
            let result = engine.evaluate_raw(black_box(sample_input(variant))).unwrap();
            black_box(result.allow)
        })
    });
}

/// CACHE HIT: the SAME input every call — after the first, every call is
/// a cache lookup only, no rego evaluation.
fn bench_cache_hit(c: &mut Criterion) {
    let engine = warm_engine();
    let input = sample_input(0);
    engine.evaluate_raw(input.clone()).unwrap(); // populate the cache
    assert_eq!(engine.eval_count(), 1, "warm-up must be exactly one real evaluation");

    c.bench_function("authz_cache_hit_single_decision", |b| {
        b.iter(|| {
            let result = engine.evaluate_raw(black_box(input.clone())).unwrap();
            black_box(result.allow)
        })
    });
    assert_eq!(engine.eval_count(), 1, "every timed iteration must have been a cache hit");
}

/// ANOMALY COST, standalone: `data.mcp.anomaly.structural_deny_reasons`
/// compiled and evaluated as its own entrypoint, exactly as `engine.rs`
/// does it — never cached, evaluated on every call regardless of the authz
/// cache (see `cache.rs`'s module doc for why). This is the third number
/// the split-cache design's throughput math depends on, alongside authz
/// hit/miss above.
fn bench_anomaly_eval_only(c: &mut Criterion) {
    let mut engine = regorus::Engine::new();
    engine
        .add_policy("anomaly.rego".to_string(), PolicyBundle::EMBEDDED_ANOMALY_REGO.to_string())
        .unwrap();
    engine.add_data(regorus::Value::from(json!({}))).unwrap();
    let compiled = engine
        .compile_with_entrypoint(&regorus::Rc::from("data.mcp.anomaly.structural_deny_reasons"))
        .unwrap();
    let recent_calls: Vec<_> = (0..3).map(|i| json!({"tool_name": format!("ping_{i}"), "timestamp": i as f64})).collect();
    let regorus_input = regorus::Value::from(json!({"recent_calls": recent_calls, "window_seconds": 300}));

    c.bench_function("anomaly_eval_with_input_preconverted", |b| {
        b.iter(|| {
            let v = compiled.eval_with_input(black_box(regorus_input.clone())).unwrap();
            black_box(v)
        })
    });
}

/// The REAL end-to-end shape once anomaly is live: authz cache HIT (same
/// client/tool/params every call) + anomaly evaluated fresh every call
/// (recent_calls varies, folded into a counter here to prove the cache
/// isn't accidentally masking it) — this is what `evaluate_raw` actually
/// costs per decision under the split-cache design, not a component in
/// isolation.
fn bench_authz_cache_hit_plus_fresh_anomaly(c: &mut Criterion) {
    let engine = RegorusPolicyEngine::with_cache(Duration::from_secs(3600), Duration::from_secs(3600), 100_000);
    let bundle = PolicyBundle::unsigned_for_tests_with_anomaly(
        PolicyBundle::EMBEDDED_AUTHZ_REGO,
        PolicyBundle::EMBEDDED_ANOMALY_REGO,
    );
    engine.load_bundle(&bundle).expect("bundle loads");
    engine.sync_data(sample_grants(), json!({}), json!([])).expect("data syncs");

    let base = sample_input(0);
    engine.evaluate_raw(base.clone()).expect("warm-up"); // populates the authz cache entry
    assert_eq!(engine.eval_count(), 1, "warm-up must be exactly one authz evaluation");

    let counter = AtomicU64::new(0);
    c.bench_function("authz_cache_hit_plus_fresh_anomaly_every_call", |b| {
        b.iter(|| {
            let variant = counter.fetch_add(1, Ordering::Relaxed);
            let mut input = base.clone();
            // recent_calls varies every call (as it does for real traffic)
            // — must NOT force an authz re-evaluation.
            input["recent_calls"] = json!([{"tool_name": format!("ping_{variant}"), "timestamp": variant as f64}]);
            input["window_seconds"] = json!(300);
            let result = engine.evaluate_raw(black_box(input)).unwrap();
            black_box(result.allow)
        })
    });
    assert_eq!(
        engine.eval_count(),
        1,
        "recent_calls varying every call must never force an authz re-evaluation"
    );
}

/// THROUGHPUT, cache-saturated: `available_parallelism()` threads all
/// hammering the SAME shared engine with the SAME input — models 3000
/// agents repeatedly calling a handful of tools, where the decision cache
/// does the most good.
fn bench_concurrent_throughput_cache_hot(c: &mut Criterion) {
    let engine = Arc::new(warm_engine());
    let input = sample_input(0);
    engine.evaluate_raw(input.clone()).unwrap(); // populate the cache once
    let n_threads = std::thread::available_parallelism().map(|n| n.get()).unwrap_or(4);

    let mut group = c.benchmark_group("authz_concurrent_throughput_cache_hot");
    group.throughput(Throughput::Elements(1));
    group.bench_function(format!("decisions_per_sec_{n_threads}_threads"), |b| {
        b.iter_custom(|iters| {
            let per_thread = (iters / n_threads as u64).max(1);
            let start = Instant::now();
            let handles: Vec<_> = (0..n_threads)
                .map(|_| {
                    let engine = engine.clone();
                    let input = input.clone();
                    std::thread::spawn(move || {
                        for _ in 0..per_thread {
                            let result = engine.evaluate_raw(input.clone()).unwrap();
                            std::hint::black_box(result.allow);
                        }
                    })
                })
                .collect();
            for h in handles {
                h.join().unwrap();
            }
            start.elapsed()
        });
    });
    group.finish();
}

/// THROUGHPUT, cache-cold: same thread count, but every call across every
/// thread uses a distinct input (a shared atomic counter), so the cache
/// never helps at all. This is the pessimistic floor — real traffic sits
/// somewhere between this and the cache-hot number above.
fn bench_concurrent_throughput_cache_cold(c: &mut Criterion) {
    let engine = Arc::new(warm_engine());
    let n_threads = std::thread::available_parallelism().map(|n| n.get()).unwrap_or(4);
    let counter = Arc::new(AtomicU64::new(0));

    let mut group = c.benchmark_group("authz_concurrent_throughput_cache_cold");
    group.throughput(Throughput::Elements(1));
    group.bench_function(format!("decisions_per_sec_{n_threads}_threads"), |b| {
        b.iter_custom(|iters| {
            let per_thread = (iters / n_threads as u64).max(1);
            let start = Instant::now();
            let handles: Vec<_> = (0..n_threads)
                .map(|_| {
                    let engine = engine.clone();
                    let counter = counter.clone();
                    std::thread::spawn(move || {
                        for _ in 0..per_thread {
                            let variant = counter.fetch_add(1, Ordering::Relaxed);
                            let result = engine.evaluate_raw(sample_input(variant)).unwrap();
                            std::hint::black_box(result.allow);
                        }
                    })
                })
                .collect();
            for h in handles {
                h.join().unwrap();
            }
            start.elapsed()
        });
    });
    group.finish();
}

criterion_group!(
    benches,
    bench_cold_compile,
    bench_floor_conversion_only,
    bench_floor_eval_only_preconverted,
    bench_cache_miss,
    bench_cache_hit,
    bench_anomaly_eval_only,
    bench_authz_cache_hit_plus_fresh_anomaly,
    bench_concurrent_throughput_cache_hot,
    bench_concurrent_throughput_cache_cold
);
criterion_main!(benches);
