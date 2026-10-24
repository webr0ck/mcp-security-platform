#!/usr/bin/env bash
# perf-check.sh — reproduce and record mcphub-policy's authz decision-latency
# benchmarks on the current machine, self-describing the environment they
# were taken in, and refusing to emit a verdict when that environment can't
# support a reliable measurement.
#
# See ../PERFORMANCE.md for what these numbers mean, why they were taken
# this way, and how to compare a new run against the recorded baseline.
#
# Usage:
#   scripts/perf-check.sh                 # run, write JSON + human summary
#   PERF_CHECK_MAX_LOAD_FRACTION=0.9 scripts/perf-check.sh   # loosen the gate
#   PERF_CHECK_SKIP_GATE=1 scripts/perf-check.sh              # force a run anyway (still labeled unreliable)
#
# Requires: cargo/rustc (via `source $HOME/.cargo/env` if not already on
# PATH), python3 (json parsing + portable getloadavg/cpu_count — no jq
# dependency, since jq is not guaranteed present on a fresh box but python3
# almost always is on Linux).
#
# Exit codes:
#   0  ran, environment suitable, verdict printed
#   1  ran, but the environment was NOT suitable — numbers are written to
#      disk (flagged unreliable) but no verdict is printed, and CI-style
#      callers should treat this as "inconclusive", not "pass" or "fail"
#   2  could not run at all (missing tooling, build failure, etc.)

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
RS_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
cd "$RS_DIR"

OUT_DIR="${PERF_CHECK_OUT_DIR:-$RS_DIR/perf-results}"
mkdir -p "$OUT_DIR"

# ---------------------------------------------------------------------------
# 0. Preconditions
# ---------------------------------------------------------------------------
if ! command -v cargo >/dev/null 2>&1; then
    echo "perf-check: cargo not on PATH — run 'source \$HOME/.cargo/env' first" >&2
    exit 2
fi
if ! command -v python3 >/dev/null 2>&1; then
    echo "perf-check: python3 not found — required for JSON parsing and portable load-average/cpu-count reads" >&2
    exit 2
fi

RUSTC_VERSION="$(rustc --version)"
CARGO_VERSION="$(cargo --version)"
GIT_COMMIT="$(git rev-parse HEAD 2>/dev/null || echo unknown)"
GIT_DIRTY="$(git status --porcelain 2>/dev/null | grep -q . && echo dirty || echo clean)"
TIMESTAMP_UTC="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
HOSTNAME="$(hostname -s 2>/dev/null || hostname)"
UNAME_S="$(uname -s)"
UNAME_R="$(uname -r)"

# ---------------------------------------------------------------------------
# 1. Environment capture — every result file must be self-describing
# ---------------------------------------------------------------------------
# CPU model + physical/logical core counts, portable across Linux/macOS.
if [ "$UNAME_S" = "Darwin" ]; then
    CPU_MODEL="$(sysctl -n machdep.cpu.brand_string 2>/dev/null || echo unknown)"
    PHYSICAL_CORES="$(sysctl -n hw.physicalcpu 2>/dev/null || echo 0)"
    LOGICAL_CORES="$(sysctl -n hw.logicalcpu 2>/dev/null || echo 0)"
elif [ "$UNAME_S" = "Linux" ]; then
    CPU_MODEL="$(grep -m1 'model name' /proc/cpuinfo 2>/dev/null | sed 's/^[^:]*: //' || echo unknown)"
    LOGICAL_CORES="$(nproc --all 2>/dev/null || echo 0)"
    if command -v lscpu >/dev/null 2>&1; then
        SOCKETS="$(lscpu | awk -F: '/^Socket\(s\)/{gsub(/ /,"",$2); print $2}')"
        CORES_PER_SOCKET="$(lscpu | awk -F: '/^Core\(s\) per socket/{gsub(/ /,"",$2); print $2}')"
        PHYSICAL_CORES="$(( ${SOCKETS:-1} * ${CORES_PER_SOCKET:-$LOGICAL_CORES} ))"
    else
        PHYSICAL_CORES="$LOGICAL_CORES"
    fi
else
    CPU_MODEL="unknown ($UNAME_S)"
    PHYSICAL_CORES="0"
    LOGICAL_CORES="$(python3 -c 'import os; print(os.cpu_count() or 0)')"
fi

# Load average (1/5/15 min) — portable via python3's os.getloadavg (POSIX).
read -r LOAD1 LOAD5 LOAD15 <<EOF
$(python3 -c "import os; l=os.getloadavg(); print(l[0], l[1], l[2])")
EOF

# ---------------------------------------------------------------------------
# 2. Suitability gate — refuse a verdict rather than emit a number nobody
#    should quote. This is the whole point: a fast machine mid-build looks
#    identical, in the printed numbers, to a genuinely fast decision path.
# ---------------------------------------------------------------------------
MAX_LOAD_FRACTION="${PERF_CHECK_MAX_LOAD_FRACTION:-0.5}"   # load1 / logical_cores must stay under this
LOAD_FRACTION="$(python3 -c "print(${LOAD1} / max(${LOGICAL_CORES}, 1))")"
UNSUITABLE_REASONS=()

if python3 -c "exit(0 if ${LOAD_FRACTION} > ${MAX_LOAD_FRACTION} else 1)"; then
    UNSUITABLE_REASONS+=("load average ${LOAD1} on ${LOGICAL_CORES} logical cores (fraction ${LOAD_FRACTION}) exceeds threshold ${MAX_LOAD_FRACTION} — machine looks busy (concurrent build, other load)")
fi

# Debug-build guard: this crate's workspace defines no [profile.bench]
# override (verified against Cargo.toml at authoring time — recheck if that
# ever changes), so `cargo bench` uses the standard optimized `bench`
# profile. If someone has forced debug via env, refuse rather than report
# debug-build latencies as if they were the optimized numbers.
if [ "${CARGO_PROFILE_BENCH_OPT_LEVEL:-3}" = "0" ] || [ "${CARGO_PROFILE_BENCH_DEBUG_ASSERTIONS:-false}" = "true" ]; then
    UNSUITABLE_REASONS+=("CARGO_PROFILE_BENCH_* env vars force an unoptimized/debug-assertions build")
fi
if grep -q '^\[profile.bench\]' Cargo.toml 2>/dev/null; then
    UNSUITABLE_REASONS+=("workspace Cargo.toml now defines [profile.bench] — re-verify it still builds optimized before trusting this script's gate")
fi

SUITABLE=1
if [ "${#UNSUITABLE_REASONS[@]}" -gt 0 ] && [ "${PERF_CHECK_SKIP_GATE:-0}" != "1" ]; then
    SUITABLE=0
fi

# ---------------------------------------------------------------------------
# 3. Warm-up + run. Pre-build the bench binary first so compilation time
#    (which on this project's dev box swung 2.6ms->11.6ms wall-clock across
#    runs with zero code changes — see PERFORMANCE.md) never bleeds into
#    criterion's own per-benchmark 3s warm-up. Criterion re-warms each
#    individual benchmark for 3s beyond this regardless; that per-benchmark
#    warm-up is criterion's, not this script's, and is not skippable via
#    its stable API without also destabilizing sample counts, so we rely on
#    it rather than re-implement a second one.
# ---------------------------------------------------------------------------
echo "perf-check: pre-building bench binary (warm-up, discarded)..." >&2
# NOTE: deliberately `cargo bench ... --no-run`, not `cargo build --benches`.
# The latter also compiles mcphub-policy's `#[cfg(test)]` unit-test unit as
# a separate artifact (cargo labels it "(lib test)") — unrelated to the
# bench binary itself, and at the time of authoring this script that unit
# does not compile (unrelated in-flight change to mcphub-types::Identity's
# role representation broke three unit-test fixtures). `cargo bench --bench
# authz_bench --no-run` builds exactly the artifact this script actually
# runs and nothing else, so an unrelated unit-test breakage elsewhere in
# the crate cannot block a perf check.
cargo bench --package mcphub-policy --bench authz_bench --no-run >&2

BENCH_LOG="$OUT_DIR/.last-bench-run.log"
echo "perf-check: running authz_bench (this takes ~1-2 minutes)..." >&2
cargo bench --package mcphub-policy --bench authz_bench 2>&1 | tee "$BENCH_LOG" >&2

# ---------------------------------------------------------------------------
# 4. Pull point estimates + CIs out of criterion's on-disk JSON. Criterion
#    writes target/criterion/<bench>/new/estimates.json after every run;
#    "mean" there is what this script reports (criterion's console "time:"
#    line is a linear-regression slope estimate that can differ slightly —
#    see PERFORMANCE.md's note on the two estimators).
# ---------------------------------------------------------------------------
estimate_ns() {
    local dir="target/criterion/$1/new/estimates.json"
    if [ ! -f "$dir" ]; then
        echo "null"
        return
    fi
    python3 -c "
import json
d = json.load(open('$dir'))
m = d['mean']
print(json.dumps({'point_ns': m['point_estimate'], 'low_ns': m['confidence_interval']['lower_bound'], 'high_ns': m['confidence_interval']['upper_bound']}))
"
}

N_THREADS="$(python3 -c "print(${LOGICAL_CORES})")"

COLD_COMPILE="$(estimate_ns authz_cold_compile_both_entrypoints)"
FLOOR_CONVERSION="$(estimate_ns authz_floor_json_to_regorus_conversion_only)"
FLOOR_EVAL="$(estimate_ns authz_floor_eval_with_input_preconverted)"
CACHE_MISS="$(estimate_ns authz_cache_miss_single_decision)"
CACHE_HIT="$(estimate_ns authz_cache_hit_single_decision)"
THROUGHPUT_HOT="$(estimate_ns "authz_concurrent_throughput_cache_hot/decisions_per_sec_${N_THREADS}_threads")"
THROUGHPUT_COLD="$(estimate_ns "authz_concurrent_throughput_cache_cold/decisions_per_sec_${N_THREADS}_threads")"

# ---------------------------------------------------------------------------
# 5. Derived throughput as a function of ASSUMED hit rate. This benchmark
#    suite only measures the two endpoints (0% and 100% hit rate) directly
#    — nothing here drives mixed traffic, so intermediate rows are a linear
#    interpolation between the two measured single-decision latencies, not
#    an independent measurement. Labeled as such in the JSON and the
#    human-readable table below. The definitive mixed-traffic number can
#    only come from component 6's loadgen against a live deployment.
# ---------------------------------------------------------------------------
derive_throughput_table() {
    python3 -c "
import json
hit = json.loads('''$CACHE_HIT''')
miss = json.loads('''$CACHE_MISS''')
if hit == 'null' or miss == 'null' or hit is None or miss is None:
    print(json.dumps([]))
else:
    hit_ns = hit['point_ns']
    miss_ns = miss['point_ns']
    rows = []
    for rate in [0.0, 0.25, 0.5, 0.75, 0.9, 0.95, 0.99, 1.0]:
        per_decision_ns = rate * hit_ns + (1 - rate) * miss_ns
        single_thread_per_sec = 1e9 / per_decision_ns
        rows.append({
            'assumed_hit_rate': rate,
            'modeled_single_thread_decisions_per_sec': round(single_thread_per_sec, 1),
            'note': 'linear interpolation between measured 0% and 100% endpoints, single-thread; NOT independently measured, and ignores any lock/cache contention that concurrent measurement captures at the endpoints'
        })
    print(json.dumps(rows))
"
}
THROUGHPUT_TABLE="$(derive_throughput_table)"

# ---------------------------------------------------------------------------
# 6. Write the self-describing JSON result file.
# ---------------------------------------------------------------------------
SAFE_COMMIT="${GIT_COMMIT:0:12}"
RESULT_FILE="$OUT_DIR/${TIMESTAMP_UTC//:/-}_${HOSTNAME}_${SAFE_COMMIT}.json"

# Build the unsuitable-reasons JSON array safely (avoids shell-quoting each
# reason string into the heredoc below).
UNSUITABLE_REASONS_JSON="[]"
if [ "${#UNSUITABLE_REASONS[@]}" -gt 0 ]; then
    UNSUITABLE_REASONS_JSON="$(printf '%s\n' "${UNSUITABLE_REASONS[@]}" | python3 -c 'import json,sys; print(json.dumps([l.rstrip("\n") for l in sys.stdin]))')"
fi

python3 - "$RESULT_FILE" <<PYEOF
import json, sys

out = {
    "schema_version": 1,
    "suitable_for_verdict": bool($SUITABLE),
    "unsuitable_reasons": json.loads('''$UNSUITABLE_REASONS_JSON'''),
    "environment": {
        "timestamp_utc": "$TIMESTAMP_UTC",
        "hostname": "$HOSTNAME",
        "os": "$UNAME_S",
        "kernel": "$UNAME_R",
        "cpu_model": "$CPU_MODEL",
        "physical_cores": $PHYSICAL_CORES,
        "logical_cores": $LOGICAL_CORES,
        "load_average_1_5_15": [$LOAD1, $LOAD5, $LOAD15],
        "load_fraction_1min": $LOAD_FRACTION,
        "rustc_version": "$RUSTC_VERSION",
        "cargo_version": "$CARGO_VERSION",
        "git_commit": "$GIT_COMMIT",
        "git_dirty": "$GIT_DIRTY",
        "build_profile": "bench (release opt-level=3, no workspace [profile.bench] override at authoring time)"
    },
    "measurements_ns": {
        "cold_compile_both_entrypoints": json.loads('''$COLD_COMPILE'''),
        "floor_json_to_regorus_conversion_only": json.loads('''$FLOOR_CONVERSION'''),
        "floor_eval_with_input_preconverted": json.loads('''$FLOOR_EVAL'''),
        "cache_miss_single_decision": json.loads('''$CACHE_MISS'''),
        "cache_hit_single_decision": json.loads('''$CACHE_HIT'''),
        "concurrent_throughput_cache_hot_time_per_op": json.loads('''$THROUGHPUT_HOT'''),
        "concurrent_throughput_cache_cold_time_per_op": json.loads('''$THROUGHPUT_COLD''')
    },
    "derived_throughput_by_assumed_hit_rate": json.loads('''$THROUGHPUT_TABLE'''),
    "notes": [
        "cache_hit / cache_miss / hit_rate are reported separately and must never be blended into one throughput figure.",
        "concurrent_throughput_cache_hot/cold are the only DIRECTLY measured throughput points (hit rate 100% and 0% respectively, all threads hammering one Arc<PolicyState>); everything in derived_throughput_by_assumed_hit_rate is a single-thread linear interpolation between the two single-decision latencies, not a measurement.",
        "compare against rs/PERFORMANCE.md's recorded baseline using the delta thresholds in that document's Comparison Procedure section, not raw eyeballing."
    ]
}
with open(sys.argv[1], "w") as f:
    json.dump(out, f, indent=2)
print(json.dumps(out, indent=2))
PYEOF

# ---------------------------------------------------------------------------
# 7. Human-readable summary + the refuse-a-verdict gate.
# ---------------------------------------------------------------------------
echo ""
echo "================================================================"
echo "perf-check: $TIMESTAMP_UTC on $HOSTNAME"
echo "  CPU: $CPU_MODEL  (${PHYSICAL_CORES} physical / ${LOGICAL_CORES} logical)"
echo "  OS: $UNAME_S $UNAME_R"
echo "  rustc: $RUSTC_VERSION"
echo "  git: $GIT_COMMIT ($GIT_DIRTY)"
echo "  load average (1m): $LOAD1  (fraction of logical cores: $LOAD_FRACTION, threshold $MAX_LOAD_FRACTION)"
echo "  result file: $RESULT_FILE"
echo "================================================================"

if [ "$SUITABLE" -eq 0 ]; then
    echo ""
    echo "!! NO VERDICT: these conditions cannot support a reliable measurement." >&2
    for r in "${UNSUITABLE_REASONS[@]}"; do
        echo "   - $r" >&2
    done
    echo ""
    echo "   Raw numbers were still written to $RESULT_FILE (suitable_for_verdict: false)" >&2
    echo "   so the run isn't wasted, but do not quote them for a capacity decision." >&2
    echo "   Re-run once the machine is quiet (PERF_CHECK_MAX_LOAD_FRACTION to adjust the gate," >&2
    echo "   PERF_CHECK_SKIP_GATE=1 to force output anyway, still flagged unreliable)." >&2
    exit 1
fi

python3 -c "
import json
r = json.load(open('$RESULT_FILE'))
m = r['measurements_ns']
def fmt(x):
    if x is None:
        return 'n/a'
    return f\"{x['point_ns']/1000:.2f}µs (CI {x['low_ns']/1000:.2f}..{x['high_ns']/1000:.2f}µs)\"
print('cache-hit  latency :', fmt(m['cache_hit_single_decision']))
print('cache-miss latency :', fmt(m['cache_miss_single_decision']))
hit = m['cache_hit_single_decision']['point_ns'] if m['cache_hit_single_decision'] else None
miss = m['cache_miss_single_decision']['point_ns'] if m['cache_miss_single_decision'] else None
if hit and miss:
    print(f'hit/miss ratio     : {miss/hit:.1f}x')
print('cold compile (both) :', fmt(m['cold_compile_both_entrypoints']))
print('floor: json->regorus:', fmt(m['floor_json_to_regorus_conversion_only']))
print('floor: eval (warm)  :', fmt(m['floor_eval_with_input_preconverted']))
print()
print('derived throughput by assumed hit rate (single-thread, interpolated — see notes):')
for row in r['derived_throughput_by_assumed_hit_rate']:
    print(f\"  hit_rate={row['assumed_hit_rate']:.2f}  ~{row['modeled_single_thread_decisions_per_sec']:>10.0f} decisions/s/thread\")
"

echo ""
echo "Verdict: environment suitable, numbers above are usable for comparison"
echo "against rs/PERFORMANCE.md's baseline (see that file's Comparison Procedure)."
