.PHONY: perf-check

# Run the mcphub-policy authz decision-latency benchmarks and record a
# self-describing result under perf-results/. See PERFORMANCE.md.
#
#   make perf-check
#   PERF_CHECK_MAX_LOAD_FRACTION=0.9 make perf-check   # loosen the busy-machine gate
#   PERF_CHECK_SKIP_GATE=1 make perf-check             # force a run anyway (flagged unreliable)
perf-check:
	@bash scripts/perf-check.sh
