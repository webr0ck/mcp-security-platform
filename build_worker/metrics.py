"""
build-worker Prometheus metrics (CR-17 / WP-D1).

Mirrors scanner_worker/metrics.py exactly (same isolated-worker shape: a
bare asyncio poll loop, prometheus_client.start_http_server() spins up its
own tiny WSGI server in a background thread). Uses a distinct port
(BUILD_WORKER_METRICS_PORT, default 9101) so it can be scraped by the same
Prometheus instance alongside scanner-worker's :9100 without colliding.

NOTE: build_worker/ has no docker-compose service definition yet (see
build_worker/README.md / WP-B3 Task 1 scope note — the package exists and
is unit-tested, but was never wired into the lab compose stack this
session). observability/prometheus/prometheus.yml's build-worker scrape
target will show as a down/absent target until that compose wiring lands —
expected, not a bug in this metrics module.
"""
from __future__ import annotations

import logging
import os

from prometheus_client import Counter, Gauge, Histogram, start_http_server

logger = logging.getLogger("build_worker.metrics")

METRICS_PORT = int(os.environ.get("BUILD_WORKER_METRICS_PORT", "9101"))

worker_up = Gauge("mcp_build_worker_up", "1 once the worker's main loop has started.")

jobs_claimed_total = Counter(
    "mcp_build_worker_jobs_claimed_total", "Build/deploy/verify jobs claimed from the queue."
)
jobs_completed_total = Counter(
    "mcp_build_worker_jobs_completed_total",
    "Jobs that finished executing and wrote a build_results row (worker_error may still be set).",
)
jobs_requeued_total = Counter(
    "mcp_build_worker_jobs_requeued_total", "Jobs that crashed and were requeued for retry."
)
jobs_dead_letter_total = Counter(
    "mcp_build_worker_jobs_dead_letter_total",
    "Jobs that exhausted max_attempts and were dead-lettered.",
)
job_duration_seconds = Histogram(
    "mcp_build_worker_job_duration_seconds",
    "Wall-clock time to process one build/deploy/verify job.",
)


def start_metrics_server() -> None:
    try:
        start_http_server(METRICS_PORT)
        worker_up.set(1)
        logger.info("build-worker metrics server listening on :%d/metrics", METRICS_PORT)
    except Exception as exc:
        # Non-fatal: a metrics-server bind failure must not stop the worker
        # from doing its actual job (building).
        logger.warning("build-worker metrics server failed to start: %s", exc)
