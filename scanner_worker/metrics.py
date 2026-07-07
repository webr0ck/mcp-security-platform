"""
scanner-worker Prometheus metrics (CR-17 / WP-D1).

Unlike the proxy (an ASGI app that can add a route), this process is a bare
asyncio poll loop — prometheus_client.start_http_server() spins up its own
tiny WSGI server in a background thread, which is the standard pattern for
exactly this shape of process. Scraped by the same Prometheus instance as
the proxy (see docker-compose.yml's `prometheus` service).
"""
from __future__ import annotations

import logging
import os

from prometheus_client import Counter, Gauge, Histogram, start_http_server

logger = logging.getLogger("scanner_worker.metrics")

METRICS_PORT = int(os.environ.get("SCAN_WORKER_METRICS_PORT", "9100"))

worker_up = Gauge("mcp_scanner_worker_up", "1 once the worker's main loop has started.")

jobs_claimed_total = Counter(
    "mcp_scanner_worker_jobs_claimed_total", "Scan jobs claimed from the queue."
)
jobs_completed_total = Counter(
    "mcp_scanner_worker_jobs_completed_total",
    "Scan jobs that finished executing and wrote a raw result (worker_error may still be set).",
)
jobs_requeued_total = Counter(
    "mcp_scanner_worker_jobs_requeued_total", "Scan jobs that crashed and were requeued for retry."
)
jobs_dead_letter_total = Counter(
    "mcp_scanner_worker_jobs_dead_letter_total",
    "Scan jobs that exhausted max_attempts and were dead-lettered.",
)
job_duration_seconds = Histogram(
    "mcp_scanner_worker_job_duration_seconds",
    "Wall-clock time to process one scan job (claim to completed/requeued/dead-lettered).",
)


def start_metrics_server() -> None:
    try:
        start_http_server(METRICS_PORT)
        worker_up.set(1)
        logger.info("scanner-worker metrics server listening on :%d/metrics", METRICS_PORT)
    except Exception as exc:
        # Non-fatal: a metrics-server bind failure must not stop the worker
        # from doing its actual job (scanning).
        logger.warning("scanner-worker metrics server failed to start: %s", exc)
