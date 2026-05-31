"""
Compliance checker entrypoint.

Runs checker.py immediately on startup, then sleeps for
COMPLIANCE_CHECK_INTERVAL_SECONDS (default 86400 = 24 h) and repeats.
No system cron required — works as any non-root user.
"""
import importlib
import logging
import os
import time

logging.basicConfig(
    level=os.getenv("LOG_LEVEL", "INFO"),
    format="%(asctime)s %(levelname)s entrypoint %(message)s",
)
log = logging.getLogger("entrypoint")

INTERVAL = int(os.getenv("COMPLIANCE_CHECK_INTERVAL_SECONDS", str(24 * 3600)))

checker = importlib.import_module("checker")

while True:
    log.info("Starting compliance check run (interval=%ds)", INTERVAL)
    try:
        rc = checker.run()
        log.info("Compliance check finished (rc=%d)", rc)
    except Exception as exc:
        log.error("Unhandled exception in compliance check: %s", exc)
    log.info("Next run in %d seconds", INTERVAL)
    time.sleep(INTERVAL)
