"""
Process hardening — shrinks the ZK-in-use window without claiming to close it.

Applied at startup. Failures are logged as warnings (not fatal) since lab environments
may run without CAP_IPC_LOCK.

Hardening steps:
1. mlock the process (prevent memory pages from being swapped to disk)
2. Disable core dumps (prevent secret leakage via crash dumps)
3. Log-level enforcement: WARNING minimum for production (no DEBUG/INFO in prod)
"""
from __future__ import annotations

import logging
import resource

logger = logging.getLogger(__name__)


def apply_process_hardening(environment: str) -> None:
    """
    Apply process hardening. Call once at startup in lifespan().
    """
    _disable_core_dumps()
    _attempt_mlock()
    _enforce_log_level(environment)


def _disable_core_dumps() -> None:
    try:
        resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
        logger.info("Core dumps disabled")
    except (ValueError, resource.error) as exc:
        logger.warning("Could not disable core dumps: %s", exc)


def _attempt_mlock() -> None:
    try:
        import ctypes
        import ctypes.util
        libc_name = ctypes.util.find_library("c")
        if libc_name:
            libc = ctypes.CDLL(libc_name, use_errno=True)
            MCL_CURRENT = 1
            MCL_FUTURE = 2
            ret = libc.mlockall(MCL_CURRENT | MCL_FUTURE)
            if ret == 0:
                logger.info("mlockall(MCL_CURRENT|MCL_FUTURE) succeeded — memory paging disabled")
            else:
                import ctypes as _ctypes
                errno = _ctypes.get_errno()
                logger.warning("mlockall failed (errno=%d) — memory may be paged to disk", errno)
        else:
            logger.warning("libc not found — mlock skipped")
    except Exception as exc:
        logger.warning("mlock attempt failed: %s", exc)


def _enforce_log_level(environment: str) -> None:
    if environment != "development":
        root_logger = logging.getLogger()
        if root_logger.level < logging.WARNING:
            root_logger.setLevel(logging.WARNING)
            logger.warning(
                "Log level enforced to WARNING for non-development environment "
                "(was %s) — debug/info logs suppressed to reduce ZK-in-use surface",
                logging.getLevelName(root_logger.level),
            )
