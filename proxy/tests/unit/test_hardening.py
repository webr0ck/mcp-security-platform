"""
Unit tests for proxy/app/core/hardening.py — process hardening.
"""
from __future__ import annotations

import logging
import resource

from app.core.hardening import _disable_core_dumps, _enforce_log_level, apply_process_hardening


def test_apply_process_hardening_does_not_raise():
    """Calling apply_process_hardening in development mode must not raise any exception."""
    apply_process_hardening("development")


def test_disable_core_dumps_sets_rlimit():
    """After _disable_core_dumps(), RLIMIT_CORE soft limit should be 0."""
    _disable_core_dumps()
    soft, _ = resource.getrlimit(resource.RLIMIT_CORE)
    assert soft == 0


def test_enforce_log_level_in_production():
    """In production, root logger level must be raised to at least WARNING."""
    root_logger = logging.getLogger()
    original_level = root_logger.level
    try:
        root_logger.setLevel(logging.DEBUG)
        _enforce_log_level("production")
        assert root_logger.level >= logging.WARNING
    finally:
        root_logger.setLevel(original_level)
