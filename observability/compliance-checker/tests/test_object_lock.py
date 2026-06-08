"""
6.5 — INV-007 startup Object-Lock verification.

verify_object_lock_startup() must exist in checker.py and must correctly
interpret the MinIO/S3 GetBucketObjectLockConfiguration response before
each compliance run.

Design decision: GOVERNANCE mode (chosen for this reference implementation).
Not MFA-enforced WORM — a privileged key can bypass it. Documented in
SECURITY_NONNEGATABLES.md §INV-007.
"""
from __future__ import annotations

import os
import sys
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

# Stub required env vars before importing checker (it reads them at module level).
_ENV_STUBS = {
    "DB_HOST": "localhost", "DB_PORT": "5432", "DB_NAME": "test",
    "COMPLIANCE_DB_USER": "test", "COMPLIANCE_DB_PASSWORD": "test",
    "MINIO_ROOT_USER": "test", "MINIO_ROOT_PASSWORD": "test",
}
for _k, _v in _ENV_STUBS.items():
    os.environ.setdefault(_k, _v)

# Add checker directory to path so we can import checker.py directly.
_CHECKER_DIR = Path(__file__).resolve().parents[1]
if str(_CHECKER_DIR) not in sys.path:
    sys.path.insert(0, str(_CHECKER_DIR))

import checker  # noqa: E402


def _s3_response(enabled: bool, mode: str = "GOVERNANCE", days: int = 90):
    """Build a mock s3 GetBucketObjectLockConfiguration response."""
    if not enabled:
        return {"ObjectLockConfiguration": {"ObjectLockEnabled": "Disabled"}}
    return {
        "ObjectLockConfiguration": {
            "ObjectLockEnabled": "Enabled",
            "Rule": {
                "DefaultRetention": {
                    "Mode": mode,
                    "Days": days,
                }
            },
        }
    }


def test_verify_object_lock_function_exists():
    """verify_object_lock_startup must be a callable in checker.py (6.5 gate)."""
    assert callable(getattr(checker, "verify_object_lock_startup", None)), (
        "checker.py must export verify_object_lock_startup() — "
        "the INV-007 startup verification function."
    )


def test_verify_object_lock_enabled_governance_passes():
    """GOVERNANCE-mode enabled bucket returns enabled=True."""
    mock_s3 = MagicMock()
    mock_s3.get_bucket_object_lock_configuration.return_value = _s3_response(True)
    result = checker.verify_object_lock_startup(mock_s3, "test-bucket")
    assert result["enabled"] is True
    assert result["mode"] == "GOVERNANCE"


def test_verify_object_lock_disabled_returns_false():
    """Disabled Object Lock returns enabled=False without raising."""
    mock_s3 = MagicMock()
    mock_s3.get_bucket_object_lock_configuration.return_value = _s3_response(False)
    result = checker.verify_object_lock_startup(mock_s3, "test-bucket")
    assert result["enabled"] is False


def test_verify_object_lock_boto3_error_returns_false():
    """If boto3 raises (e.g. bucket not found, wrong credentials), return
    enabled=False — never crash the compliance run on a startup check failure."""
    mock_s3 = MagicMock()
    mock_s3.get_bucket_object_lock_configuration.side_effect = Exception("NoSuchBucket")
    result = checker.verify_object_lock_startup(mock_s3, "test-bucket")
    assert result["enabled"] is False
    assert "error" in result


def test_verify_object_lock_compliance_mode_also_passes():
    """COMPLIANCE mode (stricter WORM) also passes the check."""
    mock_s3 = MagicMock()
    mock_s3.get_bucket_object_lock_configuration.return_value = _s3_response(
        True, mode="COMPLIANCE"
    )
    result = checker.verify_object_lock_startup(mock_s3, "test-bucket")
    assert result["enabled"] is True
    assert result["mode"] == "COMPLIANCE"
