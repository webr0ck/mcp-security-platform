"""
Unit test conftest — sets dummy env vars before any module-level imports
so that pydantic Settings validation doesn't fail in tests that don't
need real credentials.
"""
from __future__ import annotations
import os

_DEFAULTS = {
    "DB_PASSWORD": "test",
    "REDIS_PASSWORD": "test",
    "PROXY_SECRET_KEY": "test",
    "API_KEY_HMAC_KEY": "test",
    "SBOM_SIGNING_KEY": "test",
    "AUDIT_LOG_HMAC_KEY": "test",
    "WEBHOOK_SIGNING_KEY": "test",
    "MINIO_ROOT_USER": "test",
    "MINIO_ROOT_PASSWORD": "test",
}

for _k, _v in _DEFAULTS.items():
    os.environ.setdefault(_k, _v)
