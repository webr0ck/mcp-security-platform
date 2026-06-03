"""
MCP Security Platform — Authentication Router (stub — superseded by oidc_browser)

The OIDC browser login flow (GET /api/v1/auth/oidc/login, GET /api/v1/auth/oidc/callback,
POST /api/v1/auth/oidc/logout, GET /api/v1/auth/oidc/session) is fully implemented in
proxy/app/routers/oidc_browser.py (prefix="/api/v1/auth/oidc").

This file is kept as a placeholder so imports in main.py remain valid.
The router has no routes — it is registered but contributes nothing to the route table.
"""
from __future__ import annotations

from fastapi import APIRouter

router = APIRouter(prefix="/auth")
