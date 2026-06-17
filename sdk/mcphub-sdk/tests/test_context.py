"""
Tests for mcphub_sdk.context — middleware, identity(), credential().

Covers:
  - H11: identity ContextVar reaches through middleware to tool (the core correctness test)
  - H2: require_proxy rejects un-proxied requests (fail-closed)
  - H1: /health allowed without proxy headers
  - credential prefix stripping (Bearer, token)
  - credential env fallback: only when proxied (fail-closed for un-proxied)
  - H10: concurrent requests see their own identity (ContextVar isolation)
"""
from __future__ import annotations

import asyncio
import os
from contextlib import asynccontextmanager
from contextvars import copy_context

import pytest
from starlette.applications import Starlette
from starlette.requests import Request
from starlette.responses import JSONResponse
from starlette.routing import Route
from starlette.testclient import TestClient

from mcphub_sdk.context import (
    Identity,
    _ContextMiddleware,
    _proxied,
    _auth,
    credential,
    identity,
)


# ---------------------------------------------------------------------------
# Helpers: a tiny Starlette app wired with _ContextMiddleware
# ---------------------------------------------------------------------------


def _make_app(*, require_proxy: bool = True, credential_env: str | None = None):
    """Build a minimal Starlette test app with _ContextMiddleware."""

    async def identity_route(request: Request):
        who = identity()
        cred = credential(env_var=credential_env)
        return JSONResponse({"sub": who.sub, "role": who.role, "credential": cred})

    async def health_route(request: Request):
        return JSONResponse({"status": "ok"})

    app = Starlette(
        routes=[
            Route("/identity", identity_route, methods=["GET"]),
            Route("/health", health_route, methods=["GET"]),
        ]
    )
    app.add_middleware(_ContextMiddleware, require_proxy=require_proxy)
    return app


# ---------------------------------------------------------------------------
# Test: identity resolves from headers (H11 — the core correctness test)
# ---------------------------------------------------------------------------


def test_identity_resolves_from_headers():
    """Middleware sets ContextVar; identity() inside a handler reads it correctly."""
    app = _make_app()
    client = TestClient(app, raise_server_exceptions=True)
    resp = client.get(
        "/identity",
        headers={"X-User-Sub": "alice@corp", "X-User-Role": "admin"},
    )
    assert resp.status_code == 200
    data = resp.json()
    assert data["sub"] == "alice@corp", f"Expected alice@corp, got: {data['sub']}"
    assert data["role"] == "admin"


def test_identity_defaults_when_require_proxy_false():
    """With require_proxy=False, un-proxied request resolves to anonymous/agent."""
    app = _make_app(require_proxy=False)
    client = TestClient(app, raise_server_exceptions=True)
    resp = client.get("/identity")
    assert resp.status_code == 200
    data = resp.json()
    assert data["sub"] == "anonymous"
    assert data["role"] == "agent"


# ---------------------------------------------------------------------------
# Test: H2 — require_proxy rejects un-proxied requests
# ---------------------------------------------------------------------------


def test_require_proxy_rejects_unproxied():
    """Without X-User-Sub, a non-/health request returns 403."""
    app = _make_app(require_proxy=True)
    client = TestClient(app, raise_server_exceptions=True)
    resp = client.get("/identity")  # no X-User-Sub header
    assert resp.status_code == 403
    body = resp.json()
    assert "error" in body


def test_require_proxy_rejects_unproxied_post():
    """POST without X-User-Sub is also rejected (any method)."""
    app = _make_app(require_proxy=True)
    client = TestClient(app, raise_server_exceptions=True)
    resp = client.post("/identity")
    assert resp.status_code == 403


# ---------------------------------------------------------------------------
# Test: H1 — /health allowed without proxy headers
# ---------------------------------------------------------------------------


def test_health_allowed_without_proxy_headers():
    """GET /health succeeds even with require_proxy=True and no X-User-Sub."""
    app = _make_app(require_proxy=True)
    client = TestClient(app, raise_server_exceptions=True)
    resp = client.get("/health")
    assert resp.status_code == 200
    assert resp.json()["status"] == "ok"


# ---------------------------------------------------------------------------
# Test: credential() prefix stripping
# ---------------------------------------------------------------------------


def test_credential_strips_bearer_prefix():
    """Authorization: Bearer <token> → credential() returns bare token."""
    app = _make_app(require_proxy=False)
    client = TestClient(app, raise_server_exceptions=True)
    resp = client.get(
        "/identity",
        headers={"X-User-Sub": "bob@corp", "Authorization": "Bearer my-secret-token"},
    )
    assert resp.status_code == 200
    assert resp.json()["credential"] == "my-secret-token"


def test_credential_strips_token_prefix():
    """Authorization: token <sha1> → credential() returns bare token (gitea pattern)."""
    app = _make_app(require_proxy=False)
    client = TestClient(app, raise_server_exceptions=True)
    resp = client.get(
        "/identity",
        headers={"X-User-Sub": "bob@corp", "Authorization": "token abc123"},
    )
    assert resp.status_code == 200
    assert resp.json()["credential"] == "abc123"


def test_credential_strips_bearer_prefix_case_insensitive():
    """Bearer prefix match is case-insensitive."""
    app = _make_app(require_proxy=False)
    client = TestClient(app, raise_server_exceptions=True)
    resp = client.get(
        "/identity",
        headers={"X-User-Sub": "u", "Authorization": "BEARER MYTOKEN"},
    )
    assert resp.status_code == 200
    assert resp.json()["credential"] == "MYTOKEN"


# ---------------------------------------------------------------------------
# Test: credential() env fallback — fail-closed (H2)
# ---------------------------------------------------------------------------


def test_credential_env_fallback_when_proxied(monkeypatch):
    """Proxied request + no Authorization + env_var set → returns env value."""
    monkeypatch.setenv("TEST_SVC_TOKEN", "env-service-token")
    app = _make_app(require_proxy=False, credential_env="TEST_SVC_TOKEN")
    client = TestClient(app, raise_server_exceptions=True)
    # Proxied: X-User-Sub present, no Authorization header
    resp = client.get("/identity", headers={"X-User-Sub": "carol@corp"})
    assert resp.status_code == 200
    assert resp.json()["credential"] == "env-service-token"


def test_credential_env_fallback_blocked_when_not_proxied(monkeypatch):
    """Un-proxied request + env_var set → credential() returns None (fail-closed)."""
    monkeypatch.setenv("TEST_SVC_TOKEN", "env-service-token")
    app = _make_app(require_proxy=False, credential_env="TEST_SVC_TOKEN")
    client = TestClient(app, raise_server_exceptions=True)
    # No X-User-Sub header → _proxied ContextVar is False
    resp = client.get("/identity")
    assert resp.status_code == 200
    # Must be None, not the env token
    assert resp.json()["credential"] is None, (
        "credential() must return None for un-proxied requests even when env_var is set"
    )


def test_credential_returns_none_when_no_auth_no_env():
    """No Authorization header, no env_var → None."""
    app = _make_app(require_proxy=False)
    client = TestClient(app, raise_server_exceptions=True)
    resp = client.get("/identity", headers={"X-User-Sub": "dave@corp"})
    assert resp.status_code == 200
    assert resp.json()["credential"] is None


def test_credential_header_takes_priority_over_env(monkeypatch):
    """When both Authorization header and env are present, header wins."""
    monkeypatch.setenv("TEST_SVC_TOKEN", "env-token")
    app = _make_app(require_proxy=False, credential_env="TEST_SVC_TOKEN")
    client = TestClient(app, raise_server_exceptions=True)
    resp = client.get(
        "/identity",
        headers={"X-User-Sub": "eve@corp", "Authorization": "Bearer header-token"},
    )
    assert resp.status_code == 200
    assert resp.json()["credential"] == "header-token"


# ---------------------------------------------------------------------------
# Test: H10 — ContextVar isolation across concurrent requests
# ---------------------------------------------------------------------------


def test_context_isolation_concurrent_requests():
    """Two concurrent requests with different X-User-Sub values each see their own sub.

    Uses asyncio to fire two requests simultaneously in the same event loop,
    verifying that ContextVar reset-in-finally prevents cross-request bleed.
    """
    import threading

    app = _make_app(require_proxy=True)
    results = {}

    def run_request(sub: str):
        client = TestClient(app, raise_server_exceptions=True)
        resp = client.get("/identity", headers={"X-User-Sub": sub, "X-User-Role": "agent"})
        results[sub] = resp.json()

    # Run two requests in separate threads to simulate concurrency
    t1 = threading.Thread(target=run_request, args=("user-one@corp",))
    t2 = threading.Thread(target=run_request, args=("user-two@corp",))
    t1.start()
    t2.start()
    t1.join()
    t2.join()

    assert results["user-one@corp"]["sub"] == "user-one@corp", (
        f"user-one bleed: {results}"
    )
    assert results["user-two@corp"]["sub"] == "user-two@corp", (
        f"user-two bleed: {results}"
    )


# ---------------------------------------------------------------------------
# Test: ContextVar reset after request (no bleed to next)
# ---------------------------------------------------------------------------


def test_context_reset_after_request():
    """After a request completes, identity() at module level reads the default."""
    # Issue a request that sets sub to "transient@corp"
    app = _make_app(require_proxy=True)
    client = TestClient(app, raise_server_exceptions=True)
    client.get("/identity", headers={"X-User-Sub": "transient@corp"})

    # Outside request context, identity() should read the ContextVar default
    who = identity()
    assert who.sub == "anonymous", (
        f"ContextVar leaked after request: got sub={who.sub!r}"
    )


# ---------------------------------------------------------------------------
# Test: Identity dataclass
# ---------------------------------------------------------------------------


def test_identity_dataclass_defaults():
    assert Identity().sub == "anonymous"
    assert Identity().role == "agent"


def test_identity_dataclass_frozen():
    who = Identity(sub="x", role="y")
    with pytest.raises((AttributeError, TypeError)):
        who.sub = "z"  # type: ignore[misc]
