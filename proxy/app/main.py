"""
MCP Security Platform — Proxy Entry Point

Initializes the FastAPI application, registers middleware, routers,
and lifecycle event handlers.

See docs/ARCHITECTURE.md for service boundary definitions.
See docs/API.md for complete endpoint specifications.
"""
import logging
import os
from contextlib import asynccontextmanager

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from fastapi.staticfiles import StaticFiles
from starlette.middleware.trustedhost import TrustedHostMiddleware

from app.middleware.audit import AuditMiddleware, IPRateLimitMiddleware
from app.middleware.auth import AuthMiddleware
from app.middleware.rbac import RBACMiddleware
from app.routers import anomaly, audit, auth, compliance, health, integrations, mcp_server, oauth, oauth_metadata, policy, tools
from app.routers import oidc_browser, admin_credentials, portal, server_registry, catalog, lab_links, entitlements
from app.core.config import settings
from app.core.database import check_database_health
from app.core.hardening import apply_process_hardening
from app.core.redis_client import redis_pool
from app.core.asyncpg_pool import asyncpg_pool
from app.credential_broker.factory import build_broker

logger = logging.getLogger(__name__)

# Configure structured logging
logging.basicConfig(
    level=getattr(logging, settings.LOG_LEVEL, logging.INFO),
    format='{"time": "%(asctime)s", "level": "%(levelname)s", "logger": "%(name)s", "message": "%(message)s"}',
)


@asynccontextmanager
async def lifespan(app: FastAPI):
    """
    Application startup and shutdown lifecycle.

    Startup:
      1. Initialize Redis connection pool
      2. Initialize asyncpg connection pool
      3. Initialize credential broker (requires live Redis client)
      4. Initialize Registry and start 30s refresh loop
      5. Verify database connectivity

    Shutdown:
      1. Stop Registry refresh loop
      2. Zero credential broker master secret (CB-008)
      3. Close asyncpg pool
      4. Drain Redis connection pool
    """
    logger.info("MCP Security Proxy starting up", extra={"version": settings.PLATFORM_VERSION})

    # Step 0: Process hardening (mlock + no-core-dump + log-level enforcement)
    apply_process_hardening(settings.ENVIRONMENT)
    logger.info("Process hardening applied")

    if settings.OIDC_ENABLED and not settings.OIDC_AUDIENCE:
        logger.warning(
            "SECURITY WARNING: OIDC_ENABLED=true but OIDC_AUDIENCE is not set. "
            "Audience validation is DISABLED — any RS256 token from the configured issuer "
            "will authenticate regardless of intended audience. "
            "Set OIDC_AUDIENCE to the proxy's client_id to enforce audience binding."
        )

    # Step 1: Initialize Redis pool (broker needs a live client immediately after)
    await redis_pool.initialize()
    logger.info("Redis pool initialized")

    # Step 2: Initialize asyncpg pool (needed by Registry, credential_storage, etc.)
    try:
        await asyncpg_pool.initialize()
        logger.info("Asyncpg pool initialized")
    except Exception as exc:
        logger.warning(
            "Asyncpg pool initialization failed — Registry refresh loop disabled",
            extra={"error": str(exc)},
        )

    # Step 3: Initialize credential broker
    from app.services import invocation as inv_svc
    broker = build_broker(settings, redis_pool.client)
    inv_svc.broker_instance = broker
    if broker is None:
        logger.warning(
            "Credential broker disabled (VAULT_TOKEN empty) — "
            "tools with service_name + credential_approach set will fail-closed at call time"
        )
    else:
        logger.info("Credential broker initialized")

    # Step 4: Initialize Registry with asyncpg pool and start auto-refresh loop
    from app.credential_broker.registry import Registry
    registry = None
    try:
        pool = asyncpg_pool.get()
        registry = Registry(db_pool=pool, refresh_interval_secs=30)
        inv_svc.registry_instance = registry
        await registry.start_refresh_loop()
        logger.info("Registry initialized with 30s auto-refresh")
    except Exception as exc:
        logger.warning(
            "Registry initialization failed — server discovery will be unavailable",
            extra={"error": str(exc)},
        )

    # Step 5: Initialize OPA data sync service (push grants to OPA immediately)
    from app.services.opa_data_sync import OPADataSync
    from app.services import opa_data_sync as opa_data_sync_svc
    opa_data_sync = None
    try:
        pool = asyncpg_pool.get()
        opa_data_sync = OPADataSync(db_pool=pool)
        opa_data_sync_svc.opa_data_sync_instance = opa_data_sync
        # Initial push of grants to OPA (fail-logged, continues on error)
        try:
            await opa_data_sync.push_grants()
        except Exception as exc:
            logger.warning(
                "Initial OPA grants push failed — OPA will deny until first reconcile",
                extra={"error": str(exc)},
            )
        # Start background reconciliation loop (60s interval)
        await opa_data_sync.start_reconcile_loop()
        logger.info("OPA data sync service initialized")
    except Exception as exc:
        logger.warning(
            "OPA data sync initialization failed — grants will not be synced",
            extra={"error": str(exc)},
        )

    # Step 6: Verify database on startup (warn but don't crash)
    db_ok = await check_database_health()
    if not db_ok:
        logger.warning("Database not reachable at startup — health endpoint will report degraded")

    yield

    # Shutdown — stop OPA data sync reconcile loop first
    if opa_data_sync is not None:
        await opa_data_sync.stop_reconcile_loop()
        logger.info("OPA data sync reconcile loop stopped")

    # Shutdown — stop registry refresh loop
    if registry is not None:
        await registry.stop_refresh_loop()
        logger.info("Registry refresh loop stopped")

    # Shutdown — zero broker master secret before releasing Redis
    if broker is not None:
        broker._zero(broker._master_secret)
        broker._master_secret = None
        logger.info("Credential broker master secret zeroed")

    logger.info("MCP Security Proxy shutting down")
    await redis_pool.close()
    logger.info("Redis pool closed")

    await asyncpg_pool.close()
    logger.info("Asyncpg pool closed")


app = FastAPI(
    title="MCP Security Platform Proxy",
    version=settings.PLATFORM_VERSION,
    description=(
        "Security proxy for the Model Context Protocol ecosystem. "
        "Provides authentication, RBAC, OPA policy enforcement, SBOM generation, "
        "anomaly detection, and compliance-grade audit logging."
    ),
    docs_url="/docs" if settings.ENVIRONMENT == "development" else None,
    redoc_url="/redoc" if settings.ENVIRONMENT == "development" else None,
    lifespan=lifespan,
)

# ============================================================================
# Middleware stack
# Starlette middleware executes in reverse registration order.
# So the LAST added runs FIRST on requests.
#
# Execution order on request:
#   1. IPRateLimitMiddleware (global per-IP flood guard, pre-auth) — registered first
#   2. AuditMiddleware       (request_id injection, INV-001 boundary)
#   3. AuthMiddleware        (identity resolution)
#   4. RBACMiddleware        (role enforcement)
#
# Registration order (reverse of above):
# ============================================================================
app.add_middleware(RBACMiddleware)
app.add_middleware(AuthMiddleware)
app.add_middleware(AuditMiddleware)
# IPRateLimitMiddleware runs first (outermost) — registered last so it fires
# before auth on every request, catching unauthenticated floods.
_ip_rl_limit = int(os.environ.get("IP_RATE_LIMIT_PER_MIN", "100"))
app.add_middleware(IPRateLimitMiddleware, limit=_ip_rl_limit)

# PYSEC-2026-161 defence-in-depth: TrustedHostMiddleware prevents Host header
# injection attacks. Registered last so it runs first (Starlette reverse order).
# In production, set ALLOWED_HOSTS env var (comma-separated) to restrict to
# known hostnames. Defaults to wildcard "*" which blocks only blatantly malformed
# Host headers; narrowing to specific hostnames is strongly recommended.
if settings.ENVIRONMENT == "production":
    allowed_hosts_raw = getattr(settings, "ALLOWED_HOSTS", "*") or "*"
    allowed_hosts = [h.strip() for h in allowed_hosts_raw.split(",") if h.strip()]
    app.add_middleware(TrustedHostMiddleware, allowed_hosts=allowed_hosts)

if settings.ENVIRONMENT == "development":
    app.add_middleware(
        CORSMiddleware,
        allow_origins=["http://localhost:3000"],
        allow_credentials=True,
        allow_methods=["*"],
        allow_headers=["*"],
    )

# ============================================================================
# Router registration — all API endpoints under /api/v1
# Health endpoints are at root level (no prefix).
# ============================================================================
app.include_router(health.router, tags=["Health"])
app.include_router(tools.router, prefix="/api/v1", tags=["Tools"])
app.include_router(policy.router, prefix="/api/v1", tags=["Policy"])
app.include_router(compliance.router, prefix="/api/v1", tags=["Compliance"])
app.include_router(anomaly.router, prefix="/api/v1", tags=["Anomaly"])
app.include_router(audit.router, prefix="/api/v1", tags=["Audit"])
app.include_router(auth.router, prefix="/api/v1", tags=["Authentication"])
app.include_router(integrations.router, prefix="/api/v1", tags=["Integrations"])
app.include_router(mcp_server.router)
app.include_router(oauth.router)
app.include_router(oauth_metadata.router)
app.include_router(oidc_browser.router)        # Keycloak browser login flow
app.include_router(admin_credentials.router)   # Credential management UI
app.include_router(portal.router)              # Multi-role portal UI
app.include_router(server_registry.router)     # Server registry CRUD + approval
app.include_router(catalog.router)            # Principal-scoped server catalog (discovery==invoke)
app.include_router(entitlements.router)       # Entitlement CRUD (Phase 2.2)
app.include_router(lab_links.router)          # Lab convenience: / → portal, /netbox /grafana /keycloak

# Static assets — served at /static/* (no auth required; public JS/CSS only)
_static_dir = os.path.join(os.path.dirname(__file__), "static")
if os.path.isdir(_static_dir):
    app.mount("/static", StaticFiles(directory=_static_dir), name="static")


# ============================================================================
# Global exception handler for unhandled errors
# Ensures machine-readable JSON error envelope on all 5xx responses.
# ============================================================================
@app.exception_handler(Exception)
async def global_exception_handler(request: object, exc: Exception) -> JSONResponse:
    logger.error("Unhandled exception", extra={"error": str(exc), "type": type(exc).__name__})
    return JSONResponse(
        status_code=500,
        content={
            "error": {
                "code": "INTERNAL_ERROR",
                "message": "An unexpected error occurred.",
                "request_id": getattr(getattr(request, "state", None), "request_id", "unknown"),
            }
        },
    )
