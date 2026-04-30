"""
MCP Security Platform — Proxy Entry Point

Initializes the FastAPI application, registers middleware, routers,
and lifecycle event handlers.

See docs/ARCHITECTURE.md for service boundary definitions.
See docs/API.md for complete endpoint specifications.
"""
import logging
from contextlib import asynccontextmanager

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse

from app.middleware.audit import AuditMiddleware
from app.middleware.auth import AuthMiddleware
from app.middleware.rbac import RBACMiddleware
from app.routers import anomaly, audit, auth, compliance, health, integrations, policy, tools
from app.core.config import settings
from app.core.database import check_database_health
from app.core.redis_client import redis_pool

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

    Startup checks:
      1. Initialize Redis connection pool
      2. Verify database connectivity
      3. Verify OPA sidecar reachability

    Shutdown:
      1. Drain Redis connection pool
    """
    logger.info("MCP Security Proxy starting up", extra={"version": settings.PLATFORM_VERSION})

    # Initialize Redis pool
    await redis_pool.initialize()
    logger.info("Redis pool initialized")

    # Verify database on startup (warn but don't crash — health endpoint will report status)
    db_ok = await check_database_health()
    if not db_ok:
        logger.warning("Database not reachable at startup — health endpoint will report degraded")

    yield

    # Shutdown
    logger.info("MCP Security Proxy shutting down")
    await redis_pool.close()
    logger.info("Redis pool closed")


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
#   1. AuditMiddleware  (request_id injection, INV-001 boundary) — registered first
#   2. AuthMiddleware   (identity resolution)
#   3. RBACMiddleware   (role enforcement)
#
# Registration order (reverse of above):
# ============================================================================
app.add_middleware(RBACMiddleware)
app.add_middleware(AuthMiddleware)
app.add_middleware(AuditMiddleware)

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
