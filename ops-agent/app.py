"""
MCP Security Platform — ops-agent

A minimal, isolated FastAPI service that holds the container-runtime socket
(podman) so the security proxy never has to. The proxy (or, in future, an
admin UI) calls this service over an authenticated internal-only API to
fetch logs, restart, or rebuild MCP server containers.

Design constraints (see docs/spec/11-server-lifecycle-and-hardening-batch.md
§WS-A):
  - No gateway ingress. This service is reachable only on an internal
    podman network, from the proxy. It publishes no host port.
  - Auth: shared-secret `X-Ops-Token` header, constant-time compare.
    Fail-closed: if OPS_AGENT_TOKEN is unset, every request is rejected.
  - Name allowlist: container/service names must match ^(mcp-|lab-mcp-)$
    prefix rules, so even a bypassed proxy cannot drive this agent into
    arbitrary host container control.
  - All podman/podman-compose invocations use a fixed argv list via
    subprocess — never shell=True, never string-interpolated shell
    commands built from user input.

Endpoints:
  GET  /health                      — unauthenticated liveness probe
  GET  /ops/logs?container=&tail=   — podman logs --tail <=1000
  POST /ops/restart {container}     — podman restart <container>
  POST /ops/rebuild {service}       — podman-compose up -d --build <service>
"""
from __future__ import annotations

import hmac
import logging
import os
import re
import subprocess
from typing import Optional

from fastapi import Depends, FastAPI, Header, HTTPException, Query
from pydantic import BaseModel, field_validator

logger = logging.getLogger("ops-agent")
logging.basicConfig(level=logging.INFO, format='{"time": "%(asctime)s", "level": "%(levelname)s", "message": "%(message)s"}')

# ============================================================================
# Config (env-only — no secrets file, no hardcoded defaults for the token)
# ============================================================================
OPS_AGENT_TOKEN = os.environ.get("OPS_AGENT_TOKEN", "")
PODMAN_BIN = os.environ.get("OPS_AGENT_PODMAN_BIN", "podman")
PODMAN_COMPOSE_BIN = os.environ.get("OPS_AGENT_PODMAN_COMPOSE_BIN", "podman-compose")
# Comma-separated list of `-f <file>` compose files, in order, matching the
# layering the lab/prod stack actually boots with (see Makefile.lab
# LAB_COMPOSE). Required for /ops/rebuild; /ops/logs and /ops/restart don't
# need it (they operate on a running container name directly).
COMPOSE_FILES = [f.strip() for f in os.environ.get("OPS_AGENT_COMPOSE_FILES", "").split(",") if f.strip()]
COMPOSE_PROJECT_DIR = os.environ.get("OPS_AGENT_COMPOSE_PROJECT_DIR", "/workspace")
SUBPROCESS_TIMEOUT_SECONDS = int(os.environ.get("OPS_AGENT_SUBPROCESS_TIMEOUT_SECONDS", "120"))

# ISO-F1 style allowlist: only act on containers/services that look like
# MCP servers or lab-prefixed platform components we intend to manage.
# Anything else (host paths, arbitrary strings, etc.) is rejected with 403,
# even if the proxy's own authz layer were somehow bypassed.
_NAME_ALLOWLIST_RE = re.compile(r"^(mcp-|lab-mcp-)[a-zA-Z0-9_-]+$")

# The mcp-/lab-mcp- prefix alone is NOT sufficient: several platform
# infrastructure containers (see docker-compose.yml container_name: values)
# also carry the "mcp-" prefix as a legacy naming convention even though
# they are not MCP backend servers — mcp-db, mcp-vault, and mcp-proxy itself
# are the ones that matter most. Restarting/rebuilding any of these via this
# agent would defeat the least-privilege thesis this service exists for, so
# they are explicitly denylisted on top of the prefix check.
_PLATFORM_INFRA_DENYLIST = frozenset({
    "mcp-gateway", "mcp-step-ca", "mcp-proxy", "mcp-opa", "mcp-ollama",
    "mcp-db", "mcp-vault", "mcp-redis", "mcp-loki", "mcp-promtail",
    "mcp-grafana", "mcp-alertmanager", "mcp-alertmanager-renderer",
    "mcp-minio", "mcp-minio-init", "mcp-compliance-checker",
    "mcp-scanner-worker", "mcp-prometheus", "mcp-labeler-renewal",
    "mcp-build-worker",
})
_MAX_TAIL = 1000

app = FastAPI(title="MCP Ops Agent", docs_url=None, redoc_url=None)


def _require_ops_token(x_ops_token: Optional[str] = Header(default=None)) -> None:
    """
    Fail-closed shared-secret auth. If OPS_AGENT_TOKEN is unset/empty, every
    request is rejected — an agent with no configured token must never
    silently allow all callers.
    """
    if not OPS_AGENT_TOKEN:
        logger.error("OPS_AGENT_TOKEN is unset — rejecting all requests (fail-closed)")
        raise HTTPException(status_code=503, detail="ops-agent misconfigured: no token set")
    if not x_ops_token or not hmac.compare_digest(x_ops_token, OPS_AGENT_TOKEN):
        raise HTTPException(status_code=401, detail="invalid or missing X-Ops-Token")


def _is_allowlisted_name(name: str) -> bool:
    return bool(_NAME_ALLOWLIST_RE.match(name)) and name not in _PLATFORM_INFRA_DENYLIST


def _require_allowlisted_name(name: str) -> str:
    """Used for query-param inputs (GET /ops/logs) — raises HTTPException directly."""
    if not _is_allowlisted_name(name):
        raise HTTPException(
            status_code=403,
            detail=f"container/service name {name!r} is not allowlisted "
                   "(must match ^(mcp-|lab-mcp-)[a-zA-Z0-9_-]+$ and not be a platform "
                   "infrastructure container)",
        )
    return name


def _run(argv: list[str], cwd: Optional[str] = None) -> subprocess.CompletedProcess:
    """
    Run a fixed argv list — never shell=True, never string-interpolated.
    Every element of argv originates either from a hardcoded literal or from
    a value that has already passed _require_allowlisted_name.
    """
    logger.info("exec: %s", " ".join(argv))
    try:
        return subprocess.run(
            argv,
            capture_output=True,
            text=True,
            timeout=SUBPROCESS_TIMEOUT_SECONDS,
            shell=False,
            cwd=cwd,
        )
    except subprocess.TimeoutExpired as exc:
        raise HTTPException(status_code=504, detail=f"command timed out after {SUBPROCESS_TIMEOUT_SECONDS}s") from exc
    except FileNotFoundError as exc:
        raise HTTPException(status_code=500, detail=f"podman binary not found: {exc}") from exc


@app.get("/health")
async def health() -> dict:
    """Unauthenticated liveness probe (used by the compose healthcheck)."""
    return {"status": "ok", "token_configured": bool(OPS_AGENT_TOKEN)}


@app.get("/ops/logs", dependencies=[Depends(_require_ops_token)])
async def get_logs(
    container: str = Query(..., description="Container name, must match the mcp-/lab-mcp- allowlist"),
    tail: int = Query(200, ge=1, le=_MAX_TAIL, description=f"Number of trailing log lines, capped at {_MAX_TAIL}"),
) -> dict:
    _require_allowlisted_name(container)
    result = _run([PODMAN_BIN, "logs", "--tail", str(tail), container])
    if result.returncode != 0:
        raise HTTPException(status_code=502, detail=f"podman logs failed: {result.stderr.strip()[:2000]}")
    return {"container": container, "tail": tail, "logs": result.stdout}


class RestartRequest(BaseModel):
    container: str

    @field_validator("container")
    @classmethod
    def validate_container(cls, v: str) -> str:
        if not _is_allowlisted_name(v):
            raise ValueError(
                f"container/service name {v!r} is not allowlisted "
                "(must match ^(mcp-|lab-mcp-)[a-zA-Z0-9_-]+$ and not be a platform "
                "infrastructure container)"
            )
        return v


@app.post("/ops/restart", dependencies=[Depends(_require_ops_token)])
async def restart_container(body: RestartRequest) -> dict:
    result = _run([PODMAN_BIN, "restart", body.container])
    if result.returncode != 0:
        raise HTTPException(status_code=502, detail=f"podman restart failed: {result.stderr.strip()[:2000]}")
    return {"container": body.container, "restarted": True, "output": result.stdout.strip()}


class RebuildRequest(BaseModel):
    service: str

    @field_validator("service")
    @classmethod
    def validate_service(cls, v: str) -> str:
        if not _is_allowlisted_name(v):
            raise ValueError(
                f"container/service name {v!r} is not allowlisted "
                "(must match ^(mcp-|lab-mcp-)[a-zA-Z0-9_-]+$ and not be a platform "
                "infrastructure container)"
            )
        return v


@app.post("/ops/rebuild", dependencies=[Depends(_require_ops_token)])
async def rebuild_service(body: RebuildRequest) -> dict:
    if not COMPOSE_FILES:
        raise HTTPException(
            status_code=503,
            detail="ops-agent misconfigured: OPS_AGENT_COMPOSE_FILES is unset — rebuild unavailable",
        )
    argv = [PODMAN_COMPOSE_BIN]
    for f in COMPOSE_FILES:
        argv += ["-f", f]
    argv += ["up", "-d", "--build", body.service]
    result = _run(argv, cwd=COMPOSE_PROJECT_DIR)
    if result.returncode != 0:
        raise HTTPException(status_code=502, detail=f"podman-compose rebuild failed: {result.stderr.strip()[:4000]}")
    return {"service": body.service, "rebuilt": True, "output": result.stdout.strip()}
