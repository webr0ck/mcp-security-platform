"""
Deploy launcher (CR-01 / WP-B3 phase 3) — the trusted, privileged component
that starts a per-server isolated runtime container from an
evaluator-approved, digest-pinned build artifact.

This is the ONLY code path in the platform that shells out to `podman run`
for a platform-managed deployment. It structurally enforces "only
evaluator-approved artifacts get launched" by NEVER accepting a
caller-supplied image ref — it always re-reads server_registry fresh and
refuses outright unless build_evaluator.py has already written
deployment_status='built' for this exact server.

# STUB: podman run against a real build_artifact_digest requires an actual
# pushed OCI image, which build_engine.py's stubbed buildah step doesn't
# produce for real in this sandbox — this function's podman-command
# construction and hardening-flag application are real and unit-tested via a
# mocked subprocess; wire it against a real registry once
# build_worker/Dockerfile bakes in buildah and a registry push target. A real
# invocation today will fail at the healthcheck-probe step (no such image
# exists to actually run) and correctly fail closed to deployment_status=
# 'failed' rather than silently pretending to succeed.
"""
from __future__ import annotations

import asyncio
import logging

import httpx
from sqlalchemy import text

from app.core.database import AsyncSessionLocal

logger = logging.getLogger(__name__)

# Hardening flags copied verbatim from podman-compose.lab.yml's
# x-mcp-hardening anchor (&mcp-hardening) — do not invent new values here,
# every other lab MCP server (mcp-echo, lab-mcp-notes, ...) is launched with
# exactly this profile.
_HARDENING_MEMORY = "256m"
_HARDENING_CPUS = "0.5"
_HARDENING_PIDS_LIMIT = "64"
_HARDENING_USER = "1001:1001"
_HARDENING_TMPFS = "/tmp:rw,noexec,nosuid,size=32m"

_HEALTHCHECK_TIMEOUT_SECONDS = 30.0
_HEALTHCHECK_POLL_INTERVAL_SECONDS = 1.0
_HEALTHCHECK_TOTAL_ATTEMPTS = 15


async def _fetch_server(session, server_id: str):
    return (await session.execute(text(
        """
        SELECT server_id, deployment_status, build_artifact_digest, build_provenance, service_context
        FROM server_registry
        WHERE server_id = :sid AND deleted_at IS NULL
        """
    ), {"sid": str(server_id)})).mappings().first()


def _network_name(server_id: str) -> str:
    return f"mcp-deploy-{str(server_id)[:8]}-net"


def _build_podman_run_cmd(
    server_id: str, image_ref: str, container_name: str, port: int,
    service_context: dict | None = None,
) -> list[str]:
    """Construct the podman run invocation with the lab's hardening profile.
    Pure function (no subprocess call) so the exact flags can be asserted on
    in tests without ever shelling out.

    WP-A6 Finding 3: service_context (server_registry.service_context — the
    non-secret runtime context a ServiceAdapter resolved post-enrollment,
    e.g. api_base_url/resource_id) is passed to the MCP server container as
    a single JSON env var, never as a credential — secrets stay exclusively
    in credential_store/Vault and are never baked into a container's env."""
    cmd = [
        "podman", "run", "-d",
        "--name", container_name,
        "--network", _network_name(server_id),
        "--read-only",
        "--tmpfs", _HARDENING_TMPFS,
        "--security-opt", "no-new-privileges:true",
        "--cap-drop", "ALL",
        "--memory", _HARDENING_MEMORY,
        "--cpus", _HARDENING_CPUS,
        "--pids-limit", _HARDENING_PIDS_LIMIT,
        "--user", _HARDENING_USER,
        "-p", f"127.0.0.1::{port}",
    ]
    if service_context:
        import json as _json
        cmd += ["-e", f"MCP_SERVICE_CONTEXT={_json.dumps(service_context)}"]
    cmd.append(image_ref)
    return cmd


async def _run_podman(cmd: list[str], timeout: int = 60) -> tuple[int, str, str]:
    proc = await asyncio.create_subprocess_exec(
        *cmd,
        stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE,
    )
    try:
        stdout, stderr = await asyncio.wait_for(proc.communicate(), timeout=timeout)
    except asyncio.TimeoutError:
        proc.kill()
        await proc.communicate()
        return 1, "", "podman command timed out"
    return proc.returncode, stdout.decode(errors="replace"), stderr.decode(errors="replace")


async def _ensure_network(name: str) -> tuple[bool, str]:
    """C-03 fix: --network <name> is passed to `podman run` but nothing ever
    created that network. Idempotent — a concurrent/retried deploy for the
    same server_id computes the same name, so "already exists" is success,
    not failure."""
    rc, stdout, stderr = await _run_podman(["podman", "network", "create", name])
    if rc == 0:
        return True, ""
    if "already exists" in stderr.lower():
        return True, ""
    return False, stderr.strip() or stdout.strip()


async def _resolve_published_port(container_name: str, container_port: int) -> int | None:
    """C-03 fix: `-p 127.0.0.1::{port}` asks podman for a random host port —
    the actual assignment must be read back rather than assumed to equal
    container_port. `podman port` prints e.g. "127.0.0.1:54321"."""
    rc, stdout, _stderr = await _run_podman(["podman", "port", container_name, str(container_port)])
    if rc != 0 or not stdout.strip():
        return None
    last_line = stdout.strip().splitlines()[-1]
    try:
        return int(last_line.rsplit(":", 1)[-1])
    except ValueError:
        return None


async def _probe_healthcheck(runtime_url: str) -> bool:
    """Same MCP `initialize` handshake shape release_tool's invocation probe
    uses — bounded retry loop since a freshly-started container may need a
    moment before it accepts connections."""
    payload = {
        "jsonrpc": "2.0", "id": 1, "method": "initialize",
        "params": {"protocolVersion": "2024-11-05", "capabilities": {},
                  "clientInfo": {"name": "mcp-security-platform-deploy-healthcheck", "version": "1.0.0"}},
    }
    headers = {"Accept": "application/json, text/event-stream"}
    for attempt in range(_HEALTHCHECK_TOTAL_ATTEMPTS):
        try:
            async with httpx.AsyncClient() as client:
                resp = await client.post(runtime_url, json=payload, headers=headers, timeout=5)
                resp.raise_for_status()
                return True
        except httpx.HTTPError as exc:
            logger.info("deploy healthcheck attempt %d/%d failed: %s",
                       attempt + 1, _HEALTHCHECK_TOTAL_ATTEMPTS, exc)
            await asyncio.sleep(_HEALTHCHECK_POLL_INTERVAL_SECONDS)
    return False


async def _mark_failed(session, server_id: str, error: str) -> None:
    await session.execute(text(
        """
        UPDATE server_registry
        SET deployment_status = 'failed', updated_at = now()
        WHERE server_id = :sid
        """
    ), {"sid": str(server_id)})
    await session.commit()
    logger.error("deploy_server failed server_id=%s: %s", server_id, error)


async def deploy_server(server_id: str) -> dict:
    """
    Launch a per-server isolated runtime container from the evaluator-
    approved build artifact. Refuses (fails closed, never constructs a
    podman command) unless server_registry.deployment_status == 'built' at
    the moment this function reads it — a fresh read every time, never a
    caller-supplied or cached value (TOCTOU-safe, same principle as
    revalidate_upstream_ip_at_invoke).

    Returns: {"runtime_url": str|None, "deployment_status": "deployed"|"failed", "error": str|None}
    """
    async with AsyncSessionLocal() as session:
        row = await _fetch_server(session, server_id)
        if row is None:
            return {"runtime_url": None, "deployment_status": "failed",
                    "error": f"server '{server_id}' not found"}

        if row["deployment_status"] != "built":
            error = (f"refusing to deploy: deployment_status={row['deployment_status']!r}, "
                     "not 'built' — only build_evaluator-approved artifacts may be launched")
            logger.warning("deploy_server refused server_id=%s: %s", server_id, error)
            return {"runtime_url": None, "deployment_status": "failed", "error": error}

        provenance = row["build_provenance"] or {}
        image_ref = provenance.get("image_ref") if isinstance(provenance, dict) else None
        if not image_ref:
            await _mark_failed(session, server_id, "no image_ref recorded in build_provenance")
            return {"runtime_url": None, "deployment_status": "failed",
                    "error": "no image_ref recorded in build_provenance"}

        await session.execute(text(
            "UPDATE server_registry SET deployment_status = 'deploying', updated_at = now() "
            "WHERE server_id = :sid"
        ), {"sid": str(server_id)})
        await session.commit()

    container_name = f"mcp-deploy-{str(server_id)[:8]}"
    container_port = 8000
    _raw_service_context = row.get("service_context")
    service_context = _raw_service_context if isinstance(_raw_service_context, dict) else None
    cmd = _build_podman_run_cmd(server_id, image_ref, container_name, container_port, service_context=service_context)

    try:
        net_ok, net_error = await _ensure_network(_network_name(server_id))
    except Exception as exc:
        net_ok, net_error = False, str(exc)
    if not net_ok:
        error = f"podman network create failed: {net_error}"
        async with AsyncSessionLocal() as session:
            await _mark_failed(session, server_id, error)
        return {"runtime_url": None, "deployment_status": "failed", "error": error}

    # Deliberately broad except: ANY failure to even invoke podman (binary
    # missing, no container-runtime access in this process's environment,
    # a crash inside _run_podman) must fail closed to deployment_status=
    # 'failed' — never leave the row stuck at 'deploying' with an unhandled
    # exception propagating out of this function. Found live: this
    # environment's mcp-proxy container has no podman binary/socket at all
    # (a separate, narrower-scoped privileged launcher process would carry
    # that access in a real deployment — see module docstring), and prior
    # to this fix that FileNotFoundError propagated uncaught, leaving
    # deployment_status stuck at 'deploying' forever instead of failing
    # closed.
    try:
        rc, stdout, stderr = await _run_podman(cmd)
    except Exception as exc:
        error = f"podman invocation failed: {exc}"
        async with AsyncSessionLocal() as session:
            await _mark_failed(session, server_id, error)
        return {"runtime_url": None, "deployment_status": "failed", "error": error}

    if rc != 0:
        error = f"podman run failed (rc={rc}): {stderr.strip() or stdout.strip()}"
        async with AsyncSessionLocal() as session:
            await _mark_failed(session, server_id, error)
        return {"runtime_url": None, "deployment_status": "failed", "error": error}

    # NOTE: with no real registry/image in this sandbox (see module STUB
    # comment), `podman run` above will itself fail before this point in
    # practice — this healthcheck path is exercised for real only once a
    # genuine image exists.
    published_port = await _resolve_published_port(container_name, container_port)
    if published_port is None:
        error = "could not resolve podman-assigned published host port"
        async with AsyncSessionLocal() as session:
            await _mark_failed(session, server_id, error)
        return {"runtime_url": None, "deployment_status": "failed", "error": error}

    runtime_url = f"http://127.0.0.1:{published_port}/"
    healthy = await _probe_healthcheck(runtime_url)
    async with AsyncSessionLocal() as session:
        if not healthy:
            await _mark_failed(session, server_id, "post-deploy healthcheck never succeeded")
            return {"runtime_url": None, "deployment_status": "failed",
                    "error": "post-deploy healthcheck never succeeded"}

        await session.execute(text(
            """
            UPDATE server_registry
            SET deployment_status = 'deployed', runtime_url = :runtime_url, updated_at = now()
            WHERE server_id = :sid
            """
        ), {"runtime_url": runtime_url, "sid": str(server_id)})
        await session.commit()

    logger.info("deploy_server succeeded server_id=%s runtime_url=%s", server_id, runtime_url)
    return {"runtime_url": runtime_url, "deployment_status": "deployed", "error": None}
