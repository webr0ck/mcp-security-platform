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
  POST /ops/rebuild-from-git {service, git_url, ref?}
                                     — git clone/pull git_url into a dedicated
                                       writable workdir, `podman build` it,
                                       then `podman-compose up -d <service>`
                                       to recreate the container from the
                                       freshly-built image (see docstring on
                                       rebuild_service_from_git below for the
                                       full contract and its limits).
"""
from __future__ import annotations

import hmac
import ipaddress
import logging
import os
import re
import shutil
import socket
import subprocess
from typing import Optional
from urllib.parse import urlparse

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

# ── git-pull rebuild config (rebuild-from-git) ──────────────────────────────
# A dedicated, independently-writable directory for per-service git
# checkouts. Deliberately NOT the same tree as COMPOSE_PROJECT_DIR's compose
# build contexts (those stay mounted read-only — ops-agent must never be able
# to write into the platform's own checked-out source tree). In compose, this
# path is backed by its own writable named volume mounted *under* the
# otherwise-read-only /workspace mount.
GIT_WORKDIR_ROOT = os.environ.get("OPS_AGENT_GIT_WORKDIR_ROOT", "/workspace/.ops-agent-git-workdirs")
GIT_BIN = os.environ.get("OPS_AGENT_GIT_BIN", "git")
GIT_CLONE_TIMEOUT_SECONDS = int(os.environ.get("OPS_AGENT_GIT_CLONE_TIMEOUT_SECONDS", "120"))
GIT_BUILD_TIMEOUT_SECONDS = int(os.environ.get("OPS_AGENT_GIT_BUILD_TIMEOUT_SECONDS", "300"))
# Convention assumption (documented limitation — see rebuild_service_from_git
# docstring): every lab mcp-* service image is tagged "<service>:<suffix>",
# matching every entry in podman-compose.lab.yml today. A service whose
# compose definition doesn't follow this convention cannot be rebuilt via
# this endpoint.
GIT_IMAGE_TAG_SUFFIX = os.environ.get("OPS_AGENT_GIT_IMAGE_TAG_SUFFIX", "lab")
# Only a plain ref name (branch/tag/short-ish sha) — never an argv-injectable
# string. No wildcards, no leading '-' (which git would parse as an option).
_REF_RE = re.compile(r"^[a-zA-Z0-9][a-zA-Z0-9._/-]{0,199}$")

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


def _run(argv: list[str], cwd: Optional[str] = None, timeout: Optional[int] = None) -> subprocess.CompletedProcess:
    """
    Run a fixed argv list — never shell=True, never string-interpolated.
    Every element of argv originates either from a hardcoded literal or from
    a value that has already passed _require_allowlisted_name (or, for the
    git-pull path, _require_safe_git_url / _REF_RE).
    """
    effective_timeout = timeout if timeout is not None else SUBPROCESS_TIMEOUT_SECONDS
    logger.info("exec: %s", " ".join(argv))
    try:
        return subprocess.run(
            argv,
            capture_output=True,
            text=True,
            timeout=effective_timeout,
            shell=False,
            cwd=cwd,
        )
    except subprocess.TimeoutExpired as exc:
        raise HTTPException(status_code=504, detail=f"command timed out after {effective_timeout}s") from exc
    except FileNotFoundError as exc:
        raise HTTPException(status_code=500, detail=f"required binary not found: {exc}") from exc


def _classify_ip(ip_str: str) -> str:
    """Coarse classification used to reject loopback/link-local/metadata/private
    targets for the git-pull path — this agent has no DB-backed git-provider
    allowlist (unlike scanner_worker/build_worker), so it does its own minimal,
    self-contained SSRF guard rather than importing that (DB-coupled) module."""
    try:
        ip = ipaddress.ip_address(ip_str)
    except ValueError:
        return "block"
    if ip.is_loopback or ip.is_link_local or ip.is_multicast or ip.is_unspecified or ip.is_reserved:
        return "block"
    # Cloud metadata endpoint — always blocked regardless of allow_private.
    if ip_str == "169.254.169.254":
        return "block"
    if ip.is_private:
        return "private"
    return "public"


def _require_safe_git_url(url: str) -> str:
    """
    Validate a caller-supplied git_url before it ever reaches a subprocess
    argv. Public repos only (scope: no credential injection):
      - scheme must be https (no git://, ssh://, file://, or bare paths —
        those either bypass TLS or can reach local/internal resources)
      - no embedded userinfo (https://user:pass@host) — this endpoint never
        injects or forwards credentials, so a URL trying to carry one is
        rejected rather than silently stripped
      - must not start with '-' (git argv-option-injection guard; belt and
        suspenders alongside the `--` separator used at the call site)
      - hostname must resolve, and none of its addresses may be
        loopback/link-local/private/metadata (SSRF guard — this agent runs
        with a mounted container-runtime socket, so it must never be able to
        reach internal-only hosts via a crafted git_url)

    TOCTOU / defence-in-depth (code-review finding, 2026-07-19): this check
    resolves DNS once here, but `git` re-resolves independently at connect time,
    so a DNS-rebinding answer could point the actual fetch at an internal IP this
    pre-check never saw. This is NOT the sole control: in this deployment the
    ops-agent has egress ONLY via lab-egress-proxy (squid) on
    ops-agent-egress-net, whose `dstdomain` allowlist (github.com / codeload /
    objects.githubusercontent.com) blocks the CONNECT regardless of the rebound
    IP. This function is the app-level belt; squid is the load-bearing braces.
    If ops-agent is ever deployed WITHOUT that squid egress enforcement, this
    check alone is insufficient — pin the resolved IP for the git subprocess
    (as revalidate_upstream_ip_at_invoke/PinnedIPTransport do on the proxy side).
    """
    if url.startswith("-"):
        raise HTTPException(status_code=422, detail="git_url must not start with '-'")
    parsed = urlparse(url)
    if parsed.scheme != "https":
        raise HTTPException(status_code=422, detail="git_url must use https://")
    if parsed.username or parsed.password or "@" in (parsed.netloc or ""):
        raise HTTPException(
            status_code=422,
            detail="git_url must not contain embedded credentials — public repos only",
        )
    host = parsed.hostname
    if not host:
        raise HTTPException(status_code=422, detail="git_url has no resolvable host")
    try:
        infos = socket.getaddrinfo(host, None)
    except OSError as exc:
        raise HTTPException(status_code=422, detail=f"DNS resolution failed for {host!r}: {exc}") from exc
    ips = {info[4][0] for info in infos}
    if not ips:
        raise HTTPException(status_code=422, detail=f"no addresses resolved for {host!r}")
    for ip in ips:
        if _classify_ip(ip) != "public":
            raise HTTPException(
                status_code=422,
                detail=f"git_url host {host!r} resolves to a non-public address {ip!r} — refusing",
            )
    return url


def _require_safe_ref(ref: str) -> str:
    if not _REF_RE.match(ref):
        raise HTTPException(
            status_code=422,
            detail=f"ref {ref!r} is not a safe git ref (expected "
                   r"^[a-zA-Z0-9][a-zA-Z0-9._/-]{0,199}$)",
        )
    return ref


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


class RebuildFromGitRequest(BaseModel):
    service: str
    git_url: str
    ref: Optional[str] = None

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

    @field_validator("git_url")
    @classmethod
    def validate_git_url(cls, v: str) -> str:
        # Full validation (incl. DNS/SSRF check) happens again at request
        # time in the handler — field_validator runs at parse time only and
        # a re-check right before the subprocess call is the one that
        # actually gates execution. This one is a cheap fail-fast for an
        # obviously-malformed URL.
        if not v.startswith("https://"):
            raise ValueError("git_url must use https://")
        return v

    @field_validator("ref")
    @classmethod
    def validate_ref(cls, v: Optional[str]) -> Optional[str]:
        if v is not None and not _REF_RE.match(v):
            raise ValueError(f"ref {v!r} is not a safe git ref")
        return v


@app.post("/ops/rebuild-from-git", dependencies=[Depends(_require_ops_token)])
async def rebuild_service_from_git(body: RebuildFromGitRequest) -> dict:
    """
    "True git pull per server": clone (or pull, if a prior checkout exists)
    body.git_url into a dedicated writable workdir, build it into the image
    tag the target compose service expects, then recreate the container via
    podman-compose so it picks up the freshly-built image with the service's
    full hardened definition (networks, healthcheck, resource limits) intact.

    Steps (each a hard-fail — no step is best-effort, no partial/silent
    success):
      1. Validate git_url (https, no embedded creds, resolves to a public
         address — SSRF guard) and ref (safe-ref pattern) if given.
      2. git clone (first run) or git fetch + reset --hard (subsequent runs,
         idempotent update) into GIT_WORKDIR_ROOT/<service>. Fixed argv only;
         url/dest/ref are passed as discrete argv elements after a `--`
         separator, never interpolated into a string.
      3. `podman build -t <service>:<GIT_IMAGE_TAG_SUFFIX> <workdir>` — the
         image tag is built entirely from the already-allowlisted service
         name plus a fixed env-configured suffix, never from request input.
      4. `podman-compose up -d <service>` (no --build — the image is already
         freshly built in step 3) to recreate the container from that image.

    KNOWN LIMITATION (see also the platform_admin-only proxy-side router):
    step 3's tag convention `<service>:<GIT_IMAGE_TAG_SUFFIX>` matches every
    mcp-/lab-mcp- service in podman-compose.lab.yml today (all use
    `image: <container_name>:lab`), but this is a convention, not something
    ops-agent derives from the compose file itself (this agent intentionally
    never parses/writes compose definitions). A service registered with a
    differently-tagged image will build successfully in step 3 but the step-4
    `up -d` will keep running the OLD image, since podman-compose only
    recreates a container when the image it's configured to use actually
    changed. That failure mode is silent from ops-agent's point of view (both
    subprocess calls exit 0) — it can only be caught by the caller diffing
    image digests/timestamps, which is out of scope here. This only works
    for platform-hosted containers this agent can already reach via the
    podman socket; a server hosted on the owner's own infrastructure is not,
    and never will be, reachable through this endpoint.
    """
    if not COMPOSE_FILES:
        raise HTTPException(
            status_code=503,
            detail="ops-agent misconfigured: OPS_AGENT_COMPOSE_FILES is unset — rebuild unavailable",
        )

    _require_safe_git_url(body.git_url)
    ref = body.ref
    if ref is not None:
        _require_safe_ref(ref)

    try:
        os.makedirs(GIT_WORKDIR_ROOT, exist_ok=True)
    except OSError as exc:
        raise HTTPException(status_code=500, detail=f"could not create git workdir root: {exc}") from exc

    workdir = os.path.join(GIT_WORKDIR_ROOT, body.service)
    git_common_args = [
        "-c", "protocol.allow=never",
        "-c", "protocol.https.allow=always",
        "-c", "protocol.ext.allow=never",
        "-c", "protocol.file.allow=never",
    ]

    if os.path.isdir(os.path.join(workdir, ".git")):
        # Idempotent pull: fetch exactly the requested ref (default branch's
        # remote HEAD if none given) then hard-reset to it. `git clean -fdx`
        # removes any stray build artifacts left by a previous build so the
        # next `podman build` sees a clean tree.
        fetch_target = ref or "HEAD"
        fetch = _run(
            [GIT_BIN, *git_common_args, "-C", workdir, "fetch", "--quiet", "--depth", "1",
             "origin", "--", fetch_target],
            timeout=GIT_CLONE_TIMEOUT_SECONDS,
        )
        if fetch.returncode != 0:
            raise HTTPException(status_code=502, detail=f"git fetch failed: {fetch.stderr.strip()[:2000]}")
        reset = _run([GIT_BIN, "-C", workdir, "reset", "--quiet", "--hard", "FETCH_HEAD"],
                     timeout=GIT_CLONE_TIMEOUT_SECONDS)
        if reset.returncode != 0:
            raise HTTPException(status_code=502, detail=f"git reset failed: {reset.stderr.strip()[:2000]}")
        _run([GIT_BIN, "-C", workdir, "clean", "-fdx", "--quiet"], timeout=GIT_CLONE_TIMEOUT_SECONDS)
    else:
        clone_argv = [GIT_BIN, *git_common_args, "clone", "--quiet", "--depth", "1"]
        if ref:
            clone_argv += ["--branch", ref]
        clone_argv += ["--", body.git_url, workdir]
        clone = _run(clone_argv, timeout=GIT_CLONE_TIMEOUT_SECONDS)
        if clone.returncode != 0:
            # Best-effort cleanup of a partial clone so a retry doesn't see a
            # half-populated ".git"-less directory and misclassify it.
            shutil.rmtree(workdir, ignore_errors=True)
            raise HTTPException(status_code=502, detail=f"git clone failed: {clone.stderr.strip()[:2000]}")

    rev_parse = _run([GIT_BIN, "-C", workdir, "rev-parse", "HEAD"], timeout=30)
    commit = rev_parse.stdout.strip() if rev_parse.returncode == 0 else None

    image_tag = f"{body.service}:{GIT_IMAGE_TAG_SUFFIX}"
    build = _run(
        [PODMAN_BIN, "build", "-t", image_tag, workdir],
        timeout=GIT_BUILD_TIMEOUT_SECONDS,
    )
    if build.returncode != 0:
        raise HTTPException(status_code=502, detail=f"podman build failed: {build.stderr.strip()[:4000]}")

    argv = [PODMAN_COMPOSE_BIN]
    for f in COMPOSE_FILES:
        argv += ["-f", f]
    argv += ["up", "-d", body.service]
    up = _run(argv, cwd=COMPOSE_PROJECT_DIR, timeout=GIT_BUILD_TIMEOUT_SECONDS)
    if up.returncode != 0:
        raise HTTPException(status_code=502, detail=f"podman-compose up failed: {up.stderr.strip()[:4000]}")

    return {
        "service": body.service,
        "rebuilt": True,
        "git_url": body.git_url,
        "ref": ref,
        "commit": commit,
        "image_tag": image_tag,
        "output": up.stdout.strip(),
    }
