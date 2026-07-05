# MCP Security Platform — Proxy Dockerfile
# Multi-stage build: development target includes dev tools; production target is minimal.
#
# Build context should be the PROJECT ROOT (not proxy/) so local packages can be
# resolved.  docker-compose.dev.yml sets: context: ., dockerfile: proxy/Dockerfile
# For a standalone build from project root:
#   docker build -f proxy/Dockerfile --target production -t mcp-security-proxy:latest .

# ─── Base ─────────────────────────────────────────────────────────────────────
# TODO: pin @sha256:<digest> — run: docker pull python:3.12.11-slim && docker inspect --format='{{index .RepoDigests 0}}' python:3.12.11-slim
FROM python:3.12.11-slim AS base

# Security: run as non-root user
RUN groupadd --gid 1001 appgroup && \
    useradd --uid 1001 --gid appgroup --shell /bin/bash --create-home appuser

WORKDIR /app

# Install system dependencies:
#   curl/ca-certificates - healthcheck + TLS
#   git                  - submission scanner repo clone (R-0)
# ponytail: trufflehog installed via upstream script below; sidecar image that
# isolates untrusted-repo parsing from the enforcement point is the P1 follow-up
# (PRD-0003 R-0) — this is the interim in-proxy fix so scans fail closed with
# tooling present rather than silently skipping.
RUN apt-get update && apt-get install -y --no-install-recommends \
    curl \
    ca-certificates \
    git \
    && rm -rf /var/lib/apt/lists/* \
    && curl -sSfL https://raw.githubusercontent.com/trufflesecurity/trufflehog/main/scripts/install.sh \
       | sh -s -- -b /usr/local/bin v3.82.13 \
    && curl -sSfL https://raw.githubusercontent.com/anchore/syft/main/install.sh \
       | sh -s -- -b /usr/local/bin v1.18.1

# semgrep — SAST engine for the vendored mcp_checker MCP rule pack
# (proxy/vendor/mcp_checker/policies/semgrep.yml). Without it the SAST check
# SKIPs; the scanner treats a missing engine as "did not run", not a pass.
#
# Installed in an ISOLATED venv, not the app env, because:
#  - semgrep's opentelemetry dep imports pkg_resources, which setuptools 81+
#    removed and slim Python omits — the venv pins setuptools<81 where nothing
#    else can upgrade it (the app env resolves setuptools 83).
#  - it keeps semgrep's heavy transitive deps from colliding with proxy deps.
# The venv's own python is on the semgrep shebang; only the launcher is exposed.
RUN python3 -m venv /opt/semgrep-venv \
    && /opt/semgrep-venv/bin/pip install --no-cache-dir "setuptools<81" semgrep==1.86.0 \
    && ln -sf /opt/semgrep-venv/bin/semgrep /usr/local/bin/semgrep \
    && ln -sf /opt/semgrep-venv/bin/pysemgrep /usr/local/bin/pysemgrep

# ─── Builder ──────────────────────────────────────────────────────────────────
FROM base AS builder

# Install uv for fast dependency resolution
RUN pip install uv==0.4.0 --no-cache-dir

# Install local mcp-audit-logger (not on PyPI) before resolving proxy deps.
# Build context must be project root for this COPY to succeed.
COPY observability/mcp-audit-logger /tmp/mcp-audit-logger
RUN uv pip install --system --no-cache /tmp/mcp-audit-logger

# Copy pyproject.toml for dependency resolution; app source is not needed yet.
# pyproject.toml must live at WORKDIR (/app) so hatchling can find the app/ package.
COPY proxy/pyproject.toml .
# Install production dependencies only (resolves mcp-audit-logger from site-packages)
RUN uv pip install --system --no-cache -e "."

# ─── Development ──────────────────────────────────────────────────────────────
FROM builder AS development

# Install dev dependencies including debugpy
RUN uv pip install --system --no-cache -e ".[dev]" && \
    uv pip install --system --no-cache debugpy

# Copy proxy app source into WORKDIR so the editable install resolves correctly.
# At runtime, docker-compose.dev.yml bind-mounts ./proxy:/app:cached which
# shadows this layer — the COPY here is only a fallback for non-compose builds.
COPY --chown=appuser:appgroup proxy/app /app/app

USER appuser
EXPOSE 8000 5678
CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000", "--reload"]

# ─── Production ───────────────────────────────────────────────────────────────
FROM base AS production

# Copy installed packages from builder
COPY --from=builder /usr/local/lib/python3.12/site-packages /usr/local/lib/python3.12/site-packages
COPY --from=builder /usr/local/bin /usr/local/bin

# Copy application source
COPY --chown=appuser:appgroup proxy/app/ /app/app/
# Vendored mcp_checker engine — MCP-specific static security scan (see
# proxy/vendor/mcp_checker/VENDORED.md). Dev target gets this via the bind mount.
COPY --chown=appuser:appgroup proxy/vendor/ /app/vendor/

USER appuser
EXPOSE 8000

HEALTHCHECK --interval=15s --timeout=5s --start-period=30s --retries=3 \
    CMD curl -sf http://localhost:8000/health/ready || exit 1

CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000", "--workers", "4"]
