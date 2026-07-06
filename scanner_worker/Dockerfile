# scanner-worker (CR-14 / WP-B1) — isolated, unprivileged scanner execution.
#
# Build context must be the PROJECT ROOT (so vendor/mcp_checker + scan-config
# can be copied in). From repo root:
#   docker build -f scanner_worker/Dockerfile -t mcp-scanner-worker:latest .
#
# This image intentionally does NOT contain proxy application code, DB-admin
# credentials, the Vault token, or the gateway shared secret — see
# scanner_worker/README.md.

FROM python:3.12.11-slim AS base

RUN groupadd --gid 1002 workergroup && \
    useradd --uid 1002 --gid workergroup --shell /usr/sbin/nologin --create-home scanneruser

WORKDIR /app

# git            - repo clone (untrusted content; this IS the isolated place for it)
# trufflehog     - secret scanning
# syft           - CycloneDX SBOM generation
RUN apt-get update && apt-get install -y --no-install-recommends \
    curl \
    ca-certificates \
    git \
    && rm -rf /var/lib/apt/lists/* \
    && curl -sSfL https://raw.githubusercontent.com/trufflesecurity/trufflehog/main/scripts/install.sh \
       | sh -s -- -b /usr/local/bin v3.82.13 \
    && curl -sSfL https://raw.githubusercontent.com/anchore/syft/main/install.sh \
       | sh -s -- -b /usr/local/bin v1.18.1

# semgrep — SAST engine for the vendored mcp_checker MCP rule pack. Isolated
# venv for the same reasons documented in the (now-trimmed) proxy/Dockerfile.
RUN python3 -m venv /opt/semgrep-venv \
    && /opt/semgrep-venv/bin/pip install --no-cache-dir "setuptools<81" semgrep==1.86.0 \
    && ln -sf /opt/semgrep-venv/bin/semgrep /usr/local/bin/semgrep \
    && ln -sf /opt/semgrep-venv/bin/pysemgrep /usr/local/bin/pysemgrep

COPY scanner_worker/requirements.txt /app/requirements.txt
RUN pip install --no-cache-dir -r /app/requirements.txt

# Application code — this package only, never proxy/app.
COPY --chown=scanneruser:workergroup scanner_worker/ /app/scanner_worker/
# Vendored mcp_checker engine (same vendored copy the proxy used to run).
COPY --chown=scanneruser:workergroup proxy/vendor/ /app/scanner_worker/vendor/
# Scan config (secret/custom regex rules, block thresholds) — canonical copy
# lives at proxy/scan-config.yaml; baked in at build time so both services
# stay in lock-step without a runtime bind mount across trust boundaries.
COPY --chown=scanneruser:workergroup proxy/scan-config.yaml /app/scanner_worker/scan-config.yaml

# Scratch dirs: read-only checkout root + separate output dir (actual checkout
# happens under tempfile.mkdtemp() inside the container's writable /tmp;
# these are declared for clarity / volume-mount override in compose).
RUN mkdir -p /work/checkout /work/output && chown -R scanneruser:workergroup /work /app

USER scanneruser
ENV HOME=/home/scanneruser
ENV PYTHONUNBUFFERED=1

CMD ["python3", "-m", "scanner_worker.worker"]
