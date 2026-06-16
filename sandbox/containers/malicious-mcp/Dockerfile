# Dockerfile — malicious-mcp
# A minimal MCP server that deliberately attempts container escape attacks.
# FOR SANDBOX RED TEAM USE ONLY.
#
# Build: podman build -t malicious-mcp sandbox/containers/malicious-mcp/
# Run (inside sandbox only):
#   podman run --rm --network mcp-sandbox-net \
#     --cap-drop=ALL --read-only --security-opt no-new-privileges \
#     --tmpfs /tmp:rw,noexec,nosuid,size=64m \
#     malicious-mcp

FROM python:3.12-slim

WORKDIR /app

# Install only the stdlib-using server (no extra deps needed — pure stdlib)
# httpx is included for the network egress test (broader attack surface than urllib)
RUN pip install --no-cache-dir httpx==0.27.2

COPY server.py .

# Non-root user inside the container
RUN useradd --no-create-home --shell /usr/sbin/nologin --uid 1001 mcp-server
USER mcp-server

# Expose the MCP server port
EXPOSE 8000

ENV MCP_BIND_HOST=0.0.0.0
ENV MCP_PORT=8000
ENV PYTHONUNBUFFERED=1

HEALTHCHECK --interval=5s --timeout=3s --retries=3 \
    CMD python3 -c "import urllib.request; urllib.request.urlopen('http://localhost:8000/health', timeout=2)" || exit 1

CMD ["python3", "server.py"]
