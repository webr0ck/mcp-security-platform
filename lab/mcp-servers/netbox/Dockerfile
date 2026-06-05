# TODO: pin @sha256:<digest> — run: docker pull python:3.12.11-slim && docker inspect --format='{{index .RepoDigests 0}}' python:3.12.11-slim
FROM python:3.12.11-slim

WORKDIR /app

RUN pip install --no-cache-dir \
    "netbox-mcp-server @ git+https://github.com/netboxlabs/netbox-mcp-server.git" \
    2>/dev/null || \
    pip install --no-cache-dir mcp httpx 2>/dev/null

# Fallback: clone and install if pip git install fails
RUN pip show netbox-mcp-server 2>/dev/null || ( \
    apt-get update -qq && apt-get install -y --no-install-recommends git && \
    git clone --depth 1 https://github.com/netboxlabs/netbox-mcp-server.git /tmp/netbox-mcp && \
    pip install --no-cache-dir /tmp/netbox-mcp && \
    rm -rf /tmp/netbox-mcp /var/lib/apt/lists/* \
)

ENV TRANSPORT=http
ENV HOST=0.0.0.0
ENV PORT=8000

EXPOSE 8000

CMD ["python", "-m", "netbox_mcp_server"]
