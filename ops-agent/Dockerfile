# MCP Security Platform — ops-agent
#
# Thin, isolated FastAPI service that holds the podman socket so the
# security proxy never has to (least-privilege). No gateway ingress; no
# host port published. See docs/spec/11-server-lifecycle-and-hardening-batch.md
# §WS-A.
FROM python:3.11-slim

WORKDIR /app

# The agent shells out to `podman`/`podman-compose` against the *mounted* podman
# socket (CONTAINER_HOST below) — it does NOT run its own container engine. We
# only need the podman CLI in remote mode + podman-compose, not a full local
# engine (no crun/conmon storage stack). `podman` from Debian provides the
# remote-capable client; podman-compose is a pure-Python pip package.
# git is required for the /ops/rebuild-from-git path (CR: "true git pull per
# server") — clones/pulls a server's public github_repo_url into a dedicated
# writable workdir before building. podman-compose remains the only thing
# that touches the (read-only) compose build contexts under /workspace.
RUN apt-get update \
    && apt-get install -y --no-install-recommends podman git \
    && rm -rf /var/lib/apt/lists/*

# Talk to the bind-mounted podman socket instead of a local engine. `podman`
# and `podman-compose` both honour CONTAINER_HOST → remote mode.
ENV CONTAINER_HOST=unix:///var/run/docker.sock

RUN groupadd -g 1001 appgroup && useradd -u 1001 -g appgroup -m appuser

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY app.py .

# Runs as root ONLY insofar as it needs group access to the bind-mounted
# podman socket; the socket's host-side group ownership determines the
# actual privilege here — see the lab compose comment on PODMAN_SOCK.
# Non-root is used by default; override with `user:` in compose if the
# mounted socket requires a specific gid.
USER appuser

EXPOSE 9000

CMD ["uvicorn", "app:app", "--host", "0.0.0.0", "--port", "9000"]
