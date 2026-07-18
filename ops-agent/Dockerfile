# MCP Security Platform — ops-agent
#
# Thin, isolated FastAPI service that holds the podman socket so the
# security proxy never has to (least-privilege). No gateway ingress; no
# host port published. See docs/spec/11-server-lifecycle-and-hardening-batch.md
# §WS-A.
FROM python:3.11-slim

WORKDIR /app

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
