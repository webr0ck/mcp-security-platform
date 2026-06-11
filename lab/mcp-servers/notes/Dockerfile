# TODO: pin @sha256:<digest> — run: podman pull python:3.12.11-slim && podman inspect --format='{{index .RepoDigests 0}}' python:3.12.11-slim
FROM python:3.12.11-slim

RUN groupadd --gid 1001 appgroup && \
    useradd --uid 1001 --gid appgroup --no-create-home appuser

WORKDIR /app

RUN pip install --no-cache-dir "mcp[cli]>=1.0.0" uvicorn "redis[hiredis]>=5.0.0"

COPY --chown=appuser:appgroup server.py .

USER appuser

ENV HOST=0.0.0.0
ENV PORT=8000

EXPOSE 8000

CMD ["python", "server.py"]
